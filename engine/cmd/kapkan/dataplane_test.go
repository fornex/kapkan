package main

// Tests for the report and the exit codes. They run on every host, including the
// macOS development box, because renderStatus takes a dataplane.Inspection value
// and never a kernel — which is the reason InspectPins returns a value instead
// of printing.
//
// What they are actually protecting: the two ways this report can be WRONG
// rather than merely ugly. Summing the observation counters into the packet
// total is a wrong number; hiding a generic-mode attachment is a wrong
// conclusion about the box's capacity. Both have a test below.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/dataplane"
)

// enforcing builds a healthy, native-mode inspection to mutate per test.
func enforcing() statusDoc {
	return statusDoc{Inspection: dataplane.Inspection{
		PinPath:             "/sys/fs/bpf/kapkan",
		PinPathSource:       "dataplane.pin_path in /etc/kapkan/config.yaml",
		State:               dataplane.StateEnforcing,
		Reason:              "the program is attached and filtering.",
		Kernel:              "6.12.76-linuxkit",
		BinarySchemaVersion: dataplane.MapSchemaVersion,
		Program: &dataplane.PinnedProgram{
			Name: "kapkan_xdp_filter", Type: "XDP", Tag: "a1b2c3d4e5f60718",
			VerifiedInstructions: 8123,
		},
		Attachments: []dataplane.Attachment{
			{Interface: "eth0", Mode: "native", Ifindex: 5, CurrentIfindex: 5, Live: true},
		},
		Live: &dataplane.LiveState{
			SchemaVersion: dataplane.MapSchemaVersion,
			Generation:    1, PolicyStride: 512, StaticStride: 512,
			StaticRules: 3, DynamicRules: 2, PolicyBlocks: 1,
			Terminal: []dataplane.StatCount{
				{Name: "pass_default", Index: 0, Pkts: 1402331, Bytes: 2040000000},
				{Name: "drop_static", Index: 10, Pkts: 12004, Bytes: 737024},
			},
			TerminalTotal: dataplane.StatCount{Name: "total", Pkts: 1414335, Bytes: 2040737024},
			Observation: []dataplane.StatCount{
				{Name: "dryrun_would_drop", Index: 18, Pkts: 12004, Bytes: 737024},
			},
		},
		Maps: []dataplane.InspectedMap{
			{MapStatus: dataplane.MapStatus{Name: "kapkan_rl_src4", Type: "LRUHash",
				MaxEntries: 1048576, Bytes: 115343360}, Entries: 1204},
			{MapStatus: dataplane.MapStatus{Name: "kapkan_cfg", Type: "Array",
				MaxEntries: 1, Bytes: 4096}, Entries: -1},
		},
		MapBytes: 115347456,
	}}
}

func render(doc statusDoc) string {
	var b bytes.Buffer
	renderStatus(&b, doc)
	return b.String()
}

// TestExitCodeScheme is the contract https://kapkan.io/docs/cli publishes. Monitoring
// branches on these numbers, so a change here is a change to an interface.
func TestExitCodeScheme(t *testing.T) {
	// Every InspectState the package defines. Adding one without adding it here
	// fails the exhaustiveness check below, which is the point.
	all := []dataplane.InspectState{
		dataplane.StateEnforcing,
		dataplane.StateDetached,
		dataplane.StateNoPinPath,
		dataplane.StateNoProgram,
		dataplane.StateTorn,
		dataplane.StateSchemaSkew,
		dataplane.StateNotBPFFS,
		dataplane.StateAttachUnknown,
	}
	want := map[dataplane.InspectState]int{
		dataplane.StateEnforcing:  exitOK,
		dataplane.StateDetached:   exitNotEnforcing,
		dataplane.StateNoPinPath:  exitNotEnforcing,
		dataplane.StateNoProgram:  exitNotEnforcing,
		dataplane.StateTorn:       exitNeedsAttention,
		dataplane.StateSchemaSkew: exitNeedsAttention,
		dataplane.StateNotBPFFS:   exitNeedsAttention,
		// Not exitNotEnforcing: the command could not determine the state, and
		// telling monitoring the filter is down when it may be up is worse than
		// telling it the check failed.
		dataplane.StateAttachUnknown: exitError,
	}
	for _, s := range all {
		if got := statusExitCode(s); got != want[s] {
			t.Errorf("statusExitCode(%s) = %d, want %d", s, got, want[s])
		}
	}
	if len(want) != len(all) {
		t.Fatalf("the exit-code table covers %d states, the enumeration lists %d", len(want), len(all))
	}
	// Only StateEnforcing may ever be 0. A monitoring check that treats 0 as
	// "fine" must never see it for a data plane that is not filtering.
	for _, s := range all {
		if s == dataplane.StateEnforcing {
			continue
		}
		if statusExitCode(s) == exitOK {
			t.Errorf("state %s exits 0 but is not enforcing", s)
		}
		if s.Enforcing() {
			t.Errorf("state %s reports Enforcing() = true", s)
		}
	}
}

// TestHeadlineAnswersTheQuestionFirst: the verdict and the interfaces are on
// line one, the remedy on line two. That is the whole design brief for a
// diagnostic someone reads at 3am.
func TestHeadlineAnswersTheQuestionFirst(t *testing.T) {
	lines := strings.Split(render(enforcing()), "\n")
	if !strings.Contains(lines[0], "ENFORCING") || !strings.Contains(lines[0], "eth0") {
		t.Errorf("line 1 = %q, want the verdict and the interface", lines[0])
	}
	if !strings.Contains(lines[1], "attached and filtering") {
		t.Errorf("line 2 = %q, want the reason", lines[1])
	}
}

// TestObservationCountersAreNotSummedIntoTheTotal is the correctness test of the
// whole report. IsObservation counters co-occur with a terminal verdict for the
// same packet, so a reader who adds them in gets a number that does not exist.
func TestObservationCountersAreNotSummedIntoTheTotal(t *testing.T) {
	out := render(enforcing())
	terminal, _, ok := strings.Cut(out, "OBSERVATIONS")
	if !ok {
		t.Fatal("no OBSERVATIONS section; the two counter classes must be presented separately")
	}
	if strings.Contains(terminal, "dryrun_would_drop") {
		t.Error("an observation counter appears in the terminal block, where it will be summed")
	}
	// 1,402,331 + 12,004 = 1,414,335: the terminal counters and nothing else.
	if !strings.Contains(terminal, "1,414,335") {
		t.Errorf("terminal total missing or wrong:\n%s", terminal)
	}
	if !strings.Contains(out, "do NOT add these") {
		t.Error("the observation block does not warn against summing it into the total")
	}
}

// TestGenericModeIsImpossibleToMiss: generic is a silent fallback that costs
// roughly an order of magnitude of capacity, so it must not be a field among
// twenty. It has to be on line one.
func TestGenericModeIsImpossibleToMiss(t *testing.T) {
	doc := enforcing()
	doc.Attachments[0].Mode = "generic"
	doc.Warnings = append(doc.Warnings, "eth0 is attached in GENERIC (skb) mode, not native: "+
		"expect roughly an order of magnitude less capacity.")
	out := render(doc)
	first := strings.SplitN(out, "\n", 2)[0]
	if !strings.Contains(first, "GENERIC") {
		t.Errorf("line 1 = %q, want GENERIC called out", first)
	}
	if !strings.Contains(out, "WARNINGS") {
		t.Error("no WARNINGS section for a generic-mode attachment")
	}
}

// TestDryRunIsInTheHeadline: a data plane in dry-run looks perfectly healthy and
// is dropping nothing. That cannot be a line in the flags block alone.
func TestDryRunIsInTheHeadline(t *testing.T) {
	doc := enforcing()
	doc.Live.DryRun = true
	head, _, _ := strings.Cut(render(doc), "\nATTACHMENTS")
	if !strings.Contains(head, "DRY-RUN") {
		t.Errorf("dry-run is not in the header block:\n%s", head)
	}
}

// TestFailureModesPrintSomethingActionable walks every not-enforcing state and
// requires the report to name the state and carry the reason through. The reason
// strings themselves are written in inspect_linux.go and each names a fix; this
// asserts the renderer does not swallow them.
func TestFailureModesPrintSomethingActionable(t *testing.T) {
	for _, tc := range []struct {
		state  dataplane.InspectState
		reason string
	}{
		{dataplane.StateNoPinPath, "does not exist: the XDP data plane has never run on this host"},
		{dataplane.StateNoProgram, "holds no program pin"},
		{dataplane.StateTorn, "the pin set is TORN"},
		{dataplane.StateSchemaSkew, "SCHEMA SKEW"},
		{dataplane.StateNotBPFFS, "Mount it with `mount -t bpf bpffs /sys/fs/bpf`"},
		{dataplane.StateDetached, "nothing is attached"},
	} {
		doc := statusDoc{Inspection: dataplane.Inspection{
			PinPath: "/sys/fs/bpf/kapkan", State: tc.state, Reason: tc.reason,
			BinarySchemaVersion: dataplane.MapSchemaVersion,
		}}
		out := render(doc)
		if !strings.Contains(out, "NOT ENFORCING") {
			t.Errorf("%s: report does not say NOT ENFORCING:\n%s", tc.state, out)
		}
		if !strings.Contains(out, string(tc.state)) {
			t.Errorf("%s: report does not name the state:\n%s", tc.state, out)
		}
		// The reason is wrapped, so compare on the words rather than the line.
		flat := strings.Join(strings.Fields(out), " ")
		if !strings.Contains(flat, strings.Join(strings.Fields(tc.reason), " ")) {
			t.Errorf("%s: the reason was not printed:\n%s", tc.state, out)
		}
		if !strings.Contains(out, "/sys/fs/bpf/kapkan") {
			t.Errorf("%s: the report does not say which directory it looked at", tc.state)
		}
	}
}

// TestReportAlwaysNamesThePinPathAndItsSource: the single most dangerous way for
// this command to mislead is to confidently report "never ran here" about a
// directory the operator did not mean.
func TestReportAlwaysNamesThePinPathAndItsSource(t *testing.T) {
	doc := enforcing()
	doc.PinPathSource = "built-in default; /etc/kapkan/config.yaml could not be read"
	out := render(doc)
	if !strings.Contains(out, "/sys/fs/bpf/kapkan") || !strings.Contains(out, "could not be read") {
		t.Errorf("report does not disclose where the pin path came from:\n%s", out)
	}
}

// TestDisabledDataplaneIsSaidOutLoud: "not enforcing" is the CORRECT state on a
// host with dataplane.enabled: false, and an operator should not go hunting.
func TestDisabledDataplaneIsSaidOutLoud(t *testing.T) {
	doc := statusDoc{
		Inspection: dataplane.Inspection{PinPath: "/sys/fs/bpf/kapkan", State: dataplane.StateNoPinPath,
			Reason: "never ran here.", BinarySchemaVersion: dataplane.MapSchemaVersion},
		Config: &configContext{Path: "/etc/kapkan/config.yaml", DataplaneEnabled: false},
	}
	if out := render(doc); !strings.Contains(out, "dataplane.enabled is FALSE") {
		t.Errorf("a disabled data plane is not mentioned:\n%s", out)
	}
}

// TestJSONCarriesTheStateAndBothCounterClasses: the JSON form is what tooling
// and our own docs consume, so the terminal/observation split has to survive it.
func TestJSONCarriesTheStateAndBothCounterClasses(t *testing.T) {
	b, err := json.Marshal(enforcing())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["state"] != string(dataplane.StateEnforcing) {
		t.Errorf("state = %v", got["state"])
	}
	live, ok := got["live"].(map[string]any)
	if !ok {
		t.Fatalf("no live block in %s", b)
	}
	for _, k := range []string{"terminal", "observation", "terminal_total", "dynamic_rules", "static_rules", "dry_run"} {
		if _, ok := live[k]; !ok {
			t.Errorf("live block has no %q: %s", k, b)
		}
	}
	if _, ok := got["pin_path"]; !ok {
		t.Error("JSON does not name the pin path it inspected")
	}
}

func TestFormattingHelpers(t *testing.T) {
	for in, want := range map[uint64]string{0: "0", 12: "12", 999: "999", 1000: "1,000",
		12004: "12,004", 1402331: "1,402,331", 1048576: "1,048,576"} {
		if got := comma(in); got != want {
			t.Errorf("comma(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[uint64]string{0: "0 B", 512: "512 B", 4096: "4.0 KiB",
		115343360: "110.0 MiB", 246308864: "234.9 MiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := pct(1, 1048576); got != "<0.1" {
		t.Errorf("pct(1, 1048576) = %q, want <0.1", got)
	}
	if got := pct(0, 512); got != "0" {
		t.Errorf("pct(0, 512) = %q", got)
	}
}

// TestArrayMapsReportNoFill: every slot of a BPF array exists from creation, so
// a key count would imply an occupancy that does not exist.
func TestArrayMapsReportNoFill(t *testing.T) {
	out := render(enforcing())
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "kapkan_cfg") && strings.Contains(line, "entries") {
			t.Errorf("array map reports an entry count: %q", line)
		}
	}
	if !strings.Contains(out, "1,204 entries") {
		t.Errorf("hash map fill missing:\n%s", out)
	}
}

func TestSortedNamesIsStable(t *testing.T) {
	got := sortedNames(enforcing().Maps)
	if strings.Join(got, ",") != "kapkan_cfg,kapkan_rl_src4" {
		t.Errorf("sortedNames = %v", got)
	}
}

// TestAttachUnknownIsNotReportedAsNotEnforcing is a regression test for the
// worst output this command could produce.
//
// It was a real bug, found by running the binary as an unprivileged user against
// a live, filtering data plane: the kernel refuses BPF_OBJ_GET on a link pin
// unless the fd is O_RDWR, so a non-root reader gets every map and no
// attachment — and the state machine called that "detached" and printed NOT
// ENFORCING about a box that was enforcing perfectly well.
func TestAttachUnknownIsNotReportedAsNotEnforcing(t *testing.T) {
	doc := statusDoc{Inspection: dataplane.Inspection{
		PinPath:             "/sys/fs/bpf/kapkan",
		State:               dataplane.StateAttachUnknown,
		Reason:              "NONE of the 1 pinned attachments could be read, so whether packets are being filtered is UNKNOWN — not known to be false.",
		BinarySchemaVersion: dataplane.MapSchemaVersion,
		Attachments: []dataplane.Attachment{{
			Interface: "eth0", Mode: "native",
			Error: "load pinned link: permission denied", Permission: true,
		}},
		Warnings: []string{"the link pin for eth0 could not be read (permission denied); " +
			"re-run as the user the daemon runs as"},
	}}
	out := render(doc)
	if strings.Contains(out, "NOT ENFORCING") {
		t.Errorf("an unreadable attachment was reported as NOT ENFORCING:\n%s", out)
	}
	if !strings.Contains(out, "UNKNOWN") {
		t.Errorf("the report does not say the state is unknown:\n%s", out)
	}
	if !strings.Contains(out, "UNREADABLE") {
		t.Errorf("the attachment row does not say it could not be read:\n%s", out)
	}
	if got := statusExitCode(dataplane.StateAttachUnknown); got != exitError {
		t.Errorf("exit code = %d, want %d (the command could not answer)", got, exitError)
	}
}
