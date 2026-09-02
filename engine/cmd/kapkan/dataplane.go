package main

// `kapkan dataplane status` — the 3am command.
//
// The reader is an on-call engineer on a box that is already misbehaving. Two
// things follow from that and shape everything below.
//
// FIRST, IT MUST NOT TOUCH ANYTHING. It never calls dataplane.Open(), which
// adopts-or-creates, sizes maps, installs policy and attaches. It calls
// dataplane.InspectPins, which opens the pinned objects read-only and reads
// them. A diagnostic that rebuilds the pin set it disapproves of would destroy
// every dynamic rule the mitigator has installed — during the attack the
// operator is running it for.
//
// SECOND, IT MUST WORK WITH THE DAEMON STOPPED. That is the primary case: with
// on_exit: keep (the default) the kernel goes on filtering with no userspace at
// all, and "is it still filtering?" is precisely the question. Nothing here
// talks to a running kapkan — no API call, no pid file, no unix socket. It reads
// bpffs.
//
// The output is built for a stressed reader: the verdict and the remedy are the
// first two lines, everything else is below them, and the two things that most
// often mislead are given their own visual weight — generic attach mode (a
// silent order-of-magnitude capacity loss) and the observation counters (which
// co-occur with a verdict and must never be summed into the packet total).

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
)

// runDataplaneCommand dispatches the verbs under `kapkan dataplane`.
func runDataplaneCommand(args []string, f *cliFlags, out, errOut io.Writer) int {
	if len(args) == 0 {
		lineWriter{errOut}.line("kapkan dataplane: missing subcommand\n\nSubcommands:\n" +
			"  status    report the XDP data plane's state (read-only)")
		return exitUsage
	}
	switch args[0] {
	case "status":
		return runDataplaneStatus(args[1:], f, out, errOut)
	}
	lineWriter{errOut}.printf("kapkan dataplane: unknown subcommand %q (want: status)\n", args[0])
	return exitUsage
}

// statusDoc is the -json document: the Inspection plus the context that decided
// which directory was inspected. The context is not cosmetic — the single most
// dangerous way for this command to mislead is to report "never ran here" with
// total confidence about the wrong pin path.
type statusDoc struct {
	dataplane.Inspection
	Config *configContext `json:"config,omitempty"`
}

// statusErrorDoc is what -json emits when the inspection itself failed, so a
// pipeline always gets a parseable document with a `state` field rather than an
// empty stdout and prose on stderr.
type statusErrorDoc struct {
	State         string `json:"state"`
	Error         string `json:"error"`
	PinPath       string `json:"pin_path"`
	PinPathSource string `json:"pin_path_source"`
}

// configContext is what the config file said, when one could be read.
type configContext struct {
	Path             string `json:"path"`
	DataplaneEnabled bool   `json:"dataplane_enabled"`
}

// runDataplaneStatus implements `kapkan dataplane status`.
func runDataplaneStatus(args []string, f *cliFlags, out, errOut io.Writer) int {
	fs := subcommandFlags("dataplane status", errOut)
	asJSON := fs.Bool("json", false, "print the full inspection as JSON instead of the human report")
	pinPath := fs.String("pin-path", "", "bpffs pin directory to inspect (default: dataplane.pin_path from -config, else "+dataplane.DefaultPinPath+")")
	if err := fs.Parse(args); err != nil {
		// -h/-help is a request, not a mistake: flag has already printed the
		// usage, and asking for help successfully is an exit 0.
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if !rejectExtraArgs(fs, "dataplane status", errOut) {
		return exitUsage
	}

	dir, source, cc := resolvePinPath(*pinPath, f.configPath)
	ins, err := dataplane.InspectPins(dir)
	// PinPath/PinPathSource are filled in here rather than inside InspectPins
	// because only this layer knows where the path came from, and they are set
	// on the error path too: a permission failure still has to tell the operator
	// WHICH directory it could not read.
	ins.PinPath, ins.PinPathSource = dir, source
	if err != nil {
		// -json exists so tooling can parse this. A bare prose line on stderr and
		// an empty stdout means `kapkan dataplane status -json | jq .state` fails
		// to parse in exactly the situation worth alerting on, so the error path
		// emits a document with the same `state` field the success path has.
		if *asJSON {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(statusErrorDoc{
				State:         string(dataplane.StateUnreadable),
				Error:         err.Error(),
				PinPath:       dir,
				PinPathSource: source,
			}); encErr != nil {
				lineWriter{errOut}.printf("kapkan dataplane status: %v\n", encErr)
			}
			return exitError
		}
		lineWriter{errOut}.printf("kapkan dataplane status: %v\n\npin path: %s (%s)\n", err, dir, source)
		return exitError
	}

	doc := statusDoc{Inspection: ins, Config: cc}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			lineWriter{errOut}.printf("kapkan dataplane status: %v\n", err)
			return exitError
		}
		return statusExitCode(ins.State)
	}
	renderStatus(out, doc)
	return statusExitCode(ins.State)
}

// statusExitCode maps the inspected state onto the process exit code.
//
// Four buckets, because there are four different things an operator does next:
// nothing (0), start or attach it (10), fix the box (11), or re-run the command
// with more privilege (1 — the command could not answer). Splitting "never ran"
// from "detached" into separate codes would be a distinction the caller cannot
// act on differently; both are read off the printed state, or the JSON `state`
// field, when it matters.
//
// Only StateEnforcing may ever be 0. A check that treats 0 as "fine" must never
// see it for a data plane that is not filtering — or for one whose state this
// command could not determine.
func statusExitCode(s dataplane.InspectState) int {
	switch s {
	case dataplane.StateEnforcing:
		return exitOK
	case dataplane.StateNotBPFFS, dataplane.StateTorn, dataplane.StateSchemaSkew:
		return exitNeedsAttention
	case dataplane.StateAttachUnknown:
		// Not "not enforcing": unknown. Reporting 10 here would tell a
		// monitoring system the filter is down when it may be up.
		return exitError
	default:
		// StateNoPinPath, StateNoProgram, StateDetached.
		return exitNotEnforcing
	}
}

// resolvePinPath decides which directory to inspect, and records why.
//
// Order: an explicit -pin-path wins; then the config file's dataplane.pin_path;
// then the built-in default. The config is loaded best-effort — a status command
// that refused to run because the config file is unreadable would be useless in
// exactly the situation it exists for, and the default pin path is right on the
// overwhelming majority of hosts.
func resolvePinPath(explicit, configPath string) (dir, source string, cc *configContext) {
	if explicit != "" {
		return explicit, "-pin-path", nil
	}
	// Parse, not Load: the pin path lives in THIS file, and following
	// edge.zones_file here would let a tenant's broken zones file block a
	// diagnostic that exists for exactly such moments. Parse validates the edge
	// block's shape and never reads the zones file.
	raw, err := os.ReadFile(configPath)
	var cfg *config.Config
	if err == nil {
		cfg, err = config.Parse(raw)
	}
	switch {
	case err != nil:
		return dataplane.DefaultPinPath, fmt.Sprintf(
			"built-in default; %s could not be read or parsed, so dataplane.pin_path was not consulted — "+
				"pass -config or -pin-path if your pin path is not the default", configPath), nil
	case cfg.Dataplane == nil:
		return dataplane.DefaultPinPath, fmt.Sprintf(
				"built-in default; %s has no dataplane block", configPath),
			&configContext{Path: configPath, DataplaneEnabled: false}
	default:
		return cfg.DataplaneCfg.PinPath, "dataplane.pin_path in " + configPath,
			&configContext{Path: configPath, DataplaneEnabled: cfg.DataplaneCfg.Enabled}
	}
}

/* ========================================================================= */
/* The human report                                                           */
/* ========================================================================= */

// renderStatus writes the human report.
//
// THE FIRST TWO LINES ARE THE WHOLE COMMAND for most readings: line one is the
// verdict with the interfaces and the mode, line two is one sentence saying what
// to do about it. Everything below them is for the reading where the first two
// were not enough.
func renderStatus(dst io.Writer, doc statusDoc) {
	w := lineWriter{dst}
	ins := doc.Inspection
	w.printf("kapkan data plane: %s\n", headline(ins))
	w.printf("%s\n", indentWrap(ins.Reason, "  ", 96))

	// ABOVE everything else, including the pin path, and above the counter table
	// this number also appears in. A filter bypass is the one thing in this
	// report that says the operator's rules did not run at all, and it is
	// small — a few thousand packets is a working evasion — so it loses every
	// contest for attention against a drop counter in the millions. It gets the
	// second-most-read position on the page, right under the verdict.
	renderBypass(w, ins)

	w.line("")
	w.printf("  pin path   %s\n", ins.PinPath)
	if ins.PinPathSource != "" {
		w.printf("%s\n", indentWrap("("+ins.PinPathSource+")", "             ", 96))
	}
	if doc.Config != nil && !doc.Config.DataplaneEnabled {
		w.printf("  config     dataplane.enabled is FALSE in %s — this host is not meant to be filtering\n",
			doc.Config.Path)
	}
	if ins.Kernel != "" {
		w.printf("  kernel     %s\n", ins.Kernel)
	}
	w.printf("  schema     binary speaks v%d", ins.BinarySchemaVersion)
	switch {
	case ins.State == dataplane.StateSchemaSkew && ins.Live == nil:
		w.print("  ·  PINNED MAPS ARE A DIFFERENT VERSION (see above)")
	case ins.Live != nil:
		w.printf("  ·  pins are v%d (match)", ins.Live.SchemaVersion)
	}
	w.line("")
	if p := ins.Program; p != nil {
		w.printf("  program    %s  %s  tag %s", orDash(p.Name), strings.ToLower(p.Type), orDash(p.Tag))
		if p.VerifiedInstructions > 0 {
			w.printf("  %s verified insns", comma(uint64(p.VerifiedInstructions)))
		}
		w.line("")
	}

	renderAttachments(w, ins)
	renderRules(w, ins)
	renderCounters(w, ins)
	renderMaps(w, ins)

	if len(ins.UnknownPins) > 0 {
		w.printf("\nOTHER PINS IN THIS DIRECTORY  (not kapkan's; left alone)\n  %s\n",
			strings.Join(ins.UnknownPins, ", "))
	}
	if len(ins.Warnings) > 0 {
		w.line("\nWARNINGS")
		for _, warn := range ins.Warnings {
			// Hanging indent: the "!" marks the start of a warning, and a
			// continuation line that lined up with it would read as a second one.
			w.printf("%s\n", hangWrap("  ! ", "    ", warn, 96))
		}
	}
}

// headline is the first line's verdict. It carries the attach mode and the
// dry-run flag because those are the two ways a data plane can look healthy and
// not be doing what the operator thinks: generic mode costs roughly an order of
// magnitude of capacity, and dry-run means every drop is rewritten to a pass.
func headline(ins dataplane.Inspection) string {
	// A live attachment settles the question, and it is checked FIRST, before
	// the state. torn and schema_skew are detected before the attachment scan,
	// so a state-ordered verdict printed "NOT ENFORCING (torn)" directly above a
	// LIVE attachment while drop counters climbed. Those two faults break this
	// command's ability to READ the data plane; they do not stop the kernel
	// running the program it already loaded. Saying otherwise sends an operator
	// mid-attack hunting traffic that is in fact being filtered.
	degraded := ins.State != dataplane.StateEnforcing && len(ins.LiveInterfaces()) > 0

	if !degraded {
		switch ins.State {
		case dataplane.StateAttachUnknown:
			// "NOT ENFORCING" here would be a false alarm about a box that is
			// very probably filtering fine; the command just could not see the
			// links.
			return "UNKNOWN  (" + string(ins.State) + ") — could not read the attachments"
		case dataplane.StateEnforcing:
		default:
			return "NOT ENFORCING  (" + string(ins.State) + ")"
		}
	}

	var on []string
	generic := false
	for _, a := range ins.Attachments {
		if !a.Live {
			continue
		}
		on = append(on, fmt.Sprintf("%s (%s)", a.Interface, strings.ToUpper(a.Mode)))
		if a.Mode == config.XDPModeGeneric {
			generic = true
		}
	}
	s := "ENFORCING on " + strings.Join(on, ", ")
	if degraded {
		s += "  (" + string(ins.State) + ")"
	}
	if generic {
		s += "  << GENERIC/skb path: ~10x less capacity than native"
	}
	if degraded {
		s += "\n                   DEGRADED: the program is filtering, but this command cannot fully" +
			"\n                   read it — see the reason below. Restarting kapkan resolves it."
	}
	if ins.Live != nil && ins.Live.DryRun {
		s += "\n                   DRY-RUN: every drop verdict is rewritten to a pass — nothing is being dropped"
	}
	return s
}

// renderBypass prints the filter-bypass alarm, and prints nothing at all when
// there is none — which is the normal case, so its presence in the output is
// itself the signal.
//
// It is deliberately the loudest thing in the report. The failure mode being
// designed against is an operator reading "ENFORCING", seeing healthy drop
// counters, and never noticing the four-digit counter that means some fraction
// of the attack walked straight past every rule.
func renderBypass(w lineWriter, ins dataplane.Inspection) {
	if !ins.HasBypass() {
		return
	}
	w.line("")
	w.line("  " + strings.Repeat("=", 94))
	for _, b := range ins.Bypass {
		w.printf("  !! FILTER BYPASSED — %s packets (%s) were PASSED WITHOUT ANY RULE BEING EVALUATED\n",
			comma(b.Pkts), humanBytes(b.Bytes))
		w.printf("     %s\n", strings.ToUpper(b.Reason))
		w.printf("%s\n", hangWrap("     ", "     ", b.Message, 96))
	}
	w.line("  " + strings.Repeat("=", 94))
}

func renderAttachments(w lineWriter, ins dataplane.Inspection) {
	if len(ins.Attachments) == 0 {
		return
	}
	w.line("\nATTACHMENTS")
	for _, a := range ins.Attachments {
		state := "LIVE"
		switch {
		case a.Error != "":
			state = "UNREADABLE: " + a.Error
		case a.Ifindex == 0:
			state = "DEAD — the netdevice is gone, this interface is NOT filtered"
		case !a.Live:
			state = fmt.Sprintf("STALE — pinned to ifindex %d, %s is now ifindex %d",
				a.Ifindex, a.Interface, a.CurrentIfindex)
		}
		mode := a.Mode
		if a.Mode == config.XDPModeGeneric {
			mode = "GENERIC"
		}
		w.printf("  %-14s %-8s ifindex %-5d %s\n", a.Interface, mode, a.Ifindex, state)
	}
}

func renderRules(w lineWriter, ins dataplane.Inspection) {
	l := ins.Live
	if l == nil {
		return
	}
	w.printf("\nRULES  (generation %d, live half of %d)\n", l.Generation, 2)
	w.printf("  static     %s of %s encoded slots   (from the config file)\n",
		comma(uint64(l.StaticRules)), comma(uint64(l.StaticStride)))
	expired := ""
	if l.ExpiredDynamicRules > 0 {
		expired = fmt.Sprintf("   %s past their in-kernel expiry (treated as absent)",
			comma(uint64(l.ExpiredDynamicRules)))
	}
	w.printf("  dynamic    %s in %s of %s policy blocks   (installed by the mitigator)%s\n",
		comma(uint64(l.DynamicRules)), comma(uint64(l.PolicyBlocks)),
		comma(uint64(l.PolicyStride)), expired)
	w.printf("  flags      dry_run %s   drop_malformed %s\n", onOff(l.DryRun), onOff(l.DropMalformed))
}

// renderCounters prints the two counter classes as two blocks, and never as one.
//
// This is a correctness requirement, not a layout preference. Terminal counters
// PARTITION the traffic — exactly one is bumped per packet — so their sum is the
// packet count and a total under them is meaningful. Observation counters are
// bumped ALONGSIDE a terminal one for the same packet. A reader given one flat
// list will add it up, and the number they get is the packet count plus the
// observations, which is not a quantity that exists.
func renderCounters(w lineWriter, ins dataplane.Inspection) {
	l := ins.Live
	if l == nil {
		return
	}
	w.line("\nVERDICTS  ·  terminal: exactly one per packet, so these add up")
	if len(l.Terminal) == 0 {
		w.line("  (all zero — no packet has reached the program yet)")
	}
	for _, c := range l.Terminal {
		// A bypass row is flagged where it is READ, not only in the banner
		// above: an operator who scrolled to the counters and is comparing them
		// against an interface counter must not have to remember which of the
		// twenty-one names means "no rule ran".
		mark := ""
		if _, ok := dataplane.Stat(c.Index).BypassReason(); ok {
			mark = "   << FILTER BYPASSED, see the top of this report"
		}
		w.printf("  %-22s %14s pkts  %12s%s\n", c.Name, comma(c.Pkts), humanBytes(c.Bytes), mark)
	}
	if len(l.Terminal) > 0 {
		w.printf("  %s\n", strings.Repeat("-", 60))
		w.printf("  %-22s %14s pkts  %12s\n", "total", comma(l.TerminalTotal.Pkts), humanBytes(l.TerminalTotal.Bytes))
	}

	if len(l.Observation) > 0 {
		w.line("\nOBSERVATIONS  ·  bumped ALONGSIDE a verdict above — do NOT add these to the total")
		for _, c := range l.Observation {
			w.printf("  %-22s %14s pkts  %12s\n", c.Name, comma(c.Pkts), humanBytes(c.Bytes))
		}
	}
}

func renderMaps(w lineWriter, ins dataplane.Inspection) {
	if len(ins.Maps) == 0 {
		return
	}
	w.printf("\nMAPS  ·  %s across %d maps\n", humanBytes(ins.MapBytes), len(ins.Maps))
	for _, m := range ins.Maps {
		fill := "-"
		if m.Entries >= 0 {
			fill = comma(uint64(m.Entries)) + " entries"
			if m.Capped {
				fill = "at least " + fill
			}
			if m.MaxEntries > 0 && !m.Capped {
				fill += fmt.Sprintf(" (%s%%)", pct(uint64(m.Entries), uint64(m.MaxEntries)))
			}
		}
		w.printf("  %-20s %-14s %12s max  %10s  %s\n",
			m.Name, m.Type, comma(uint64(m.MaxEntries)), humanBytes(m.Bytes), fill)
	}
}

/* ========================================================================= */
/* Formatting helpers                                                         */
/* ========================================================================= */

// comma groups an integer in threes. Packet counters are the numbers an operator
// compares against an interface counter at 3am, and 1402331 versus 14023310 is
// not a comparison the eye makes reliably.
func comma(v uint64) string {
	s := strconv.FormatUint(v, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// humanBytes renders a byte count in binary units, which is what the kernel's
// own memlock accounting is in.
func humanBytes(v uint64) string {
	const unit = 1024
	if v < unit {
		return strconv.FormatUint(v, 10) + " B"
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(v)/float64(div), "KMGTP"[exp])
}

// pct renders a fill percentage with enough precision to distinguish "empty"
// from "nearly empty" on a million-entry map.
func pct(n, of uint64) string {
	if of == 0 {
		return "0"
	}
	p := float64(n) * 100 / float64(of)
	switch {
	case p == 0:
		return "0"
	case p < 0.1:
		return "<0.1"
	default:
		return strconv.FormatFloat(p, 'f', 1, 64)
	}
}

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "off"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// indentWrap wraps a sentence to width and indents every line, so a Reason that
// names a fix in three clauses stays readable in an 80-column terminal instead
// of becoming one line the operator has to scroll.
func indentWrap(s, indent string, width int) string { return hangWrap(indent, indent, s, width) }

// hangWrap is indentWrap with a different prefix on the first line, for list
// items whose marker must not be repeated on continuations.
func hangWrap(first, rest, s string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return first
	}
	var (
		out  []string
		line = first + words[0]
	)
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			out = append(out, line)
			line = rest + word
			continue
		}
		line += " " + word
	}
	return strings.Join(append(out, line), "\n")
}

// sortedNames is used by the tests to compare against dataplane.AllMaps without
// depending on the report's largest-first ordering.
func sortedNames(maps []dataplane.InspectedMap) []string {
	out := make([]string, 0, len(maps))
	for _, m := range maps {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}
