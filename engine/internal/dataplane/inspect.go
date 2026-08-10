package dataplane

// The READ-ONLY view of a pinned data plane, and the types it reports.
//
// WHY THIS EXISTS AT ALL, when Manager.Stats() already returns a Snapshot: because
// Stats() is a method on a Manager, and getting a Manager means calling Open(),
// and Open() adopts-or-creates and then attaches. An operator asking "is the data
// plane working?" on a box that is already misbehaving must not be handed a tool
// that loads a program, creates 235 MiB of maps, rebuilds pins whose schema it
// dislikes, or attaches to a NIC. A diagnostic that mutates the thing it is
// diagnosing is worse than no diagnostic: it destroys the evidence and, in this
// package's case, it can destroy the mitigation too (a rebuild drops every
// dynamic rule the mitigator installed).
//
// So this is a second, deliberately impoverished entry point: open what is
// already pinned, read it, report, close. It never touches the data plane: no
// map value is written, nothing is attached or detached, no pin is created or
// removed, and the program is never loaded. See inspect_linux.go for how that
// is enforced rather than merely intended.
//
// One honest caveat, because the absolute version of that sentence is false:
// cilium/ebpf runs feature probes on first use, and those create a couple of
// tiny anonymous maps (4-byte arrays) which are closed before this returns.
// They are unpinned, unreachable from the data plane, and provably leak
// nothing. They are also the reason CAP_BPF is needed when
// kernel.unprivileged_bpf_disabled is non-zero: BPF_MAP_CREATE is the gated
// syscall, not the reads.
//
// It also has to work with the daemon STOPPED, which is the primary case and not
// a bonus — an operator runs this when kapkan is dead and they want to know
// whether the kernel is still filtering (with on_exit: keep, it is). Everything
// here therefore comes from bpffs and /proc, never from a running process.
//
// This file is untagged, like health.go and options.go, so cmd/kapkan can render
// an Inspection on the macOS development host where nothing can be loaded.

import (
	"fmt"
	"strings"
)

// DefaultPinPath is config's own default for dataplane.pin_path, restated here
// so a read-only inspection can find the pins without loading a config file —
// which is exactly the situation `kapkan dataplane status` runs in on a host
// whose config is elsewhere or unreadable.
//
// TestDefaultPinPathMatchesConfig is the drift gate: it resolves a real config
// and fails if the two ever disagree.
const DefaultPinPath = "/sys/fs/bpf/kapkan"

// InspectState is the coarse answer to "is it working". Stable strings: they are
// the `state` field of `kapkan dataplane status -json` and a monitoring script
// will branch on them.
//
// The order below is the order the checks run in, which is also worst-first for
// diagnosis: you cannot have a torn pin set if there is no bpffs.
type InspectState string

// The states. Each one maps to exactly one remedy, which is the bar for being a
// separate state rather than a detail on another one.
const (
	// StateNotBPFFS: the pin path is not on a bpffs. Nothing can ever be pinned
	// there. Remedy: mount it.
	StateNotBPFFS InspectState = "not_bpffs"
	// StateNoPinPath: the pin directory does not exist. The data plane has never
	// run on this host, or ran and exited with on_exit: detach. Remedy: none
	// needed — this is a correct state for a box where the feature is off.
	StateNoPinPath InspectState = "no_pin_path"
	// StateNoProgram: the directory exists but holds no program pin. Same
	// meaning as StateNoPinPath (systemd's RuntimeDirectory=, a packaging
	// script and a clean on_exit: detach all leave an empty directory), stated
	// separately because the directory being there is exactly what makes an
	// operator think something IS running.
	StateNoProgram InspectState = "no_program"
	// StateTorn: a program pin with maps missing under it. A previous process
	// died between pinning the program and pinning its maps. Remedy: restart —
	// the manager tears a torn set down and rebuilds it.
	StateTorn InspectState = "torn"
	// StateSchemaSkew: the pinned map_schema_version is not the one this binary
	// speaks, so the map CONTENTS cannot be decoded without reading every field
	// at the wrong offset. Remedy: restart — the manager refuses to adopt a
	// skewed set and rebuilds it.
	StateSchemaSkew InspectState = "schema_skew"
	// StateDetached: program and maps are pinned and readable, but no link pin
	// is bound to a live netdevice. Policy is intact; nothing is being filtered.
	StateDetached InspectState = "detached"
	// StateAttachUnknown: the maps could be read but the LINK pins could not, so
	// whether packets are being filtered is genuinely unknown.
	//
	// This is not a hypothetical. It is what an unprivileged operator gets, and
	// it took a measurement to find: BPF_OBJ_GET refuses a link whose file flags
	// are anything but O_RDWR, so reading a link pin needs WRITE permission on
	// its inode, while reading a map pin needs only read. kapkan's pins are mode
	// 0600, so a non-root reader sees every map and no attachment.
	//
	// It exists as a separate state because the alternative was reporting
	// StateDetached — "NOT ENFORCING" — about a box that is enforcing perfectly
	// well. A diagnostic may say "I do not know"; it may not guess.
	StateAttachUnknown InspectState = "attach_unknown"
	// StateEnforcing: at least one interface has a live XDP attachment.
	StateEnforcing InspectState = "enforcing"
	// StateUnreadable: the inspection itself failed and produced no verdict —
	// a permission denial, an I/O error. It is never returned by InspectPins
	// (which returns an error instead); it exists so the -json error document
	// carries the same `state` field as a successful one and a pipeline reading
	// .state never has to special-case an empty stdout.
	StateUnreadable InspectState = "unreadable"
)

// Enforcing reports whether packets are actually being filtered. It is the
// one-bit answer the first line of `kapkan dataplane status` gives, and the
// difference between exit 0 and exit 10.
func (s InspectState) Enforcing() bool { return s == StateEnforcing }

// Inspection is everything a read-only pass over a pin directory can learn.
//
// It is Snapshot-shaped on purpose — Maps, the verdict counters, the generation
// and the schema version are the same values Manager.Stats() reports, so the two
// can be compared field for field when the daemon IS running. It differs where
// the difference is real: there is no Health here, because health is a property
// of a Manager's own attach attempts and this process made none; what there is
// instead is Attachments, read back out of the link pins.
//
// Fields that could not be read are absent rather than zero. A zero counter and
// an unread counter are not the same claim, and at 3am the difference decides
// whether an operator restarts the daemon.
type Inspection struct {
	// PinPath is the directory that was read, and PinPathSource says where that
	// path came from. The second field exists because the single most dangerous
	// way for this command to mislead is to confidently report "never ran here"
	// about the wrong directory.
	PinPath       string `json:"pin_path"`
	PinPathSource string `json:"pin_path_source,omitempty"`
	// State is the verdict; Reason is one human sentence naming the remedy.
	State  InspectState `json:"state"`
	Reason string       `json:"reason"`
	// Kernel is the running kernel's release string, "" if unreadable.
	Kernel string `json:"kernel,omitempty"`
	// BinarySchemaVersion is the MapSchemaVersion this binary speaks. It is
	// reported unconditionally so a skew is legible from the output alone,
	// without the reader having to know which build they are holding.
	BinarySchemaVersion uint32 `json:"binary_map_schema_version"`

	// Program describes the pinned program, nil when there is none.
	Program *PinnedProgram `json:"program,omitempty"`
	// Attachments is one entry per link pin, whether or not it is still live.
	Attachments []Attachment `json:"attachments,omitempty"`

	// Live is the decoded map CONTENTS: generation, rule counts, flags and the
	// verdict counters. It is nil whenever the contents could not be trusted —
	// no maps, or a schema skew — because reporting a generation read at the
	// wrong offset is worse than reporting nothing.
	Live *LiveState `json:"live,omitempty"`

	// Maps is the per-map cost and occupancy, largest first.
	Maps []InspectedMap `json:"maps,omitempty"`
	// MapBytes totals Maps[].Bytes.
	MapBytes uint64 `json:"map_bytes,omitempty"`
	// MissingMaps names contract maps with no pin. Non-empty means StateTorn.
	MissingMaps []string `json:"missing_maps,omitempty"`
	// UnknownPins names entries in the directory this build does not recognise.
	// Reported, never touched: pin_path may be a shared bpffs directory.
	UnknownPins []string `json:"unknown_pins,omitempty"`

	// Warnings are things that are working but should not be left alone — a
	// generic-mode attachment, dry-run, a link pin whose netdevice is gone.
	// Each is one sentence naming the consequence.
	Warnings []string `json:"warnings,omitempty"`

	// Bypass is the alarm: traffic that went past the filter without any rule
	// being evaluated. Empty on a healthy box, and empty is the overwhelmingly
	// common case, which is exactly why a non-empty one is worth its own field
	// instead of a row in a twenty-one-line counter table.
	//
	// It is a separate field from Warnings because the two say different things
	// to whoever is reading. A warning is "this box is misconfigured"; this is
	// "somebody may be routing around your filter". A monitoring script can key
	// on `.filter_bypass | length > 0` without parsing prose.
	Bypass []BypassSignal `json:"filter_bypass,omitempty"`
}

// BypassSignal is one parse-limit bypass with a non-zero counter: packets the
// datapath PASSED without consulting a single rule. See Stat.BypassReason for
// why this is a security signal and not a parser statistic.
type BypassSignal struct {
	// Reason is the stable class name, matching the Prometheus label value on
	// kapkan_dataplane_filter_bypass_packets_total.
	Reason string `json:"reason"`
	// Stat is the underlying counter's name in the terminal block, so a reader
	// can find the same number there and see that it is not double-counted.
	Stat  string `json:"stat"`
	Pkts  uint64 `json:"pkts"`
	Bytes uint64 `json:"bytes"`
	// Message is the operator-facing sentence: what happened, and what to do.
	Message string `json:"message"`
}

// bypassSignals extracts the alarm-grade counters from a decoded LiveState.
//
// It reads l.Terminal, which is already zero-suppressed, so a zero counter
// produces no signal and a healthy box produces an empty slice — nil, not [],
// because `omitempty` on the field is the whole point: the key's ABSENCE is the
// all-clear, and a consumer checking `.filter_bypass` gets null rather than an
// empty array it has to distinguish from a missing one.
func bypassSignals(l *LiveState) []BypassSignal {
	if l == nil {
		return nil
	}
	var out []BypassSignal
	for _, c := range l.Terminal {
		if c.Pkts == 0 && c.Bytes == 0 {
			continue
		}
		reason, ok := Stat(c.Index).BypassReason()
		if !ok {
			continue
		}
		out = append(out, BypassSignal{
			Reason:  reason,
			Stat:    c.Name,
			Pkts:    c.Pkts,
			Bytes:   c.Bytes,
			Message: bypassMessage(reason),
		})
	}
	return out
}

// bypassMessage is the one home for the sentence an operator reads, so the CLI
// report, the JSON document and anything else quoting it cannot drift apart.
func bypassMessage(reason string) string {
	switch reason {
	case "ipv6_exthdr_cap":
		return fmt.Sprintf("These packets carried %d or more IPv6 extension headers, which is the "+
			"datapath's parse limit, so the parser gave up BEFORE the rule scan and the packets were "+
			"forwarded with no rule evaluated at all — allow-lists, drop rules and rate limits alike. "+
			"They are passed rather than dropped on purpose: a parse budget must not become a "+
			"default-deny. Nothing legitimate chains %d extension headers, so treat any movement here "+
			"as a possible attempt to evade this filter. Identify the source, and either filter the "+
			"chain upstream (a router ACL on IPv6 extension-header count) or alert and investigate.",
			MaxIPv6ExtHdrs, MaxIPv6ExtHdrs)
	}
	return "These packets were forwarded without any rule being evaluated."
}

// HasBypass reports whether the filter was bypassed at all. It is the one-bit
// question a first line answers.
func (i Inspection) HasBypass() bool { return len(i.Bypass) > 0 }

// PinnedProgram is the identity of the program in the pin directory.
type PinnedProgram struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	// Tag is the kernel's hash of the linked instruction stream. Two binaries
	// with the same tag load the same datapath; a different tag is what makes a
	// restart refuse to adopt these pins. It is NOT compared here — computing
	// this binary's tag means loading the program, which is a write.
	Tag string `json:"tag,omitempty"`
	// VerifiedInstructions is what the verifier walked, 0 if unavailable.
	VerifiedInstructions uint32 `json:"verified_instructions,omitempty"`
}

// Attachment is one link pin: the interface it names, the mode it was attached
// in, and whether the kernel still has it bound to a netdevice.
type Attachment struct {
	// Interface and Mode are parsed from the pin's file name, which is the only
	// place the mode is recorded — bpf_link_info for XDP carries the ifindex and
	// nothing else. See linkPinPrefix.
	Interface string `json:"interface"`
	Mode      string `json:"mode"`
	// Ifindex is what the link reports. 0 is the kernel's own way of saying the
	// netdevice this link pointed at has been unregistered.
	Ifindex int `json:"ifindex"`
	// CurrentIfindex is the ifindex the interface NAME resolves to right now, 0
	// when no such interface exists. A mismatch with Ifindex means the NIC was
	// replaced or renamed and this link is filtering something else, or nothing.
	CurrentIfindex int `json:"current_ifindex"`
	// Live is the ground truth: the link is bound to a netdevice and that
	// netdevice is the one this interface name resolves to.
	Live bool `json:"live"`
	// Error explains a link pin that could not be read, and Permission says the
	// reason was permission rather than corruption. They are separate because
	// only one of them has a remedy the operator can apply in the next second.
	Error      string `json:"error,omitempty"`
	Permission bool   `json:"permission_denied,omitempty"`
}

// LiveState is the decoded contents of kapkan_cfg plus the counters. Present
// only when the pinned schema version matches this binary's.
type LiveState struct {
	SchemaVersion uint32 `json:"map_schema_version"`
	Generation    uint32 `json:"generation"`
	PolicyStride  uint32 `json:"policy_stride"`
	StaticStride  uint32 `json:"static_stride"`
	// StaticRules is kapkan_cfg's static_count: the operator's rules from the
	// config file, in the live generation.
	StaticRules uint32 `json:"static_rules"`
	// DynamicRules is the mitigator's rules in the live generation, and
	// ExpiredDynamicRules how many of those are past their in-kernel TTL. An
	// expired rule is treated as ABSENT by the datapath but still occupies its
	// slot, so the two numbers answer different questions: how much of the rule
	// budget is used, and how much of it is actually dropping traffic.
	DynamicRules        int `json:"dynamic_rules"`
	ExpiredDynamicRules int `json:"expired_dynamic_rules"`
	// PolicyBlocks is how many victims have a rule block in the live generation.
	PolicyBlocks int `json:"policy_blocks"`
	// DryRun is what the KERNEL is doing, not what the config file asked for.
	// True means every drop verdict is rewritten to a pass.
	DryRun        bool `json:"dry_run"`
	DropMalformed bool `json:"drop_malformed"`

	// Terminal counters partition the traffic: exactly one is bumped per packet,
	// so their sum is the packet count and TerminalTotal is meaningful.
	Terminal      []StatCount `json:"terminal"`
	TerminalTotal StatCount   `json:"terminal_total"`
	// Observation counters CO-OCCUR with a terminal one for the same packet.
	// They are a separate list, and there is deliberately no total, because the
	// only thing a total of these could invite is adding it to TerminalTotal.
	Observation []StatCount `json:"observation"`
}

// StatCount is one verdict counter with its stable name.
type StatCount struct {
	Name  string `json:"name,omitempty"`
	Index uint32 `json:"index"`
	Pkts  uint64 `json:"pkts"`
	Bytes uint64 `json:"bytes"`
}

// InspectedMap is a map's cost plus how much of it is in use. It extends the
// MapStatus that Manager.Stats() already reports rather than changing it, so the
// API's shape is untouched.
type InspectedMap struct {
	MapStatus
	// Entries is the number of keys present, or -1 when it was not counted.
	// ARRAY maps are always fully allocated, so a key count for them would be a
	// restatement of MaxEntries and is not attempted.
	Entries int64 `json:"entries"`
	// Capped is true when the walk hit inspectEntryBudget and stopped, so
	// Entries is a floor rather than a count.
	Capped bool `json:"entries_capped,omitempty"`
}

// LiveInterfaces names the interfaces with a live XDP attachment, in report
// order. Non-empty means the datapath IS filtering, whatever else is wrong.
func (i Inspection) LiveInterfaces() []string {
	var live []string
	for _, a := range i.Attachments {
		if a.Live {
			live = append(live, a.Interface+"/"+a.Mode)
		}
	}
	return live
}

// Summary renders the verdict as one line, the way Health.Summary does: short
// enough to page, specific enough to act on.
//
// The verdict is decided by whether a live attachment was OBSERVED, not by
// which fault check returned first. StateTorn and StateSchemaSkew are found
// before the attachment scan runs, and a state-ordered verdict therefore used
// to print "NOT ENFORCING (torn)" in the same report that listed a LIVE
// attachment — while drop counters climbed. That is worse than unhelpful: an
// operator mid-attack reads it as "my traffic is unfiltered" and a monitoring
// check reads the exit code as "the filter is down", when neither is true. A
// torn pin set and a schema skew break this command's ability to READ the data
// plane; they do not stop the kernel from running the program it already has.
//
// So: enforcing-but-degraded when packets are provably being filtered, and the
// fault named in the same breath so nobody reads it as "all clear". Same
// standard as StateAttachUnknown — say what is known, never guess.
func (i Inspection) Summary() string {
	if live := i.LiveInterfaces(); len(live) > 0 && i.State != StateEnforcing {
		return fmt.Sprintf("dataplane: ENFORCING on %s, BUT DEGRADED — %s "+
			"(the program is filtering; this command cannot fully read it)",
			strings.Join(live, ", "), i.State)
	}
	switch i.State {
	case StateEnforcing:
		s := "dataplane: ENFORCING on " + strings.Join(i.LiveInterfaces(), ", ")
		if i.Live != nil && i.Live.DryRun {
			s += " (DRY-RUN: every drop is rewritten to a pass)"
		}
		return s
	case StateDetached:
		return "dataplane: NOT ENFORCING — pinned but attached to nothing"
	case StateAttachUnknown:
		return "dataplane: UNKNOWN — the maps read, the attachments did not"
	default:
		return fmt.Sprintf("dataplane: NOT ENFORCING — %s", i.State)
	}
}

// dynamicRuleTotals is the arithmetic over a generation's policy blocks, split
// out so it can be unit-tested on any host: blocks with at least one rule, the
// rules in them, and how many of those rules the datapath would already treat as
// absent because their boot-clock deadline has passed.
//
// nowNs is CLOCK_BOOTTIME in nanoseconds, comparable with the ExpiresAtNs the
// encoder writes. A zero deadline never expires and is reserved for static
// rules, so it is never counted as expired here.
func dynamicRuleTotals(blocks []PolicyBlock, nowNs uint64) (used, rules, expired int) {
	for _, b := range blocks {
		n := int(b.N_rules)
		if n <= 0 {
			continue
		}
		if n > RulesPerPolicy {
			n = RulesPerPolicy
		}
		used++
		rules += n
		for _, r := range b.Rules[:n] {
			if r.ExpiresAtNs != 0 && nowNs != 0 && r.ExpiresAtNs <= nowNs {
				expired++
			}
		}
	}
	return used, rules, expired
}

// splitCounters divides the counter block into the two lists that must never be
// summed together, dropping the zeros. Zero-suppression is not cosmetic: a flat
// list of 21 counters of which 3 are non-zero hides the 3, and the whole point
// of the section is that a reader can see which branch decided the traffic's
// fate.
func splitCounters(c [StatMax]Counter) (terminal, observation []StatCount, total StatCount) {
	// Non-nil so the JSON is [] rather than null. `jq '.live.observation[]'`
	// errors on null, and no observations at all is the healthy, common case —
	// the shape of the document should not change with the traffic.
	terminal, observation = []StatCount{}, []StatCount{}
	for s := Stat(0); s < StatMax; s++ {
		e := StatCount{Name: s.String(), Index: uint32(s), Pkts: c[s].Pkts, Bytes: c[s].Bytes}
		if s.IsObservation() {
			if e.Pkts != 0 || e.Bytes != 0 {
				observation = append(observation, e)
			}
			continue
		}
		total.Pkts += e.Pkts
		total.Bytes += e.Bytes
		if e.Pkts != 0 || e.Bytes != 0 {
			terminal = append(terminal, e)
		}
	}
	total.Name = "total"
	total.Index = uint32(StatMax)
	return terminal, observation, total
}
