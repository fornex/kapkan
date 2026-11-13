// Package steer is an edge node's testimony about itself (edge-spec §8, E7:
// "testify, don't steer"). For each steered address — a VIP the operator's
// own BGP speaker announces from several nodes — it keeps a node-local,
// damped verdict on one question: should this box carry this address now?
// Kapkan never speaks BGP on an edge node and never names a prefix. The
// verdict is read on loopback (E7.2: GET /steer, `kapkan edge -steer`), and
// the operator's speaker, driven by the shipped consumer (E7.3), announces or
// withdraws. The contract has three values: announce, withdraw, and
// everything else — silence included — holds.
//
// This package is the verdict alone: its inputs, the probe and the
// automaton. It has no configuration key, endpoint, command or metric of its
// own; E7.2 wires it into node.Run, serves it and gives it a command line.
//
// THE RULE. A shared address is only as safe as the worst mistake of whatever
// withdraws it, and a signal that can go wrong on every node at once withdraws
// the whole address. So an input may withdraw an address only if its "no"
// means this box certainly will not complete TCP+TLS on that address. What can
// say "no" on every node at once while they serve — what Kapkan computes, what
// the brain sends, what a client can provoke — may delay a join and never
// causes a withdrawal. Only an observation of this box's own kernel, or its
// operator's local command, takes an address out; what cannot be observed
// holds: unknown is never a withdrawal.
//
// THE CLOSED TRIGGER SET. Triggers has exactly four fields, a reflection test
// pins them with the rule above as its failure message, and the automaton's
// way out of service reads nothing else:
//
//   - Refused: the probe's connect returned ECONNREFUSED — that errno and no
//     other — and the kernel lists no LISTEN socket on :443 covering the
//     probed address (the address itself, or a wildcard) in /proc/net/tcp and
//     /proc/net/tcp6. The second half refines the E7 design, from E7.0's
//     review: a host firewall that REJECTs the probe on loopback :443 makes
//     connect() fail with the same errno as a port nobody listens on, and such
//     a rule, rolled out to every node, would withdraw the fleet while nginx
//     serves it. A listener behind the refusal makes it a firewall's, and a
//     table that cannot be read makes it unknown: neither is Refused.
//   - NotTLS: the first byte of the answer is neither 0x15 (a TLS alert) nor
//     0x16 (a handshake record): something that is not a TLS server holds
//     :443.
//   - Unbound: the kernel does not hold the address — no LOCAL route in
//     /proc/net/fib_trie covers it; /proc/net/if_inet6 does not list it, or
//     lists it tentative or dadfailed, and no local route in
//     /proc/net/ipv6_route covers it. An unbound address is not probed. A
//     /proc that cannot be read is unknown, not Unbound, and so is a reading
//     of fib_trie the kernel's own churn tore, or one the tick's deadline
//     cut short.
//   - Drained: a drain file is there — the operator's, state_dir/steering/drain
//     for the node or drain.<addr> for one address, or the new-node drain,
//     state_dir/steering/new_node (below). A drain file whose existence
//     cannot be established is no drain, and no lift either: it closes a join
//     gate.
//
// Refused, NotTLS and Unbound are hard samples. An address is withdrawn on
// FailAfter (3) hard samples among the last FailWindow (5) decisive ones
// taken within the last 2×FailWindow (10) ticks, so an nginx restart shorter
// than two ticks, or an address a network manager re-adds within one,
// withdraws nothing — however long the probe has since been soft, blind or
// refused by a firewall — while a crash-loop between restarts does. Drained
// takes effect at once and wins over everything else.
//
// WHAT ONLY GATES A JOIN. A live generation that passed `nginx -t` (read
// without the Applier's lock, through apply.ReadLive), a document with at
// least one zone, drain files that could be looked at, the node's first entry
// (the new-node drain), and an expired hold-down. Each may keep an address out;
// none takes one out. An announced address that loses a gate — the document
// emptied, a `nginx -t` in progress, a drain file that cannot be looked at —
// stays announced, with the gate named in Verdict.Warning.
//
// WHAT IS REPORT-ONLY. The terminator's pid — alive, gone or unknown — and
// whether it is frozen (state T, t or Z in /proc/<pid>/stat), the soft and
// blind probe classes, the probe's errors, and the access log's progress,
// which tells overload from silence. A pid is not a listener: workers keep
// serving after their master is killed. And a soft probe is what load looks
// like: a full accept queue drops the SYN, and tcp_abort_on_overflow resets a
// connection only after its handshake — neither refuses one. Withdrawing a
// loaded node hands its share of a flood to the rest, so none of these
// withdraws: a hung nginx that still listens stays in, flagged, and the
// operator's drain is its cure.
//
// THE PROBE, once a tick per target. Only an address the kernel holds is
// probed: from that address (the source is bound to it, an IPv6 one with
// IP_FREEBIND, which an AnyIP range needs; the packets never leave lo) to
// its :443, connect within 300 ms, a TLS ClientHello naming
// kapkan-steer.invalid, and the first byte of the answer within 600 ms. The
// node's implicit target — no VIPs configured — probes 127.0.0.1:443 and,
// unless the node renders no IPv6, [::1]:443. The reserved name matches no
// zone, so the attempt ends at the catch-all's TLS alert: no HTTP is sent
// (no decision, no origin, no access-log line), and the alert comes before a
// session exists, so nothing lands in the kapkan_ssl cache. Classes: ok (0x15
// or 0x16), refused, not_tls, soft (a timeout, silence, EOF or a reset before
// any byte) and blind (EMFILE, ENFILE, ENOBUFS, EADDRINUSE: the probe could
// not look).
//
// THE AUTOMATON, one per target. It starts unknown. It announces on an ok
// sample, once RecoverAfter (10) have come in a row with every gate open and
// the hold-down over — a soft sample breaks the run, and a blind or none tick
// neither extends it nor joins; it withdraws on the window above; it drains
// at once, without growing the hold-down. A withdrawal from announce is a
// flap: the hold-down starts at 10 s and doubles per flap up to 60 s
// (configurable up to 600 s), and its level resets after 600 s announced —
// time out of service forgives nothing. A verdict older than three intervals,
// or stamped more than one interval ahead of the reader's clock, reads
// unknown, so a stopped sampler holds and never withdraws.
//
// FIRST ENTRY (D7). A node without state_dir/steering/state.json is born
// drained with reason new_node: Birth writes state_dir/steering/new_node,
// beside any drain of the operator's and never over it, and a wiped state_dir
// arms it again at the next start. It lifts by itself (LiftNewNode, which
// removes new_node and nothing else) once the live document has at least one
// zone, every zone has a :443 server in the live render, and one handshake
// with each zone's name has shown a leaf certificate that names it — the name
// only, no chain, no dates. Certificates are read nowhere else: not to
// withdraw (a VIP withdrawn everywhere passes no HTTP-01 validation, so
// renewal would deadlock), and not to rejoin. The first node of a new VIP
// joins by hand (E7.2: `-s undrain -force`).
//
// PERSISTENCE. state_dir/steering holds state.json — each target's
// hold-down, written by the daemon alone — the operator's drain files,
// written by the operator's commands, and new_node; every write is atomic. A
// target's key is the name its drain file is written under — for a VIP,
// VIPTarget's: the canonical text, unmapped, without a zone — and the Store
// takes no other key, so no key names a second file for one address, or a
// path outside the directory. Loading caps every hold-down's end at now+max,
// so a clock jump or a hand-edited file cannot keep a node out past the
// configured ceiling.
//
// THE CONTRACT — the invariants every change here is reviewed against:
//
//   - I1. Kapkan builds no route: no internal/edge package imports gobgp or
//     internal/mitigate directly, and kapkan-edge.service grants no
//     AF_NETLINK. This package reads /proc files and lists the interfaces'
//     IPv4 addresses with an ioctl on an AF_INET socket (SIOCGIFCONF); it
//     opens no netlink socket.
//   - I2. withdraw is reachable only from Triggers: the types say so, and a
//     test reads every file of the package to keep the automaton's one way
//     out of service the only one.
//   - I3. Unknown means hold, and steer never ends node.Run: every failure
//     here is a value — an error, TriUnknown, ClassBlind — that holds, and
//     nothing panics on what /proc, the disk or a socket hands it.
//   - I4. steer is a leaf: its transitive imports are the standard library
//     and internal/edge/apply.
//   - I5. The brain has no write path: no edgedoc field, API route or lever
//     reaches this package. The node hands it data — the live document's
//     zones, the render's :443 zones — never a verdict.
//   - I6. Watch first: steering is off until edge.yaml turns it on (E7.2),
//     and the shipped consumer starts with DRY=1 (E7.3).
//
// WIRING (E7.2). Per target and per tick: Prober.Observe through one
// Proc.Tick (which reads only what the asked addresses need, the TCP table
// only after a refusal, and stops reading when the tick's ctx ends — on a
// box carrying a full table, one reading of fib_trie can outlast many
// ticks), Store.DrainFor for the drain, ReadGenerationLive
// for the gate; Observation.Triggers folds the first two into Inputs — the
// drain's TriYes is Triggers.Drained, and anything but TriUnknown is
// Gates.DrainKnown; Automaton.Step returns the verdict, and Store.Save keeps
// what Automaton.Saved returns. A reader takes Verdict.AsOf, with the
// sampler's clock and its own both read through time.Now. Without the
// daemon, `kapkan edge -steer` runs the same inputs through
// Automaton.Evaluate.
package steer
