package render_test

// The steering arms of TestRealTerminator (edge-spec §8, E7.1). A node that
// steers probes each steered address once a second (internal/edge/steer): a
// TLS ClientHello naming kapkan-steer.invalid to the address's :443, and one
// read for the first byte of the answer. What it sees may take the address
// out of service, so it must not depend on anything the zones behind the
// listener are doing, and at one probe a second it must leave no trace. These
// arms run that probe — the production Prober, its timeouts included —
// against the :443 a node renders, on the terminator it targets:
//
//   - serve/steer/catch-all: decide failure_mode closed and no decision
//     service, so every request to the zone is a 503.
//   - serve/steer/dead-origin: decide failure_mode open, no decision service
//     and nothing listening at the origin, so every request is a 502.
//   - serve/steer/challenge-manual (Linux only: the decision service needs its
//     unix socket): the real decision service and clearance page with the
//     zone's rung on manual, so every request is the challenge page's 403.
//
// Each is a condition the v1.8 guide's `curl -sf --resolve zone:443:…` took
// for "withdraw" on every node at once (E7.0). In each, twenty probes are ok
// by the catch-all's alert (first byte 0x15); then the arm's control request
// fails just as that curl saw it, so the ok beside it is not vacuous. And the
// probes leave nothing behind:
//
//   - the error log gains nothing at nginx's default level (error) or above:
//     the catch-all logs its rejection at info, below even the harness's
//     notice;
//   - the access log gains no line. The arm keeps the http-level access log —
//     the catch-all's, as it has none of its own — in a file. The same probe
//     sent to the plain-HTTP :80 is answered "HTTP/1.1 400", which is class
//     not_tls (the trigger is real), and that 400 lands in the file: the file
//     is known to be written, and it holds that line alone. On Linux the
//     zones' own log, the rollups' socket, is read as well: its only record
//     is the control request's.
//
// Docker's userland proxy accepts a connection before the container listens,
// so a probe through it means something only once waitReady has seen the
// terminator serve, and a refusal can never be asserted here: the probe's own
// tests, against loopback listeners, own refused.

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kapkan-io/kapkan/internal/edge/clearance"
	"github.com/kapkan-io/kapkan/internal/edge/clearance/page"
	"github.com/kapkan-io/kapkan/internal/edge/decide"
	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
	"github.com/kapkan-io/kapkan/internal/edge/render"
	"github.com/kapkan-io/kapkan/internal/edge/rollup"
	"github.com/kapkan-io/kapkan/internal/edge/steer"
)

const (
	// steerProbeCount is twenty seconds of a node's steady state, back to
	// back.
	steerProbeCount = 20
	// steerDeadOrigin is an address nothing listens on inside the
	// terminator's container (the discard port).
	steerDeadOrigin = "127.0.0.1:9"
	// steerControlPath is the control request's path, the one record the
	// zones' access log may hold.
	steerControlPath = "/kapkan-steer-control"
)

func (h *harness) steerArms(t *testing.T) {
	t.Run("serve/steer/catch-all", func(t *testing.T) {
		s := h.serveWith(t, "decide-closed", "steer-catch-all", serveOptions{accessLog: true})
		s.steerCheck(t, "closed.example.net", 503, "")
	})
	t.Run("serve/steer/dead-origin", func(t *testing.T) {
		s := h.serveWith(t, "decide-open", "steer-dead-origin", serveOptions{accessLog: true, mutate: func(in *render.Inputs) {
			for i := range in.Doc.Zones {
				in.Doc.Zones[i].Origins = []string{steerDeadOrigin}
			}
		}})
		s.steerCheck(t, "example.com", 502, "")
	})
	t.Run("serve/steer/challenge-manual", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("needs the decision service on its unix socket, which does not cross a Docker Desktop bind mount")
		}
		// The rung on manual and enforcing: a request without a clearance is
		// challenged, whoever sends it. The render does not change with the
		// rung (render.go: rendered for every decide zone); the decision
		// service is what challenges, so it is given the same document.
		manual := func(in *render.Inputs) {
			for i := range in.Doc.Zones {
				in.Doc.Zones[i].Policy.Challenge = edgedoc.ChallengeManual
				in.Doc.Zones[i].Policy.ChallengeOptions = &edgedoc.ChallengeOptions{DryRun: false, Difficulty: clearance.MinDifficulty}
			}
		}
		s := h.serveWith(t, "decide-open", "steer-challenge-manual", serveOptions{accessLog: true, mutate: manual})
		fx := loadFixture(t, "decide-open")
		manual(&fx)
		svc := decide.New(decide.Options{Now: time.Now})
		svc.SetZones(fx.Doc)
		h.startReal(t, (&decide.Server{Service: svc, Path: filepath.Join(h.work, "run", "decide.sock"), Mode: 0o666}).ListenAndServe, "decide.sock")
		h.startReal(t, (&page.Server{Zones: svc, Path: filepath.Join(h.work, "run", "clearance.sock"), Mode: 0o666}).ListenAndServe, "clearance.sock")
		s.steerCheck(t, "example.com", 403, `id="kapkan-puzzle"`)
	})
}

// steerCheck is a steering arm once its terminator serves: the probes and
// their footprint, then the control request to zone, which must fail with
// status (and a body containing body) as the v1.8 guide's curl saw it.
func (s *served) steerCheck(t *testing.T, zone string, status int, body string) {
	t.Helper()
	var sink *logSink
	if runtime.GOOS == "linux" {
		// The zones' access log, as the node's rollups receive it.
		sink = s.h.startLogSink(t)
	}
	before := s.steerSettledLogs(t)

	bad, first := 0, steer.Result{}
	for range steerProbeCount {
		r := steerProbe(t, s.port443)
		if r.Class != steer.ClassOK || !r.HasFirst || r.First != 0x15 {
			if bad == 0 {
				first = r
			}
			bad++
		}
	}
	if bad > 0 {
		t.Errorf("%d of %d probes of the rendered :443 (%s) were not ok by the catch-all's alert; the first: class %v, first byte %#02x (one arrived: %v), err %v",
			bad, steerProbeCount, s.port443, first.Class, first.First, first.HasFirst, first.Err)
	}

	// The same probe at the plain-HTTP :80, where nginx reads the ClientHello
	// as a request line and answers 400: a first byte that is not TLS, and a
	// line in the catch-all's access log — the file the :443 probes must have
	// left empty.
	if r := steerProbe(t, s.port80); r.Class != steer.ClassNotTLS || r.First != 'H' {
		t.Errorf("probe of the plain-HTTP :80 (%s): class %v, first byte %q, err %v; want not_tls by the 'H' of nginx's HTTP/1.1 400",
			s.port80, r.Class, r.First, r.Err)
	}
	if lines := s.steerAccessLog(t); len(lines) != 1 {
		t.Errorf("the catch-all's access log holds %d lines, want the :80 probe's 400 alone — the :443 probes reached HTTP:\n%s",
			len(lines), strings.Join(lines, "\n"))
	}
	// A line in flight from before the probes would be blamed on them; a
	// "while logging to syslog" line here would be a zone's access log
	// written, which the probes cannot reach either.
	was, now := steerLines(before), steerLines(s.steerSettledLogs(t))
	added := now[min(len(was), len(now)):]
	if loud := steerAtErrorLevel(added); len(loud) > 0 {
		t.Errorf("the probes left lines at nginx's default error_log level (error) or above:\n%s", strings.Join(loud, "\n"))
	} else if len(added) > 0 {
		t.Logf("the terminator logged, below the default level, while probed:\n%s", strings.Join(added, "\n"))
	}

	s.request(t, "GET", true, zone, steerControlPath, "", nil).expect(t, status, body)
	if sink == nil {
		return
	}
	sink.wait(t, func(r rollup.Record) bool { return r.URI == steerControlPath })
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, r := range sink.recs {
		if r.URI != steerControlPath {
			t.Errorf("the zones' access log holds a record besides the control request's: %+v", r)
		}
	}
}

// steerProbe makes one steering probe at a published address: from its host,
// to its port.
func steerProbe(t *testing.T, hostPort string) steer.Result {
	t.Helper()
	ap, err := netip.ParseAddrPort(hostPort)
	if err != nil {
		t.Fatalf("published address %q: %v", hostPort, err)
	}
	// The Prober bounds itself (connect, first byte); this only bounds a
	// Prober that would not.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return steer.Prober{Port: ap.Port()}.Probe(ctx, ap.Addr())
}

// steerAccessLog waits for the :80 probe's 400 to reach the arm's http-level
// access log, then returns every line the file holds.
func (s *served) steerAccessLog(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(s.dir, "access.log")
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		lines := steerLines(string(raw))
		if slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, `" 400 `) }) {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("the :80 probe's 400 never reached %s (%v), so an empty file there would prove nothing; it holds:\n%s", path, err, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// steerSettledLogs is the terminator's log once it has stopped growing:
// docker logs trails the process, and a line still in flight would be counted
// at the wrong step.
func (s *served) steerSettledLogs(t *testing.T) string {
	t.Helper()
	logs := s.logs(t)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		time.Sleep(250 * time.Millisecond)
		next := s.logs(t)
		if next == logs {
			break
		}
		logs = next
	}
	return logs
}

// steerLines is text's non-empty lines.
func steerLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// steerAtErrorLevel is the lines logged at nginx's default error_log level,
// error, or above.
func steerAtErrorLevel(lines []string) []string {
	var out []string
	for _, line := range lines {
		for _, level := range []string{"[error]", "[crit]", "[alert]", "[emerg]"} {
			if strings.Contains(line, level) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}
