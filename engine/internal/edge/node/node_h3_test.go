package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/edge/apply"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// The renderer (E5.2) keys on the state alone, so the four states must be
// told apart exactly: the node's switch outranks everything, a failed probe
// is unknown, not a guess.
func TestH3State(t *testing.T) {
	with := apply.Terminator{Kind: "nginx", Version: "1.30.4", Core: "1.30.4", HTTP3Module: true}
	without := apply.Terminator{Kind: "nginx", Version: "1.22.1", Core: "1.22.1"}
	cases := []struct {
		name        string
		term        apply.Terminator
		probed, off bool
		want        string
	}{
		{"module, auto", with, true, false, api.H3StateReady},
		{"no module", without, true, false, api.H3StateNoModule},
		{"module, node off", with, true, true, api.H3StateNodeOff},
		{"no module, node off", without, true, true, api.H3StateNodeOff},
		{"probe failed", apply.Terminator{}, false, false, api.H3StateUnknown},
		{"probe failed, node off", apply.Terminator{}, false, true, api.H3StateNodeOff},
	}
	for _, c := range cases {
		if got := H3State(c.term, c.probed, c.off); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// The report, /healthz and the gauge carry the same readiness, and the
// advisory travels as a fact about the build — the node says what it sees.
func TestReportAndHealthzCarryH3Readiness(t *testing.T) {
	debian13 := apply.Terminator{Kind: "nginx", Version: "1.26.3", Core: "1.26.3", HTTP3Module: true, TLSLibrary: "OpenSSL 3.5.7"}
	nginx122 := apply.Terminator{Kind: "nginx", Version: "1.22.1", Core: "1.22.1", TLSLibrary: "OpenSSL 1.1.1n"}
	angie := apply.Terminator{Kind: "angie", Version: "1.12.1", Core: "1.31.2", HTTP3Module: true, TLSLibrary: "OpenSSL 3.5.7", EarlyDataCapable: true}
	cases := []struct {
		name     string
		term     apply.Terminator
		probeErr error
		off      bool
		want     api.EdgeReportH3
		advisory string // substring, "" = none
		gauge    float64
	}{
		{"Debian 13: module, advisory, no 0-RTT", debian13, nil, false,
			api.EdgeReportH3{State: api.H3StateReady, Module: true, TLSLibrary: "OpenSSL 3.5.7"}, "CVE-2026-40460", 1},
		{"nginx 1.22: no module", nginx122, nil, false,
			api.EdgeReportH3{State: api.H3StateNoModule, TLSLibrary: "OpenSSL 1.1.1n"}, "", 0},
		{"Angie: ready, capable, no advisory", angie, nil, false,
			api.EdgeReportH3{State: api.H3StateReady, Module: true, TLSLibrary: "OpenSSL 3.5.7", EarlyDataCapable: true}, "", 1},
		{"node switched off keeps the build's facts", debian13, nil, true,
			api.EdgeReportH3{State: api.H3StateNodeOff, Module: true, TLSLibrary: "OpenSSL 3.5.7"}, "CVE-2026-40460", 0},
		// The prober answers with facts AND an error, the way a half-parsed
		// output would: the node must keep none of them. Expecting zeroes
		// from a zero answer would prove nothing about the discard.
		{"probe failed: unknown, and a partial answer is discarded", debian13, errors.New("nginx -V: exit status 1"), false,
			api.EdgeReportH3{State: api.H3StateUnknown}, "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			brain := &fakeBrain{}
			brain.set(testDoc(10), `"v1"`)
			srv := httptest.NewServer(brain)
			defer srv.Close()
			state, sockets := shortDirs(t)
			opt := baseOptions(srv, state, sockets, &fakeTester{}, &fakeReloader{})
			opt.Prober = func(context.Context, string) (apply.Terminator, error) { return c.term, c.probeErr }
			opt.QUIC.H3Off = c.off
			n, err := New(opt)
			if err != nil {
				t.Fatal(err)
			}
			stop := run(t, n)
			defer func() {
				if err := stop(); err != nil {
					t.Errorf("Run: %v", err)
				}
			}()

			waitFor(t, "a report", func() bool {
				rep, ok := brain.lastReport()
				return ok && rep.Terminator != nil && rep.Terminator.H3 != nil
			})
			rep, _ := brain.lastReport()
			checkH3(t, "report", rep.Terminator.H3, c.want, c.advisory)
			if c.probeErr == nil && (rep.Terminator.Kind != c.term.Kind || rep.Terminator.Version != c.term.Version) {
				t.Errorf("report names %s %s, want %s %s", rep.Terminator.Kind, rep.Terminator.Version, c.term.Kind, c.term.Version)
			}
			if c.probeErr != nil && (rep.Terminator.Kind != "" || rep.Terminator.Version != "") {
				t.Errorf("a failed probe still named a terminator: %s %s", rep.Terminator.Kind, rep.Terminator.Version)
			}

			resp, err := http.Get("http://" + statusAddr(t, n) + "/healthz")
			if err != nil {
				t.Fatal(err)
			}
			var st Status
			if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			checkH3(t, "/healthz", st.H3, c.want, c.advisory)

			if got := testutil.ToFloat64(metrics.EdgeH3Ready); got != c.gauge {
				t.Errorf("kapkan_edge_h3_ready = %v, want %v", got, c.gauge)
			}
		})
	}
}

func checkH3(t *testing.T, where string, got *api.EdgeReportH3, want api.EdgeReportH3, advisory string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: no h3 section", where)
	}
	// The whole object, so a field added to it later cannot go unchecked;
	// the advisory is long and is matched as a substring below.
	bare := *got
	bare.Advisory = ""
	if bare != want {
		t.Errorf("%s: h3 = %+v, want %+v (advisory aside)", where, bare, want)
	}
	switch {
	case advisory == "" && got.Advisory != "":
		t.Errorf("%s: unexpected advisory %q", where, got.Advisory)
	case advisory != "" && !strings.Contains(got.Advisory, advisory):
		t.Errorf("%s: advisory %q lacks %q", where, got.Advisory, advisory)
	}
}
