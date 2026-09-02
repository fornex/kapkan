package decide

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkDecide is the in-process cost of one decision: the table lookups
// and the bucket update under the service mutex. This is the floor of the
// auth_request tax; the socket round trip below is the number edge-spec §5
// asks for ("tens of µs local"). Run with `make bench`.
func BenchmarkDecide(b *testing.B) {
	s := New(Options{})
	s.SetZones(doc(zone("example.com", 1_000_000_000, 1_000_000)))
	sources := make([]netip.Addr, 4096)
	for i := range sources {
		sources[i] = netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			s.Decide("example.com", sources[i&4095])
			i++
		}
	})
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "decisions/sec")
}

// BenchmarkDecideOverUnixSocket is the client-observed round trip of GET
// /decide over the unix socket with keep-alive, as nginx's auth_request makes
// it — the added latency a protected zone pays per request, measured, not
// assumed (edge-spec §5, §8). Target: tens of microseconds on a local socket.
func BenchmarkDecideOverUnixSocket(b *testing.B) {
	quiet := slog.New(slog.DiscardHandler)
	s := New(Options{Logger: quiet})
	s.SetZones(doc(zone("example.com", 1_000_000_000, 1_000_000)))
	path := filepath.Join(b.TempDir(), "d.sock")
	srv := &Server{Service: s, Path: path, Logger: quiet}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
		MaxIdleConnsPerHost: 256,
	}
	client := &http.Client{Transport: tr}
	newReq := func(i int) *http.Request {
		req, _ := http.NewRequest("GET", "http://decide/decide", nil)
		req.Header.Set(headerZone, "example.com")
		req.Header.Set(headerClient, netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String())
		req.Header.Set("X-Kapkan-Method", "GET")
		req.Header.Set("X-Kapkan-URI", "/")
		return req
	}
	// Wait for the socket.
	for i := 0; i < 100; i++ {
		if resp, err := client.Do(newReq(0)); err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			resp, err := client.Do(newReq(i))
			if err != nil {
				b.Fatal(err)
			}
			_ = resp.Body.Close()
			i++
		}
	})
	b.ReportMetric(float64(b.Elapsed().Microseconds())/float64(b.N), "µs/decision")
}
