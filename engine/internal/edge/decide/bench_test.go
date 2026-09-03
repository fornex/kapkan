package decide

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// BenchmarkDecide is the in-process cost of one decision: the table lookups
// and the bucket update under the service mutex, from many goroutines. This
// is the floor of the auth_request tax and the node's decision throughput.
func BenchmarkDecide(b *testing.B) {
	s := New(Options{Logger: slog.New(slog.DiscardHandler)})
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

// BenchmarkDecideFullTableNewSource pins the cost of a decision from a NEW
// source while the bucket table is full — the case an address-rotating
// attacker manufactures. It must stay within a small multiple of the known-
// source cost; the on-full sweep is paced so it does.
func BenchmarkDecideFullTableNewSource(b *testing.B) {
	s := New(Options{Logger: slog.New(slog.DiscardHandler)})
	s.SetZones(doc(zone("example.com", 1_000_000_000, 0)))
	for i := 0; i < DefaultMaxSources; i++ {
		s.Decide("example.com", netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Decide("example.com", netip.AddrFrom4([4]byte{172, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
}

// BenchmarkDecideOverUnixSocket is the client-observed ROUND TRIP of GET
// /decide over the unix socket with keep-alive, from ONE client, as nginx's
// auth_request makes it — the added latency a protected zone pays per
// request, measured, not assumed (edge-spec §5, §8). ns/op is that latency;
// p50 and p99 are reported alongside. Target: tens of microseconds. (nginx's
// own subrequest handling adds to this; the terminator harness measures the
// whole thing on Linux.)
func BenchmarkDecideOverUnixSocket(b *testing.B) {
	client, newReq := socketBench(b)
	samples := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		resp, err := client.Do(newReq(i))
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	b.ReportMetric(float64(samples[len(samples)/2].Microseconds()), "p50-µs")
	b.ReportMetric(float64(samples[len(samples)*99/100].Microseconds()), "p99-µs")
}

// BenchmarkDecideOverUnixSocketParallel is the socket's THROUGHPUT with many
// concurrent clients (nginx keeps 64 connections); ns/op here is inverse
// throughput, not latency.
func BenchmarkDecideOverUnixSocketParallel(b *testing.B) {
	client, newReq := socketBench(b)
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
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "decisions/sec")
}

func socketBench(b *testing.B) (*http.Client, func(int) *http.Request) {
	quiet := slog.New(slog.DiscardHandler)
	s := New(Options{Logger: quiet})
	s.SetZones(doc(zone("example.com", 1_000_000_000, 1_000_000)))
	path := filepath.Join(b.TempDir(), "d.sock")
	srv := &Server{Service: s, Path: path, Logger: quiet}
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
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
	for i := 0; i < 100; i++ {
		if resp, err := client.Do(newReq(0)); err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return client, newReq
}
