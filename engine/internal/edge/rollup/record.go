// Package rollup consumes the terminator's access log — one JSON object per
// request, shipped by nginx's syslog transport over a unix datagram socket
// (edge-spec §2.1) — and turns it into per-zone, per-source windows: request
// rates, status mix, top sources (§2.3 "signals up"), and the local rules
// that promote a source which keeps flooding through its denials into a
// verdict for the decision service (§5 "local loop"). Nothing here talks to
// the brain: rollups are advisory and travel in the node's report; verdicts
// stay node-local (C6).
//
// The wire is what the renderer emits (internal/edge/render): a datagram
// `<PRI>Mmm dd hh:mm:ss kapkan: {json}` per request (nohostname, tag=kapkan),
// with the fields of log_format kapkan_edge. Parse looks for the JSON and
// ignores everything before it, so a hostname or a different tag would not
// break it. Datagrams are fire-and-forget: a slow reader drops them at the
// kernel's receive queue, which is acceptable for advisory rollups and is
// counted when detectable (a datagram larger than the buffer).
package rollup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// Record is one access-log line, decoded.
type Record struct {
	// TS is the request's completion time as the terminator saw it.
	TS   time.Time
	Zone string
	Src  netip.Addr
	// Port is the server port the request arrived on: 443 for decided
	// traffic, 80 for the redirect/ACME listener.
	Port   int
	Method string
	Host   string
	URI    string
	Status int
	Bytes  uint64
	// RT is the request time in seconds; URT the upstream response time as
	// nginx prints it ("-" or "" when no upstream was consulted).
	RT  float64
	URT string
	UA  string
	// Decision is the decision service's answer for this request: "200"
	// (allow), "403" (deny), a 5xx when the service could not be reached
	// (undecided, passed or refused by failure_mode), "" when the zone does
	// not decide or the request never reached the decision (e.g. :80).
	Decision string
}

// Decided reports whether the decision service answered this request (and so
// opened an in-flight slot the decider must be told to close).
func (r Record) Decided() bool {
	return r.Decision == "200" || r.Decision == "403"
}

// ErrNoJSON is returned for a datagram without a JSON object.
var ErrNoJSON = errors.New("no JSON object in datagram")

var zoneRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// wire mirrors log_format kapkan_edge. Numbers the format prints bare are
// numbers here; everything else is a string.
type wire struct {
	TS       string  `json:"ts"`
	Zone     string  `json:"zone"`
	Src      string  `json:"src"`
	Port     int     `json:"port"`
	Method   string  `json:"method"`
	Host     string  `json:"host"`
	URI      string  `json:"uri"`
	Status   int     `json:"status"`
	Bytes    uint64  `json:"bytes"`
	RT       float64 `json:"rt"`
	URT      string  `json:"urt"`
	UA       string  `json:"ua"`
	Decision string  `json:"decision"`
}

// Parse decodes one datagram. The syslog header (anything before the first
// '{') is skipped; trailing NUL/newline is tolerated.
func Parse(datagram []byte) (Record, error) {
	i := bytes.IndexByte(datagram, '{')
	if i < 0 {
		return Record{}, ErrNoJSON
	}
	body := bytes.TrimRight(datagram[i:], "\x00\r\n")
	var w wire
	if err := json.Unmarshal(body, &w); err != nil {
		return Record{}, fmt.Errorf("access-log record: %w", err)
	}
	if !zoneRe.MatchString(w.Zone) {
		return Record{}, fmt.Errorf("access-log record: zone %q is not a hostname", w.Zone)
	}
	src, err := netip.ParseAddr(w.Src)
	if err != nil {
		return Record{}, fmt.Errorf("access-log record: src: %w", err)
	}
	ts, err := time.Parse(time.RFC3339, w.TS)
	if err != nil {
		return Record{}, fmt.Errorf("access-log record: ts: %w", err)
	}
	if w.Status < 100 || w.Status > 999 {
		return Record{}, fmt.Errorf("access-log record: status %d", w.Status)
	}
	return Record{
		TS: ts, Zone: w.Zone, Src: src.Unmap(), Port: w.Port, Method: w.Method, Host: w.Host, URI: w.URI,
		Status: w.Status, Bytes: w.Bytes, RT: w.RT, URT: w.URT, UA: w.UA, Decision: w.Decision,
	}, nil
}
