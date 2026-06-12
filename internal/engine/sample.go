package engine

import (
	"net/netip"
	"sort"
	"strconv"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
)

// topK is how many entries each aggregate in an attack sample keeps.
const topK = 5

// sampleEntry is one slot of a shard's recent-flows ring.
type sampleEntry struct {
	f     flow.Flow
	epoch int64
	dir   int8
}

// SampleFlow is one captured flow record in an attack sample. Bytes and
// Packets are raw (pre-sampling-correction), as exported by the router;
// SamplingRate is attached so consumers can correct them.
type SampleFlow struct {
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	SrcPort      uint16 `json:"src_port"`
	DstPort      uint16 `json:"dst_port"`
	Proto        string `json:"proto"`
	TCPFlags     uint8  `json:"tcp_flags,omitempty"`
	Fragment     bool   `json:"fragment,omitempty"`
	Bytes        uint64 `json:"bytes"`
	Packets      uint64 `json:"packets"`
	SamplingRate uint64 `json:"sampling_rate"`
}

// Counter is one aggregated key of an attack sample. Packets and Bytes are
// sampling-corrected totals over the flows seen in the buffer window.
type Counter struct {
	Key     string `json:"key"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// AttackSample summarizes the buffered flows behind a detection at the
// moment the threshold tripped: dominant sources, ports and protocols, plus
// up to flows_per_attack raw records. Host samples list raw flows newest
// first; group samples interleave per-member captures, so order carries no
// recency meaning there. For outgoing attacks the "sources" are the victims
// the host is attacking.
type AttackSample struct {
	Flows       []SampleFlow `json:"flows,omitempty"`
	TopSources  []Counter    `json:"top_sources,omitempty"`
	TopSrcPorts []Counter    `json:"top_src_ports,omitempty"`
	TopDstPorts []Counter    `json:"top_dst_ports,omitempty"`
	Protocols   []Counter    `json:"protocols,omitempty"`
}

// protoName renders an IP protocol number for samples.
func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return strconv.Itoa(int(p))
	}
}

// sampleAggregator accumulates matching flows into an AttackSample.
type sampleAggregator struct {
	maxFlows  int
	flows     []SampleFlow
	sources   map[string]*Counter
	srcPorts  map[string]*Counter
	dstPorts  map[string]*Counter
	protocols map[string]*Counter
}

func newSampleAggregator(maxFlows int) *sampleAggregator {
	return &sampleAggregator{
		maxFlows:  maxFlows,
		sources:   make(map[string]*Counter),
		srcPorts:  make(map[string]*Counter),
		dstPorts:  make(map[string]*Counter),
		protocols: make(map[string]*Counter),
	}
}

func bump(m map[string]*Counter, key string, packets, bytes uint64) {
	c := m[key]
	if c == nil {
		c = &Counter{Key: key}
		m[key] = c
	}
	c.Packets += packets
	c.Bytes += bytes
}

// add accumulates one matching flow into the aggregates and, when capture
// is set and the cap allows, into the raw flow list. dir tells which
// endpoint is the remote side: for incoming attacks the remote is the
// source, for outgoing attacks it is the destination.
func (a *sampleAggregator) add(f *flow.Flow, dir int8, capture bool) {
	rate := f.SamplingRate
	if rate == 0 {
		rate = 1
	}
	packets := f.Packets * rate
	bytes := f.Bytes * rate

	remote := f.SrcAddr
	if dir == dirOut {
		remote = f.DstAddr
	}
	bump(a.sources, remote.String(), packets, bytes)
	bump(a.srcPorts, strconv.Itoa(int(f.SrcPort)), packets, bytes)
	bump(a.dstPorts, strconv.Itoa(int(f.DstPort)), packets, bytes)
	bump(a.protocols, protoName(f.IPProto), packets, bytes)

	if capture && len(a.flows) < a.maxFlows {
		a.flows = append(a.flows, SampleFlow{
			Src:          f.SrcAddr.String(),
			Dst:          f.DstAddr.String(),
			SrcPort:      f.SrcPort,
			DstPort:      f.DstPort,
			Proto:        protoName(f.IPProto),
			TCPFlags:     f.TCPFlags,
			Fragment:     f.Fragment,
			Bytes:        f.Bytes,
			Packets:      f.Packets,
			SamplingRate: f.SamplingRate,
		})
	}
}

// top returns the k heaviest counters by packets, descending.
func top(m map[string]*Counter, k int) []Counter {
	out := make([]Counter, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Key < out[j].Key // deterministic order for ties
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// sample finalizes the aggregation. It returns nil when nothing matched.
func (a *sampleAggregator) sample() *AttackSample {
	if len(a.flows) == 0 && len(a.sources) == 0 {
		return nil
	}
	return &AttackSample{
		Flows:       a.flows,
		TopSources:  top(a.sources, topK),
		TopSrcPorts: top(a.srcPorts, topK),
		TopDstPorts: top(a.dstPorts, topK),
		Protocols:   top(a.protocols, topK),
	}
}

// scanRing walks one shard's ring newest-first, calling visit for every
// entry recorded at or after sinceEpoch. Callers hold the shard's lock.
//
// Entries are written in arrival order, so the backwards walk sees epochs
// in (almost) non-increasing order and can stop early instead of scanning
// the whole ring: at the first never-written slot (epoch 0 — zeros only
// exist past the oldest entry of a not-yet-wrapped ring), or once entries
// are a full second older than the window. The one-second slack covers
// epochs being read before the shard lock is taken in Process, which lets
// neighboring entries disagree by up to a second across a tick boundary.
func scanRing(sh *shard, sinceEpoch int64, visit func(*sampleEntry)) {
	if len(sh.ring) == 0 {
		return
	}
	for i := 0; i < len(sh.ring); i++ {
		idx := sh.pos - 1 - i
		if idx < 0 {
			idx += len(sh.ring)
		}
		e := &sh.ring[idx]
		if e.epoch == 0 || e.epoch < sinceEpoch-1 {
			return
		}
		if e.epoch < sinceEpoch {
			continue
		}
		visit(e)
	}
}

// collectHostSample builds the sample for a (host, direction) attack from
// the host's own shard ring. The caller already holds sh's lock — the ring
// containing the host's flows lives in the same shard as its counters.
func (e *Engine) collectHostSample(sh *shard, target netip.Addr, dir int, sinceEpoch int64) *AttackSample {
	if len(sh.ring) == 0 {
		return nil
	}
	agg := newSampleAggregator(e.sampleFlows)
	d := int8(dir)
	scanRing(sh, sinceEpoch, func(se *sampleEntry) {
		if se.dir != d {
			return
		}
		if dir == dirOut {
			if se.f.SrcAddr != target {
				return
			}
		} else if se.f.DstAddr != target {
			return
		}
		agg.add(&se.f, se.dir, true)
	})
	return agg.sample()
}

// collectGroupSample builds the sample for a (total group, direction)
// attack by scanning every shard's ring for flows whose monitored endpoint
// belongs to the group. Callers must NOT hold any shard lock.
//
// Group members spread across shards, so the raw-flow cap is allotted
// across shards by groupQuotas (counted in a first pass); otherwise the
// first scanned shard would exhaust the cap and the sample would show a
// single member host. Aggregates always cover every match.
//
// Shard locks are released between the two passes, so record() keeps
// overwriting ring slots in the gap and pass 2 may see a slightly
// different match set than was counted — quotas are best-effort, the
// global cap in add() is the hard bound. This staleness is accepted by
// design; do not "fix" it by holding all shard locks at once.
func (e *Engine) collectGroupSample(cfg *config.Config, gi int, dir int, sinceEpoch int64) *AttackSample {
	d := int8(dir)
	match := func(se *sampleEntry) bool {
		if se.dir != d {
			return false
		}
		monitored := se.f.DstAddr
		if dir == dirOut {
			monitored = se.f.SrcAddr
		}
		return cfg.GroupIndexFor(monitored) == gi
	}

	var counts [numShards]int
	total := 0
	for i, sh := range e.shards {
		sh.mu.Lock()
		scanRing(sh, sinceEpoch, func(se *sampleEntry) {
			if match(se) {
				counts[i]++
				total++
			}
		})
		sh.mu.Unlock()
	}
	if total == 0 {
		return nil
	}

	quotas := groupQuotas(counts[:], total, e.sampleFlows)

	agg := newSampleAggregator(e.sampleFlows)
	for i, sh := range e.shards {
		if counts[i] == 0 {
			continue
		}
		taken := 0
		sh.mu.Lock()
		scanRing(sh, sinceEpoch, func(se *sampleEntry) {
			if !match(se) {
				return
			}
			capture := taken < quotas[i]
			if capture {
				taken++
			}
			agg.add(&se.f, se.dir, capture)
		})
		sh.mu.Unlock()
	}
	return agg.sample()
}

// groupQuotas splits a raw-flow budget across shards proportionally to
// their match counts, deterministically, with sum(quotas) <= budget exactly.
// The budget's worth of heaviest shards are guaranteed one slot each first
// (so minority group members stay visible next to a dominant one), then the
// remainder is distributed by largest fractional share. Ties break toward
// the heavier shard, then the lower index.
func groupQuotas(counts []int, total, budget int) []int {
	type share struct{ idx, count int }
	shards := make([]share, 0, 64)
	for i, c := range counts {
		if c > 0 {
			shards = append(shards, share{i, c})
		}
	}
	sort.Slice(shards, func(a, b int) bool {
		if shards[a].count != shards[b].count {
			return shards[a].count > shards[b].count
		}
		return shards[a].idx < shards[b].idx
	})
	if len(shards) > budget {
		shards = shards[:budget] // can't represent more shards than slots
	}

	quotas := make([]int, len(counts))
	remaining := budget
	for _, s := range shards { // guaranteed representation
		quotas[s.idx] = 1
		remaining--
	}
	for remaining > 0 { // largest-remainder rounds, heaviest first
		granted := 0
		for _, s := range shards {
			if remaining == 0 {
				break
			}
			extra := budget*s.count/total - quotas[s.idx]
			if extra <= 0 {
				continue
			}
			quotas[s.idx]++
			remaining--
			granted++
		}
		if granted == 0 {
			// Proportional shares exhausted (rounding leftovers): hand the
			// rest out one by one, heaviest shard first.
			for _, s := range shards {
				if remaining == 0 {
					break
				}
				if quotas[s.idx] < s.count {
					quotas[s.idx]++
					remaining--
					granted++
				}
			}
			if granted == 0 {
				break // budget exceeds total matches; nothing left to take
			}
		}
	}
	return quotas
}
