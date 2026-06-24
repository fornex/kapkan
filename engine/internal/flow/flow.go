// Package flow defines the normalized flow record shared between the
// ingestion layer and the detection engine. It is the contract of the hot
// path: every decoded sFlow/NetFlow/IPFIX sample is converted into a Flow
// before it reaches the engine, so this struct must stay small, comparable
// where possible, and free of heap-allocated fields.
package flow

import "net/netip"

// Proto identifies the wire protocol a flow was received over.
type Proto uint8

// Wire protocols recognized by the ingestion layer.
const (
	ProtoUnknown Proto = iota
	ProtoSFlow5
	ProtoNetFlow5
	ProtoNetFlow9
	ProtoIPFIX
)

// String returns the human-readable protocol name used in logs and metrics.
func (p Proto) String() string {
	switch p {
	case ProtoSFlow5:
		return "sflow5"
	case ProtoNetFlow5:
		return "netflow5"
	case ProtoNetFlow9:
		return "netflow9"
	case ProtoIPFIX:
		return "ipfix"
	default:
		return "unknown"
	}
}

// Flow is one normalized flow record. Rates derived from Bytes/Packets must
// be multiplied by SamplingRate before threshold comparison.
type Flow struct {
	// SrcAddr and DstAddr are the sampled packet's endpoints.
	SrcAddr netip.Addr
	DstAddr netip.Addr
	// Exporter is the address of the router that exported this flow.
	Exporter netip.Addr
	// Bytes and Packets are raw (pre-sampling-correction) counters.
	Bytes   uint64
	Packets uint64
	// SamplingRate is the exporter's 1-in-N rate. The ingestion layer
	// guarantees it is >= 1, substituting the configured default when the
	// exporter does not report one.
	SamplingRate uint64
	// InIf and OutIf are the input/output interface indices (ifIndex) the
	// exporter reported for this flow. 0 means unknown/unset. They let the
	// engine deduplicate flows seen at multiple sampling vantage points via
	// interface-boundary counting (see config.Sampling.Boundary).
	InIf    uint32
	OutIf   uint32
	SrcPort uint16
	DstPort uint16
	// IPProto is the IP protocol number (6 TCP, 17 UDP, ...).
	IPProto  uint8
	TCPFlags uint8
	// Fragment marks non-first IP fragments (fragment offset > 0). First
	// fragments are not detectable from flow telemetry alone, so fragment
	// counters undercount by one packet per fragmented datagram.
	Fragment bool
	// Wire is the telemetry protocol this record arrived over.
	Wire Proto
}
