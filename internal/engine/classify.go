package engine

import "strconv"

// AttackType is the inferred attack vector.
type AttackType string

// Attack vectors recognized by the classifier.
const (
	AttackNTPAmplification       AttackType = "ntp_amplification"
	AttackDNSAmplification       AttackType = "dns_amplification"
	AttackCLDAPAmplification     AttackType = "cldap_amplification"
	AttackMemcachedAmplification AttackType = "memcached_amplification"
	AttackSSDPAmplification      AttackType = "ssdp_amplification"
	AttackChargenAmplification   AttackType = "chargen_amplification"
	AttackSYNFlood               AttackType = "syn_flood"
	AttackFragmentFlood          AttackType = "fragment_flood"
	AttackICMPFlood              AttackType = "icmp_flood"
	AttackUDPFlood               AttackType = "udp_flood"
	AttackTCPFlood               AttackType = "tcp_flood"
	// AttackMixed means no single vector dominates the traffic.
	AttackMixed AttackType = "mixed"
)

// AttackTypes lists every classification the engine can produce. Used by
// consumers that need the complete set (schema checks, future UI/API).
func AttackTypes() []AttackType {
	return []AttackType{
		AttackNTPAmplification, AttackDNSAmplification, AttackCLDAPAmplification,
		AttackMemcachedAmplification, AttackSSDPAmplification, AttackChargenAmplification,
		AttackSYNFlood, AttackFragmentFlood, AttackICMPFlood,
		AttackUDPFlood, AttackTCPFlood, AttackMixed,
	}
}

// Classification describes the attack vector inferred at detection time
// from the windowed per-protocol rates and the flow sample.
type Classification struct {
	Type AttackType `json:"type"`
	// Confidence is the share (0..1) of the attack traffic matching the
	// winning signature. For mixed no signature matched at all and
	// Confidence is 0.
	Confidence float64 `json:"confidence"`
	// SrcPort is the reflected service port for amplification vectors.
	SrcPort uint16 `json:"src_port,omitempty"`
}

// Classifier thresholds.
const (
	// dominantShare is the traffic share a signature needs to win.
	dominantShare = 0.5
	// amplifiedMinBytes is the minimum sampling-corrected average packet
	// size for a source port to read as reflected/amplified responses;
	// request-sized packets from a service port classify as a plain flood.
	amplifiedMinBytes = 200
)

// amplificationPorts maps reflected UDP service source ports to vectors.
var amplificationPorts = map[uint16]AttackType{
	123:   AttackNTPAmplification,
	53:    AttackDNSAmplification,
	389:   AttackCLDAPAmplification,
	11211: AttackMemcachedAmplification,
	1900:  AttackSSDPAmplification,
	19:    AttackChargenAmplification,
}

// classify infers the attack vector. The rate breakdown (full window,
// sampling-corrected) decides protocol dominance; the sample contributes
// source-port and packet-size signatures for amplification. It works with
// a nil sample (sampling disabled) and returns nil only when there is no
// traffic to classify.
//
// Order matters: amplification is the most specific signature, then pure
// SYN, then fragments (fragmented floods are usually also UDP-dominant),
// then the per-protocol volumetric floods.
func classify(r Rates, s *AttackSample) *Classification {
	if r.PPS <= 0 {
		return nil
	}
	udpShare := r.UDPPPS / r.PPS
	synShare := r.TCPSYNPPS / r.PPS
	tcpShare := r.TCPPPS / r.PPS
	icmpShare := r.ICMPPPS / r.PPS
	fragShare := r.FragPPS / r.PPS

	if udpShare >= dominantShare {
		if typ, port, share := amplificationSignature(s); typ != "" {
			return &Classification{Type: typ, Confidence: share, SrcPort: port}
		}
	}
	if synShare >= dominantShare {
		return &Classification{Type: AttackSYNFlood, Confidence: synShare}
	}
	if fragShare >= dominantShare {
		return &Classification{Type: AttackFragmentFlood, Confidence: fragShare}
	}
	if icmpShare >= dominantShare {
		return &Classification{Type: AttackICMPFlood, Confidence: icmpShare}
	}
	if udpShare >= dominantShare {
		return &Classification{Type: AttackUDPFlood, Confidence: udpShare}
	}
	if tcpShare >= dominantShare {
		return &Classification{Type: AttackTCPFlood, Confidence: tcpShare}
	}
	return &Classification{Type: AttackMixed}
}

// amplificationSignature looks for a dominant reflected-service source port
// with response-sized packets in the sample. Returns "" when there is no
// sample or no port qualifies.
func amplificationSignature(s *AttackSample) (AttackType, uint16, float64) {
	if s == nil || len(s.TopSrcPorts) == 0 {
		return "", 0, 0
	}
	// Denominator: the sample's untruncated packet total. The top-K lists
	// (ports AND protocols) drop lighter keys and would inflate the head's
	// share.
	total := s.TotalPackets
	if total == 0 {
		return "", 0, 0
	}
	// TopSrcPorts is sorted heaviest-first; only the dominant port can
	// reach the share gate, so checking the head is sufficient.
	head := s.TopSrcPorts[0]
	port64, err := strconv.ParseUint(head.Key, 10, 16)
	if err != nil {
		return "", 0, 0
	}
	typ, ok := amplificationPorts[uint16(port64)]
	if !ok {
		return "", 0, 0
	}
	share := float64(head.Packets) / float64(total)
	if share < dominantShare {
		return "", 0, 0
	}
	if head.Packets == 0 || head.Bytes/head.Packets < amplifiedMinBytes {
		return "", 0, 0
	}
	return typ, uint16(port64), share
}

// clsType renders a classification for logs, tolerating nil.
func clsType(c *Classification) string {
	if c == nil {
		return "unclassified"
	}
	return string(c.Type)
}
