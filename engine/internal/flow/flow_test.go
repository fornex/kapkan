package flow

import "testing"

// TestProtoString asserts every defined Proto value, plus an out-of-range
// value, maps to its exact metrics/log label. These strings are part of the
// metrics contract, so the exact spelling matters.
func TestProtoString(t *testing.T) {
	tests := []struct {
		name string
		p    Proto
		want string
	}{
		{"unknown", ProtoUnknown, "unknown"},
		{"sflow5", ProtoSFlow5, "sflow5"},
		{"netflow5", ProtoNetFlow5, "netflow5"},
		{"netflow9", ProtoNetFlow9, "netflow9"},
		{"ipfix", ProtoIPFIX, "ipfix"},
		{"out-of-range", Proto(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("Proto(%d).String() = %q, want %q", tt.p, got, tt.want)
			}
		})
	}
}

// TestProtoStringNoUnknownDrift guards against enum/stringer drift: every
// known protocol (the contiguous range ProtoSFlow5..ProtoIPFIX, i.e. all
// consts except ProtoUnknown) must return a non-"unknown" label. Adding a new
// Proto const to that range without a corresponding String() case makes this
// test fail rather than letting metrics silently emit "unknown".
func TestProtoStringNoUnknownDrift(t *testing.T) {
	for p := ProtoSFlow5; p <= ProtoIPFIX; p++ {
		if got := p.String(); got == "unknown" {
			t.Errorf("Proto(%d).String() = %q; known protocol must not map to %q (missing String() case?)", p, got, "unknown")
		}
	}
}
