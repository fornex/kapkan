package config

import (
	"strings"
	"testing"
)

const edgeEABBase = "controller:\n  url: https://brain.example:8443\n  token_env: KAPKAN_EDGE_TOKEN\n  name: edge-1\n"

func TestEdgeNodeEABValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"valid", edgeEABBase + "acme:\n  eab:\n    - directory: https://acme.zerossl.com/v2/DV90\n      kid: abc\n      hmac_key_env: ZEROSSL_HMAC\n", ""},
		{"bad directory", edgeEABBase + "acme:\n  eab:\n    - directory: zerossl\n      kid: abc\n      hmac_key_env: ZEROSSL_HMAC\n", "acme.eab[0].directory"},
		{"missing kid", edgeEABBase + "acme:\n  eab:\n    - directory: https://acme.zerossl.com/v2/DV90\n      hmac_key_env: ZEROSSL_HMAC\n", "acme.eab[0].kid"},
		{"bad env name", edgeEABBase + "acme:\n  eab:\n    - directory: https://acme.zerossl.com/v2/DV90\n      kid: abc\n      hmac_key_env: 'not valid'\n", "hmac_key_env"},
		{"inline key refused", edgeEABBase + "acme:\n  eab:\n    - directory: https://acme.zerossl.com/v2/DV90\n      kid: abc\n      hmac_key: secret\n", "hmac_key"},
		{"duplicate directory", edgeEABBase + "acme:\n  eab:\n    - directory: https://acme.zerossl.com/v2/DV90\n      kid: a\n      hmac_key_env: A\n    - directory: https://acme.zerossl.com/v2/DV90\n      kid: b\n      hmac_key_env: B\n", "listed twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseEdgeNode([]byte(c.yaml))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %v, want it to mention %q", err, c.wantErr)
			}
		})
	}
}

func TestEdgeNodeResolveEAB(t *testing.T) {
	ec, err := ParseEdgeNode([]byte(edgeEABBase + "acme:\n  eab:\n    - directory: https://acme.zerossl.com/v2/DV90\n      kid: abc\n      hmac_key_env: TEST_EAB_HMAC\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Unset: a hard error, not a silent registration without the binding.
	t.Setenv("TEST_EAB_HMAC", "")
	if _, err := ec.ACME.ResolveEAB(); err == nil || !strings.Contains(err.Error(), "TEST_EAB_HMAC") {
		t.Fatalf("unset env: %v", err)
	}
	t.Setenv("TEST_EAB_HMAC", " c2VjcmV0 \n")
	got, err := ec.ACME.ResolveEAB()
	if err != nil {
		t.Fatal(err)
	}
	if c := got["https://acme.zerossl.com/v2/DV90"]; c.KID != "abc" || c.HMACKey != "c2VjcmV0" {
		t.Fatalf("resolved %+v", got)
	}
	// No bindings: nil, no error.
	plain, err := ParseEdgeNode([]byte(edgeEABBase))
	if err != nil {
		t.Fatal(err)
	}
	if m, err := plain.ACME.ResolveEAB(); err != nil || m != nil {
		t.Fatalf("no bindings: %v %v", m, err)
	}
}
