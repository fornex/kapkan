package config

import (
	"strings"
	"testing"

	"github.com/kapkan-io/kapkan/internal/edge/edgedoc"
)

func TestEdgeNodeDefaultsAreTheRolesOwnDirectories(t *testing.T) {
	ec, err := ParseEdgeNode([]byte(edgeEABBase))
	if err != nil {
		t.Fatal(err)
	}
	if ec.StateDir != "/var/lib/kapkan-edge" || ec.SocketsDir != "/run/kapkan-edge" {
		t.Fatalf("defaults %s %s must not be the brain's /var/lib/kapkan and /run/kapkan", ec.StateDir, ec.SocketsDir)
	}
}

func TestEdgeNodeRefusesCredentialsInTheControllerURL(t *testing.T) {
	_, err := ParseEdgeNode([]byte("controller:\n  url: https://admin:s3cret@brain.example:8443\n  token_env: KAPKAN_EDGE_TOKEN\n  name: edge-1\n"))
	if err == nil || !strings.Contains(err.Error(), "must not carry credentials") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("userinfo: %v", err)
	}
	// The scrub role's copy of the check agrees.
	_, err = ParseScrub([]byte("controller:\n  url: https://admin:s3cret@brain.example:8443\n  token_env: KAPKAN_SCRUB_TOKEN\n  name: scrub-1\ndataplane:\n  interfaces: [eth0]\n"))
	if err == nil || !strings.Contains(err.Error(), "must not carry credentials") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("scrub userinfo: %v", err)
	}
}

func TestEdgeNodeFallbackMustDifferFromTheResolvedPrimary(t *testing.T) {
	// An empty directory means Let's Encrypt production; naming it as the
	// fallback would alternate between two identical CAs.
	_, err := ParseEdgeNode([]byte(edgeEABBase + "acme:\n  fallback: " + edgedoc.DefaultACMEDirectory + "\n"))
	if err == nil || !strings.Contains(err.Error(), "acme.fallback must name a different directory") {
		t.Fatalf("fallback == default primary: %v", err)
	}
	if _, err := ParseEdgeNode([]byte(edgeEABBase + "acme:\n  directory: https://acme-staging-v02.api.letsencrypt.org/directory\n  fallback: " + edgedoc.DefaultACMEDirectory + "\n")); err != nil {
		t.Fatalf("a fallback different from an explicit primary refused: %v", err)
	}
}
