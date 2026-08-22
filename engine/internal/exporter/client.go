package exporter

// The API half: one POST, shaped exactly as https://kapkan.io/docs/api documents the
// source-block channel. The exporter is an ordinary API caller on purpose —
// every guarantee (TTL bounds, tenant scope, dry-run, the refusals) is
// enforced and audited brain-side, and nothing here could bypass them.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(base, token string) *client {
	return &client{
		base:  strings.TrimRight(base, "/"),
		token: token,
		// Short and absolute: a hung brain must not stall the decision loop —
		// the next window re-decides anyway.
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

type blockRequest struct {
	Victim     string `json:"victim"`
	Source     string `json:"source"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Reason     string `json:"reason"`
}

func (c *client) blockSource(ctx context.Context, victim, source netip.Addr, ttl time.Duration, reason string) error {
	body, err := json.Marshal(blockRequest{
		Victim:     victim.String(),
		Source:     source.String(),
		TTLSeconds: int64(ttl / time.Second),
		Reason:     reason,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/api/v1/dataplane/sources", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	// The refusal body is the brain's judgement in one line ({"error": ...});
	// surface it verbatim — it already names the allowlist entry, the tenant
	// boundary, or whichever guarantee said no.
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
}
