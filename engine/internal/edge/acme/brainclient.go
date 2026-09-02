package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// BrainClient is the node's side of the brain's issuance coordination
// (internal/api/edge_acme.go): it implements SlotClient and
// ChallengePublisher over the API with the node's agent token. Every call is
// bounded and every failure is an error the Manager treats as advisory.
type BrainClient struct {
	// BaseURL is the brain's API base, e.g. "https://brain.internal:8443".
	BaseURL string
	// Token is the agent bearer token; Node this node's configured name.
	Token string
	Node  string
	// HTTPClient may be nil (a 10 s client is used).
	HTTPClient *http.Client
}

func (b *BrainClient) client() *http.Client {
	if b.HTTPClient != nil {
		return b.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (b *BrainClient) post(ctx context.Context, path string, body any) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	u, err := url.JoinPath(b.BaseURL, "/api/v1/edge/nodes", url.PathEscape(b.Node), path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.Token)
	return b.client().Do(req)
}

type slotResponse struct {
	Granted           bool   `json:"granted"`
	Holder            string `json:"holder"`
	RetryAfterSeconds int    `json:"retry_after_seconds"`
}

// Acquire implements SlotClient.
func (b *BrainClient) Acquire(ctx context.Context, zone string) (bool, time.Duration, error) {
	resp, err := b.post(ctx, "acme/slot", map[string]any{"zone": zone})
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, 0, apiError(resp)
	}
	var sr slotResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&sr); err != nil {
		return false, 0, fmt.Errorf("slot response: %w", err)
	}
	return sr.Granted, time.Duration(sr.RetryAfterSeconds) * time.Second, nil
}

// Release implements SlotClient.
func (b *BrainClient) Release(ctx context.Context, zone string) error {
	resp, err := b.post(ctx, "acme/slot", map[string]any{"zone": zone, "release": true})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return apiError(resp)
	}
	return nil
}

// Publish implements ChallengePublisher.
func (b *BrainClient) Publish(ctx context.Context, zone, token, keyAuthorization string) error {
	resp, err := b.post(ctx, "acme/challenges", map[string]any{"zone": zone, "token": token, "key_authorization": keyAuthorization})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return apiError(resp)
	}
	return nil
}

func apiError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if len(body) == 0 {
		return errors.New(resp.Status)
	}
	return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(body))
}
