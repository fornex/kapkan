package acme

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBrainClientSpeaksTheCoordinatorContract(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.EscapedPath()+" "+r.Header.Get("Authorization")+" "+string(body))
		switch {
		case strings.Contains(r.URL.Path, "/nodes/nobody/"):
			http.Error(w, `{"error":"unknown edge node"}`, http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/acme/slot") && strings.Contains(string(body), `"release":true`):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/acme/slot") && len(seen) == 1:
			_ = json.NewEncoder(w).Encode(map[string]any{"granted": false, "holder": "e2", "retry_after_seconds": 7})
		case strings.HasSuffix(r.URL.Path, "/acme/slot"):
			_ = json.NewEncoder(w).Encode(map[string]any{"granted": true, "expires_at": time.Now().Add(time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/acme/challenges"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unknown", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	b := &BrainClient{BaseURL: srv.URL, Token: "agent-secret", Node: "edge one"}
	ctx := context.Background()

	granted, retry, err := b.Acquire(ctx, "example.com")
	if err != nil || granted || retry != 7*time.Second {
		t.Fatalf("first acquire: %v %v %v", granted, retry, err)
	}
	granted, _, err = b.Acquire(ctx, "example.com")
	if err != nil || !granted {
		t.Fatalf("second acquire: %v %v", granted, err)
	}
	if err := b.Publish(ctx, "example.com", "tok", "tok.thumb"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := b.Release(ctx, "example.com"); err != nil {
		t.Fatalf("release: %v", err)
	}
	want := []string{
		`POST /api/v1/edge/nodes/edge%20one/acme/slot Bearer agent-secret {"zone":"example.com"}`,
		`POST /api/v1/edge/nodes/edge%20one/acme/slot Bearer agent-secret {"zone":"example.com"}`,
		`POST /api/v1/edge/nodes/edge%20one/acme/challenges Bearer agent-secret {"key_authorization":"tok.thumb","token":"tok","zone":"example.com"}`,
		`POST /api/v1/edge/nodes/edge%20one/acme/slot Bearer agent-secret {"release":true,"zone":"example.com"}`,
	}
	for i := range want {
		if i >= len(seen) || seen[i] != want[i] {
			t.Fatalf("request %d:\n got %q\nwant %q", i, seen, want[i])
		}
	}
	// An API error is an error, with the brain's message.
	b.Node = "nobody"
	if _, _, err := b.Acquire(ctx, "example.com"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404 not surfaced: %v", err)
	}
}
