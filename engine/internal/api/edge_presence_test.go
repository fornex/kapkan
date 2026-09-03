package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A node that dies while its poll is parked closes the connection; the brain
// must notice, end the hold and stop counting the node as present once
// stale_after has passed — the E3 rig stops a node for 6 s with stale_after 5
// and expects the inventory to say so.
func TestEdgePresenceEndsWhenAParkedPollDisconnects(t *testing.T) {
	s := testServer(t, edgeStoreNodes(t, edgeZonesOne, "e1"))
	s.rulesHold = 10 * time.Second
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	first, err := http.Get(srv.URL + "/api/v1/status") // warm-up is not needed; keep the server honest
	if err == nil {
		_ = first.Body.Close()
	}
	// The node's first poll: 200 with the ETag.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/edge/zones?node=e1", nil)
	req.Header.Set("Authorization", "Bearer agent-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || etag == "" {
		t.Fatalf("first poll: %d etag=%q", resp.StatusCode, etag)
	}

	// The second poll parks; then the client goes away.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/edge/zones?node=e1", nil)
		r.Header.Set("Authorization", "Bearer agent-secret")
		r.Header.Set("If-None-Match", etag)
		_, err := http.DefaultClient.Do(r)
		done <- err
	}()
	waitEdgeHolds(t, s, 1)
	if _, holding := s.edgePresence.seen("e1"); !holding {
		t.Fatal("parked poll not counted as holding")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled poll returned without an error")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, holding := s.edgePresence.seen("e1"); !holding {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	last, holding := s.edgePresence.seen("e1")
	if holding {
		t.Fatal("the brain still counts the disconnected poll as holding; the hold loop did not see the client leave")
	}
	if time.Since(last) > time.Second {
		t.Fatalf("lastSeen %v ago; the disconnect should have stamped it", time.Since(last))
	}
	// Alive while inside stale_after, lost after it.
	if !s.edgePresence.alive("e1", 5*time.Second) {
		t.Fatal("node counted lost right after its poll ended")
	}
	if s.edgePresence.alive("e1", 0) {
		t.Fatal("node counted alive past stale_after")
	}
}
