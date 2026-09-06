package clearance

import (
	"net/url"
	"strings"
	"testing"
)

// TestAnswerFormFitsTheTerminatorBodyCap pins the answer POST's budget
// against the renderer's client_max_body_size for /_kapkan/clearance/ (8k):
// the browser form-encodes the hidden fields, tripling every reserved byte,
// so the longest return path the puzzle admits, the longest nonce and the
// longest solution the page accepts must still fit together — or nginx
// answers a bare 413 the visitor cannot get past, and the solver, which
// finishes long before the timed fallback is offered, posts it again.
func TestAnswerFormFitsTheTerminatorBodyCap(t *testing.T) {
	const bodyCap = 8 << 10               // client_max_body_size in the rendered clearance location
	const maxNonce, maxSolution = 128, 64 // the page's bounds on the answer's fields
	// Every byte reserved, so every byte encodes to three.
	form := url.Values{
		"nonce":    {strings.Repeat("/", maxNonce)},
		"solution": {strings.Repeat("/", maxSolution)},
		"return":   {strings.Repeat("&", maxReturnPath-1)},
	}
	if n := len(form.Encode()); n > bodyCap {
		t.Fatalf("the worst-case answer body is %d bytes; the terminator accepts %d", n, bodyCap)
	}
}
