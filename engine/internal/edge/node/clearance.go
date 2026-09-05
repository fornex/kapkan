package node

import (
	"context"

	"github.com/kapkan-io/kapkan/internal/edge/clearance/page"
)

// serveClearance runs the clearance page on the fourth socket — the
// proof-of-work rung's face (edge-spec §5, E4.3): the challenge page the
// terminator serves in place of the origin on a 401, the answer endpoint
// that mints the clearance cookie, the no-JS ticket, and the page's two
// assets. It signs with the keys the decision service verifies with, and
// reads each zone's rung policy from it, so the two halves cannot disagree.
// Same socket contract as the decision service: 0660, the terminator's
// worker group — the page mints cookies, so nobody else may ask it.
func (n *Node) serveClearance(ctx context.Context) error {
	return (&page.Server{Zones: n.svc, Path: n.files.clearanceSock, SocketGroup: n.opt.SocketGroup, Logger: n.opt.Logger}).ListenAndServe(ctx)
}
