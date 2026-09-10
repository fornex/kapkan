package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// APIZoneRefused counts the requests a tenant-scoped token made on a zone it
// does not own — another tenant's, unlabelled, or gone from the zones file —
// by route (edge_lever, edge_history). The caller gets the route's one
// uniform refusal (the lever's "unknown zone" 404, the history reads' 403)
// and no audit row is written (edge-spec §8, D10); a rising count is a
// misconfigured or leaked scoped token, and the brain's log names it once a
// minute per token.
var APIZoneRefused = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "kapkan",
	Subsystem: "api",
	Name:      "zone_refused_total",
	Help:      "Requests refused because a tenant-scoped token named a zone outside its tenant, by route (edge_lever|edge_history).",
}, []string{"route"})
