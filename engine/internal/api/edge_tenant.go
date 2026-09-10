package api

// Tenant scope on the edge channel's human-facing reads (E6.2). A zone is
// owned by the tenant its zones-file entry names (config.Zone.Tenant); an
// unlabelled zone by nobody but the unscoped tokens. Default-deny and
// fail-closed: a zone outside the file — reported by a node, or carrying a
// lever set before a reload removed it — is visible to unscoped tokens only.
// The zones DOCUMENT the nodes poll never carries the label and stays
// unscoped (agent + unscoped operator), as do both reports, the ACME
// coordination, the inventory and config/reload. Node names are NOT hidden
// from a tenant (edge-spec §8, D3): where its zones are served is its
// business; the addresses and hostgroups live in the inventory.

import (
	"net/http"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/metrics"
)

// logZoneRefusal is the trace a scoped caller's refusal on a zone it does not
// own leaves for the OPERATOR (D10): the caller sees the route's one uniform
// refusal (the lever's 404, the history reads' 403) and no audit row is
// written, but the counter moves and one Warn a minute per token
// names the token, its tenant, the route and what it asked for — so a leaked
// scoped token walking a hostname list is visible in the log and in
// Prometheus without the caller learning whether the zone exists.
func (s *Server) logZoneRefusal(c caller, zone, route string, r *http.Request) {
	metrics.APIZoneRefused.WithLabelValues(route).Inc()
	if !s.warnOncePerToken(c.token) {
		return
	}
	s.log.Warn("zone refused: the token's tenant does not own it", "token", c.token, "tenant", c.tenant, "zone", truncateForLog(zone), "route", route, "remote", r.RemoteAddr)
}

// zoneInFile returns the zones file's entry for name, or nil when the brain
// holds no zones file or the name is not in it.
func zoneInFile(cfg *config.Config, name string) *config.Zone {
	if cfg == nil || cfg.ZonesCfg == nil {
		return nil
	}
	for i := range cfg.ZonesCfg.Zones {
		if z := &cfg.ZonesCfg.Zones[i]; z.Name == name {
			return z
		}
	}
	return nil
}

// visibleZone says whether the caller may see and act on the zone: an
// unscoped token sees every zone, a scoped one exactly the file's zones
// labelled with its tenant.
func visibleZone(c caller, cfg *config.Config, name string) bool {
	if c.unscoped() {
		return true
	}
	z := zoneInFile(cfg, name)
	return z != nil && z.Tenant == c.tenant
}
