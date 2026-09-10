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

import "github.com/kapkan-io/kapkan/internal/config"

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
