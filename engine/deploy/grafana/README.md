# Kapkan Grafana dashboard

`kapkan-overview.json` is an official Grafana dashboard for the `kapkan_*` Prometheus
metrics exposed at `GET /metrics` (see [Metrics](../../../docs/en/metrics.mdx)). It covers
the whole pipeline:

- **Overview** — active attacks, tracked hosts, announced routes (real), FlowSpec rules (real).
- **Ingestion** — flow records/s, telemetry datagrams/s, decode errors/s (all by protocol),
  and dropped flows/s (engine queue full).
- **Detection / Engine** — active attacks, attacks started/s, tracked hosts, and hot-path
  processing latency (p50 / p95 / p99).
- **Mitigation** — announced routes and FlowSpec rules by `mode` (real vs dry_run), bans
  rejected/s by `reason`, and mitigation fallbacks/s (`from → to`).
- **Notifications & Storage** — notification attempts/s by channel and result, storage
  rows/s by table and result.

## Import

**Grafana UI** — Dashboards → New → Import → Upload `kapkan-overview.json`, then pick your
Prometheus data source when prompted (the dashboard templatizes it as `DS_PROMETHEUS`).

**Provisioning** — drop the file into a provisioned dashboards path, e.g.:

```yaml
# /etc/grafana/provisioning/dashboards/kapkan.yaml
apiVersion: 1
providers:
  - name: kapkan
    type: file
    options:
      path: /var/lib/grafana/dashboards/kapkan
```

The dashboard is built for Grafana 10+ (schema version 39) and was import-verified against
Grafana 11.3.

Make sure Kapkan is a Prometheus scrape target first — see the **Scraping** section of the
[Metrics](../../../docs/en/metrics.mdx) docs.
