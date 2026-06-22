// Package app wires the kapkan components — ingest, engine, mitigation,
// notification and the API — into a single startable/stoppable unit. Both the
// command binary and the end-to-end test construct an App, so the wiring is
// exercised exactly as it runs in production.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/geoip"
	"github.com/kapkan-io/kapkan/internal/ingest"
	"github.com/kapkan-io/kapkan/internal/mitigate"
	"github.com/kapkan-io/kapkan/internal/notify"
	"github.com/kapkan-io/kapkan/internal/storage"
)

// App holds the wired components and their lifecycle handles.
type App struct {
	Store    *config.Store
	Engine   *engine.Engine
	Ingest   *ingest.Ingester
	Mitigate *mitigate.Mitigator
	Notify   *notify.Notifier
	API      *api.Server
	Storage  storage.Writer
	GeoIP    *geoip.DB

	log         *slog.Logger
	cancel      context.CancelFunc
	storeCancel context.CancelFunc
	wg          sync.WaitGroup
	apiErr      chan error
}

// New builds all components from the configuration store. It does not bind
// sockets or start goroutines; call Start for that.
func New(store *config.Store, log *slog.Logger) (*App, error) {
	a := &App{Store: store, log: log, apiErr: make(chan error, 1)}

	// GeoIP/ASN enrichment is optional. Config validation already rejected a
	// missing path or a directory at load time; a remaining open failure here
	// (a corrupt/unreadable .mmdb, or one removed between load and open) is
	// logged and the detector runs without attribution rather than refusing to
	// start over a non-critical data file.
	engineOpts := []engine.Option{engine.WithLogger(log)}
	if gc := store.Get().GeoIPCfg; gc.Enabled {
		db, err := geoip.Open(gc.ASNPath, gc.CountryPath)
		if err != nil {
			log.Warn("geoip disabled: could not open database", "err", err)
		} else {
			a.GeoIP = db
			engineOpts = append(engineOpts, engine.WithGeoIP(db))
			log.Info("geoip enabled", "asn_database", gc.ASNPath, "country_database", gc.CountryPath)
		}
	}
	a.Engine = engine.New(store, engineOpts...)

	mit, err := mitigate.New(store, log)
	if err != nil {
		return nil, fmt.Errorf("init mitigation: %w", err)
	}
	a.Mitigate = mit

	a.Notify = notify.New(store, log)

	ing, err := ingest.New(store, a.Engine.Process, log)
	if err != nil {
		return nil, fmt.Errorf("init ingest: %w", err)
	}
	a.Ingest = ing

	a.API = api.New(store, a.Engine, mit, log)
	a.API.SetQuerier(storage.NewQuerier(store.Get().StorageCfg, log))
	a.Storage = storage.NewWriter(store.Get().StorageCfg, log)
	a.API.SetAuditWriter(a.Storage) // operator-attributed audit trail (no-op when storage off)
	return a, nil
}

// Start brings up the BGP speaker, binds the UDP listeners and the API, and
// launches the engine evaluation loop and the event consumer. It returns once
// everything is started; use APIError to observe a fatal API failure.
func (a *App) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	if err := a.Mitigate.Start(runCtx); err != nil {
		cancel()
		return fmt.Errorf("start mitigation: %w", err)
	}
	if err := a.Ingest.Start(); err != nil {
		cancel()
		return fmt.Errorf("start ingest: %w", err)
	}
	// Storage gets its own context, cancelled only in Stop after every
	// producer goroutine has joined — so its shutdown drain runs strictly
	// last and captures the final attack/traffic rows instead of racing the
	// producers for them.
	storeCtx, storeCancel := context.WithCancel(context.Background())
	a.storeCancel = storeCancel
	a.Storage.Start(storeCtx)

	go func() { a.apiErr <- a.API.ListenAndServe(runCtx) }()

	a.wg.Add(3)
	go func() { defer a.wg.Done(); a.Engine.Run(runCtx) }()
	go func() { defer a.wg.Done(); a.consumeEvents(runCtx) }()
	go func() { defer a.wg.Done(); a.persistTraffic(runCtx) }()
	return nil
}

// APIError returns a channel that yields the API server's terminal error (or
// nil on clean shutdown).
func (a *App) APIError() <-chan error { return a.apiErr }

// Stop tears down ingest, the engine loop and the BGP speaker in the safe
// order: stop accepting flows first, then drain. Storage is torn down last,
// and only after every producer goroutine has joined, so its final drain
// truly captures the last attack/traffic rows they enqueued.
func (a *App) Stop() {
	a.Ingest.Stop()
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait() // engine, consumeEvents and persistTraffic have stopped producing
	a.Mitigate.Stop()
	if a.storeCancel != nil {
		a.storeCancel() // now trigger the storage drain+flush
	}
	a.Storage.Stop()
	// The engine has stopped collecting samples (wg.Wait above), so the mmap
	// is no longer read; release it last.
	if a.GeoIP != nil {
		_ = a.GeoIP.Close()
	}
}

// consumeEvents bridges engine attack events to mitigation, the API attack
// log and notifications.
func (a *App) consumeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-a.Engine.Events():
			switch ev.Kind {
			case engine.AttackStarted:
				ban := a.Mitigate.OnAttackStarted(ev)
				a.API.RecordAttackStarted(ev, ban)
				a.Notify.NotifyAttackStarted(ctx, ev, ban)
				a.Storage.WriteAttack(attackRow(ev, ban))
			case engine.AttackEnded:
				ban := a.Mitigate.OnAttackEnded(ev)
				a.API.RecordAttackEnded(ev, ban)
				a.Notify.NotifyAttackEnded(ctx, ev, ban)
				a.Storage.WriteAttack(attackRow(ev, ban))
			}
		}
	}
}

// chTimeFormat is ClickHouse's DateTime literal layout (UTC).
const chTimeFormat = "2006-01-02 15:04:05"

// attackRow maps an engine event (and its resulting ban) to a storage row.
func attackRow(ev engine.Event, ban *mitigate.Ban) storage.AttackRow {
	r := storage.AttackRow{
		EventTime: ev.At.UTC().Format(chTimeFormat),
		Kind:      ev.Kind.String(),
		Scope:     string(ev.Scope),
		Group:     ev.Group,
		Direction: string(ev.Direction),
		Metric:    string(ev.Metric),
		Rate:      ev.Rate,
		Threshold: ev.Threshold,
		PPS:       ev.Rates.PPS,
		Mbps:      ev.Rates.Mbps,
		FlowsPS:   ev.Rates.FlowsPerSec,
	}
	if ev.Target.IsValid() {
		r.Target = ev.Target.String()
	}
	if ev.Classification != nil {
		r.AttackType = string(ev.Classification.Type)
	}
	if ev.Sample != nil {
		keys := make([]string, 0, len(ev.Sample.TopSources))
		for _, c := range ev.Sample.TopSources {
			keys = append(keys, c.Key)
		}
		r.TopSources = strings.Join(keys, ",")
		asns := make([]string, 0, len(ev.Sample.TopASNs))
		for _, c := range ev.Sample.TopASNs {
			asns = append(asns, c.Key)
		}
		// Pipe-joined, not comma: AS org names routinely contain commas
		// ("DigitalOcean, LLC"), which would make a comma-joined field
		// ambiguous to split.
		r.TopASNs = strings.Join(asns, " | ")
	}
	if ban != nil {
		r.BanState = string(ban.State)
		if ban.DryRun {
			r.DryRun = 1
		}
	}
	if ev.Reason != nil {
		if b, err := json.Marshal(ev.Reason); err == nil {
			r.Reason = string(b)
		}
	}
	return r
}

// persistTraffic snapshots per-host rates to storage on a fixed interval so
// the dashboard and reports can show traffic over time. engine.Snapshot is
// O(tracked hosts) and runs off the hot path; the rows are enqueued
// non-blocking, so a slow ClickHouse only drops snapshots. (Per-hostgroup
// totals are not yet snapshotted — the engine does not expose group state.)
func (a *App) persistTraffic(ctx context.Context) {
	interval := a.Store.Get().StorageCfg.TrafficInterval
	if interval <= 0 {
		return // storage disabled
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.snapshotTraffic()
		}
	}
}

func (a *App) snapshotTraffic() {
	hosts := a.Engine.Snapshot()
	if len(hosts) == 0 {
		return
	}
	ts := time.Now().UTC().Format(chTimeFormat)
	rows := make([]storage.TrafficRow, 0, len(hosts))
	for _, h := range hosts {
		rows = append(rows, trafficRow(h, ts))
	}
	a.Storage.WriteTraffic(rows)
}

// trafficRow maps one host snapshot to a storage row.
func trafficRow(h engine.HostStat, ts string) storage.TrafficRow {
	row := storage.TrafficRow{
		TS:      ts,
		Scope:   "host",
		Key:     h.Target.String(),
		Group:   h.Group,
		PPS:     h.Rates.PPS,
		Mbps:    h.Rates.Mbps,
		FlowsPS: h.Rates.FlowsPerSec,
	}
	if h.InAttack {
		row.InAttack = 1
	}
	if h.Baseline != nil {
		row.BaselinePPS = h.Baseline.PPS
	}
	return row
}
