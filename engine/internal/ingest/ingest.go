// Package ingest receives sFlow/NetFlow/IPFIX telemetry over UDP using
// netsampler/goflow2 v2 in library mode and converts every decoded flow into
// the normalized flow.Flow consumed by the detection engine.
//
// goflow2's decoded messages alias a pooled UDP buffer that is recycled the
// moment the producer's Produce method returns, so this package deep-copies
// every retained field (addresses) into value types before handing a flow
// downstream. See docs/research/goflow2.md.
package ingest

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/flow"
	"github.com/kapkan-io/kapkan/internal/metrics"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	flowpb "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/producer"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/utils"
	"github.com/netsampler/goflow2/v2/utils/debug"
)

// SinkFunc receives each normalized flow. It is called concurrently by the
// receiver's decode workers, so it must be safe for concurrent use (the
// engine's Process is).
type SinkFunc func(flow.Flow)

// Ingester owns the UDP receivers and decode pipeline.
type Ingester struct {
	store *config.Store
	sink  SinkFunc
	log   *slog.Logger

	recvs map[string]*utils.UDPReceiver // proto family -> receiver
	prod  producer.ProducerInterface
	pipes []utils.FlowPipe
	stopC chan struct{}
}

// New builds an Ingester. The proto producer is configured with an empty
// (default) mapping; the sampling system is per-exporter so reported rates
// are honored, with the configured default applied as a fallback during
// conversion.
func New(store *config.Store, sink SinkFunc, log *slog.Logger) (*Ingester, error) {
	cfg, err := (&protoproducer.ProducerConfig{}).Compile()
	if err != nil {
		return nil, fmt.Errorf("compile producer config: %w", err)
	}
	inner, err := protoproducer.CreateProtoProducer(cfg, protoproducer.CreateSamplingSystem)
	if err != nil {
		return nil, fmt.Errorf("create proto producer: %w", err)
	}
	ing := &Ingester{
		store: store,
		sink:  sink,
		log:   log,
		recvs: make(map[string]*utils.UDPReceiver),
		stopC: make(chan struct{}),
	}
	// Wrap: our converter, then the panic guard so malformed packets that
	// trip the packet parser become errors instead of crashing the process.
	var prod producer.ProducerInterface = &flowProducer{
		inner:     inner,
		sink:      sink,
		store:     store,
		exporters: newExporterLabeler(),
	}
	prod = debug.WrapPanicProducer(prod)
	ing.prod = prod
	return ing, nil
}

// dropCounter implements utils.ReceiverCallback, recording UDP queue drops.
type dropCounter struct{}

func (dropCounter) Dropped(utils.Message) { metrics.DroppedFlowsTotal.Inc() }

// Start binds the configured UDP listeners and begins decoding. Each listen
// address gets its own receiver and protocol-appropriate pipe.
func (i *Ingester) Start() error {
	cfg := i.store.Get()
	if cfg.Listen.SFlow != "" {
		if err := i.startReceiver("sflow", cfg.Listen.SFlow, utils.NewSFlowPipe(&utils.PipeConfig{Producer: i.prod})); err != nil {
			return err
		}
	}
	if cfg.Listen.NetFlow != "" {
		if err := i.startReceiver("netflow", cfg.Listen.NetFlow, utils.NewNetFlowPipe(&utils.PipeConfig{Producer: i.prod})); err != nil {
			return err
		}
	}
	return nil
}

func (i *Ingester) startReceiver(family, listen string, pipe utils.FlowPipe) error {
	host, port, err := splitListen(listen)
	if err != nil {
		return fmt.Errorf("%s listen %q: %w", family, listen, err)
	}
	recv, err := utils.NewUDPReceiver(&utils.UDPReceiverConfig{
		Sockets:          2,
		Workers:          4,
		QueueSize:        1_000_000, // 0 would mean an UNBUFFERED dispatch channel
		ReceiverCallback: dropCounter{},
	})
	if err != nil {
		return fmt.Errorf("%s receiver: %w", family, err)
	}
	// PanicDecoderWrapper recovers panics in the decode path into errors.
	decode := debug.PanicDecoderWrapper(pipe.DecodeFlow)
	if err := recv.Start(host, port, decode); err != nil {
		return fmt.Errorf("%s start %s: %w", family, listen, err)
	}
	i.recvs[family] = recv
	i.pipes = append(i.pipes, pipe)
	go i.drainErrors(family, recv)
	i.log.Info("ingest listener started", "proto", family, "listen", listen)
	return nil
}

// drainErrors consumes the receiver error channel (the sender side is
// non-blocking, so unread errors are silently dropped) and records metrics.
func (i *Ingester) drainErrors(family string, recv *utils.UDPReceiver) {
	errs := recv.Errors()
	for {
		select {
		case <-i.stopC:
			return
		case err, ok := <-errs:
			if !ok {
				return
			}
			switch {
			case errors.Is(err, net.ErrClosed):
				// Socket closed during Stop; not an error.
			case errors.Is(err, netflow.ErrorTemplateNotFound):
				metrics.DecodeErrorsTotal.WithLabelValues(family).Inc()
				i.log.Warn("flow data before template (exporter warm-up)", "proto", family)
			case errors.Is(err, debug.ErrPanic):
				metrics.DecodeErrorsTotal.WithLabelValues(family).Inc()
				i.log.Error("recovered panic decoding flow", "proto", family, "err", err)
			default:
				metrics.DecodeErrorsTotal.WithLabelValues(family).Inc()
				i.log.Warn("flow decode error", "proto", family, "err", err)
			}
		}
	}
}

// Stop shuts down all receivers and the decode pipeline.
func (i *Ingester) Stop() {
	close(i.stopC)
	for _, recv := range i.recvs {
		_ = recv.Stop()
	}
	for _, p := range i.pipes {
		p.Close()
	}
	if i.prod != nil {
		i.prod.Close()
	}
}

// flowProducer converts goflow2 proto messages into flow.Flow and pushes
// them to the sink. It wraps the proto producer and returns the original
// message set so the proto producer can recycle its pooled messages.
type flowProducer struct {
	inner     producer.ProducerInterface
	sink      SinkFunc
	store     *config.Store
	exporters *exporterLabeler
}

func (p *flowProducer) Produce(msg interface{}, args *producer.ProduceArgs) ([]producer.ProducerMessage, error) {
	set, err := p.inner.Produce(msg, args)
	cfg := p.store.Get()
	for _, m := range set {
		pm, ok := m.(*protoproducer.ProtoProducerMessage)
		if !ok {
			continue
		}
		f, ok := convert(pm, cfg.Sampling.DefaultRate)
		if !ok {
			continue
		}
		metrics.FlowsTotal.WithLabelValues(f.Wire.String()).Inc()
		if f.Exporter.IsValid() {
			// The exporter is the telemetry UDP source address, which is
			// unauthenticated and trivially spoofable, so the metric label is
			// cardinality-bounded to keep a flood of spoofed sources from
			// exhausting memory. See exporterLabeler.
			metrics.PacketsTotal.WithLabelValues(p.exporters.label(f.Exporter, cfg.FlowSourceSet), f.Wire.String()).Inc()
		}
		p.sink(f)
	}
	// Return the original set (even on error: partial results may exist) so
	// Commit recycles the pooled messages.
	return set, err
}

func (p *flowProducer) Commit(set []producer.ProducerMessage) { p.inner.Commit(set) }
func (p *flowProducer) Close()                                { p.inner.Close() }

const (
	// maxExporterLabels bounds the number of distinct exporter addresses that
	// receive their own "exporter" label on the packets_total metric when no
	// flow_sources allowlist is configured. Telemetry arrives over
	// unauthenticated UDP, so the exporter (source) address is attacker-
	// spoofable; without a bound a flood of distinct spoofed sources would
	// create unbounded Prometheus time series and exhaust the daemon's memory
	// — exactly during the attack it must survive. Real deployments have far
	// fewer exporters than this; operators wanting exact, spoof-proof
	// attribution should set flow_sources.
	maxExporterLabels = 1024
	// otherExporter is the bucket label for exporters beyond the cap, or
	// outside a configured flow_sources allowlist.
	otherExporter = "other"
)

// exporterLabeler maps an exporter address to a bounded-cardinality metric
// label value. It is safe for concurrent use by the decode workers.
type exporterLabeler struct {
	mu   sync.RWMutex
	seen map[netip.Addr]string // capped cache of exporter -> label string
}

func newExporterLabeler() *exporterLabeler {
	return &exporterLabeler{seen: make(map[netip.Addr]string)}
}

// label returns the metric label for exporter. When allow is non-empty only
// addresses in it are labeled individually and every other (incl. spoofed)
// source buckets under otherExporter — so an allowlisted exporter is never
// displaced by a flood. When allow is empty the first maxExporterLabels
// distinct exporters seen are labeled and the rest bucket under otherExporter.
func (l *exporterLabeler) label(exporter netip.Addr, allow map[netip.Addr]struct{}) string {
	if len(allow) > 0 {
		if _, ok := allow[exporter]; ok {
			return exporter.String()
		}
		return otherExporter
	}
	l.mu.RLock()
	s, known := l.seen[exporter]
	full := len(l.seen) >= maxExporterLabels
	l.mu.RUnlock()
	if known {
		return s
	}
	if full {
		return otherExporter
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.seen[exporter]; ok { // re-check after upgrading the lock
		return s
	}
	if len(l.seen) >= maxExporterLabels {
		return otherExporter
	}
	s = exporter.String()
	l.seen[exporter] = s
	return s
}

// convert deep-copies the aliased fields of a proto message into a flow.Flow.
// It returns ok=false for messages without a usable destination address.
func convert(pm *protoproducer.ProtoProducerMessage, defaultRate uint64) (flow.Flow, bool) {
	// AddrFromSlice copies the bytes — mandatory, the slices alias the
	// pooled UDP buffer that is recycled when Produce returns.
	dst, ok := netip.AddrFromSlice(pm.DstAddr)
	if !ok {
		return flow.Flow{}, false
	}
	src, _ := netip.AddrFromSlice(pm.SrcAddr)
	exporter, _ := netip.AddrFromSlice(pm.SamplerAddress)

	rate := pm.SamplingRate
	if rate == 0 {
		rate = defaultRate
	}
	if rate == 0 {
		rate = 1
	}

	return flow.Flow{
		SrcAddr:      src.Unmap(),
		DstAddr:      dst.Unmap(),
		Exporter:     exporter.Unmap(),
		Bytes:        pm.Bytes,
		Packets:      pm.Packets,
		SamplingRate: rate,
		InIf:         pm.InIf,
		OutIf:        pm.OutIf,
		SrcPort:      uint16(pm.SrcPort),
		DstPort:      uint16(pm.DstPort),
		IPProto:      uint8(pm.Proto),
		TCPFlags:     uint8(pm.TcpFlags),
		Fragment:     pm.FragmentOffset > 0,
		Wire:         wireProto(pm.Type),
	}, true
}

func wireProto(t flowpb.FlowMessage_FlowType) flow.Proto {
	switch t {
	case flowpb.FlowMessage_SFLOW_5:
		return flow.ProtoSFlow5
	case flowpb.FlowMessage_NETFLOW_V5:
		return flow.ProtoNetFlow5
	case flowpb.FlowMessage_NETFLOW_V9:
		return flow.ProtoNetFlow9
	case flowpb.FlowMessage_IPFIX:
		return flow.ProtoIPFIX
	default:
		return flow.ProtoUnknown
	}
}

// splitListen splits a ":port" or "host:port" listen string into a host
// (empty means all interfaces) and an integer port.
func splitListen(listen string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port %d out of range", port)
	}
	return host, port, nil
}

// newDecodeProducer exposes the conversion producer for tests that drive a
// pipe directly without a UDP socket.
func newDecodeProducer(store *config.Store, sink SinkFunc) producer.ProducerInterface {
	cfg, _ := (&protoproducer.ProducerConfig{}).Compile()
	inner, _ := protoproducer.CreateProtoProducer(cfg, protoproducer.CreateSamplingSystem)
	return debug.WrapPanicProducer(&flowProducer{
		inner:     inner,
		sink:      sink,
		store:     store,
		exporters: newExporterLabeler(),
	})
}
