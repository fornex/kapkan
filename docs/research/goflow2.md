# goflow2 v2 (v2.2.6) — library-mode implementation notes

Target: ingest **sFlow v5 + NetFlow v5/v9 + IPFIX** over UDP inside our own Go program and
convert every flow into a custom internal struct. No goflow2 binary, no format/transport
plugins required.

Sources read from: `$(go env GOMODCACHE)/github.com/netsampler/goflow2/v2@v2.2.6`
(= `/Users/fornex/go/pkg/mod/github.com/netsampler/goflow2/v2@v2.2.6`).

Module: `github.com/netsampler/goflow2/v2`, `go 1.23.0`. The UDP receiver pulls in
`github.com/libp2p/go-reuseport v0.4.0` (SO_REUSEPORT); the proto producer pulls in
`google.golang.org/protobuf`.

---

## 1. UDP receiver, decode func, pipes

### 1.1 `utils.UDPReceiver` — `github.com/netsampler/goflow2/v2/utils` (utils/udp.go)

Exact signatures (copied from source):

```go
// ReceiverCallback is notified when packets are dropped.
type ReceiverCallback interface {
	Dropped(msg Message)
}

// DecoderFunc decodes a received UDP message.
type DecoderFunc func(msg interface{}) error

// Message carries a received UDP payload and metadata.
type Message struct {
	Src      netip.AddrPort
	Dst      netip.AddrPort
	Payload  []byte
	Received time.Time
}

// UDPReceiverConfig configures UDP receiver workers and sockets.
type UDPReceiverConfig struct {
	Workers   int
	Sockets   int
	Blocking  bool
	QueueSize int

	ReceiverCallback ReceiverCallback
}

func NewUDPReceiver(cfg *UDPReceiverConfig) (*UDPReceiver, error)

// Start runs UDP receivers and processing routines.
func (r *UDPReceiver) Start(addr string, port int, decodeFunc DecoderFunc) error

// Stop stops the receiver and worker routines.
func (r *UDPReceiver) Stop() error

// Errors returns a channel of receiver errors.
func (r *UDPReceiver) Errors() <-chan error
```

Semantics (from source, not docs):

- **Config defaults**: with `cfg == nil`: `sockets=2, workers=2, queueSize=1000000`. With
  `cfg != nil`: `Sockets <= 0` → 1; `Workers <= 0` → `Workers = Sockets`;
  `QueueSize == 0` → **unbuffered** dispatch channel ("synchronous mode") — so if you pass
  a config and want a buffer you must set `QueueSize` explicitly (the goflow2 CLI defaults
  it to 1,000,000 when not blocking).
- **Concurrency model**: `Start` spawns `Sockets` goroutines each doing
  `reuseport.ListenPacket("udp", addr:port)` + `ReadFromUDP` loop, and `Workers` decoder
  goroutines all consuming one shared `dispatch chan *udpPacket` and calling **the same
  `decodeFunc` concurrently**. Your DecoderFunc / pipe / producer must be thread-safe.
- **Packet buffers come from a `sync.Pool` of 9000-byte slices** (`packetPool`). The
  worker builds `Message{Payload: pkt.payload[0:pkt.size], ...}` , calls `decodeFunc(&msg)`,
  then does `packetPool.Put(pkt)`. **`Message.Payload` (and anything aliasing it) is only
  valid for the duration of the decodeFunc call.** Datagrams larger than 9000 bytes are
  silently truncated by `ReadFromUDP`.
- **Backpressure**: `Blocking: true` → receive goroutine blocks on dispatch (no drops).
  Non-blocking (default) → on full queue the packet is dropped and
  `ReceiverCallback.Dropped(Message)` is invoked (this is the drop-metrics hook).
- **Errors**: decode errors are wrapped as `&ReceiverError{err}` (`Error() = "receiver: ..."`,
  has `Unwrap()`) and pushed to the error channel with a **non-blocking send** — if you
  don't drain `Errors()`, errors are silently discarded (it never blocks the workers).
- **Lifecycle**: a receiver can only be `Start`ed once at a time
  (`"receiver is already started"`); `Stop()` closes the quit channel, pushes one `nil`
  per decoder goroutine into dispatch, waits on the WaitGroup, then re-inits so the same
  receiver may be started again. One `UDPReceiver` handles exactly one `(addr, port)`;
  create one per listening port.

### 1.2 Choosing decoders per port — pipes (utils/pipe.go)

There is no port→decoder registry. You choose the decoder by constructing the matching
pipe and passing its `DecodeFlow` method as the `DecoderFunc` for that port's receiver.

```go
// FlowPipe describes a flow decoder/formatter pipeline.
type FlowPipe interface {
	DecodeFlow(msg interface{}) error
	Close()
}

// PipeConfig wires formatter, transport, and producer dependencies.
type PipeConfig struct {
	Format    format.FormatInterface
	Transport transport.TransportInterface
	Producer  producer.ProducerInterface

	NetFlowTemplater templates.TemplateSystemGenerator
}

func NewSFlowPipe(cfg *PipeConfig) *SFlowPipe
func NewNetFlowPipe(cfg *PipeConfig) *NetFlowPipe
func NewFlowPipe(cfg *PipeConfig) *AutoFlowPipe   // auto-detects sFlow vs NetFlow per packet

func (p *SFlowPipe) DecodeFlow(msg interface{}) error
func (p *NetFlowPipe) DecodeFlow(msg interface{}) error
func (p *NetFlowPipe) GetTemplatesForAllSources() map[string]map[uint64]interface{}
```

- All `PipeConfig` fields may be nil. If `Producer == nil`, `DecodeFlow` decodes and
  returns nil (useful only for side effects). If `Format == nil`, the post-produce
  `formatSend` loop is a no-op — **in library mode set only `Producer` and leave
  `Format`/`Transport` nil**.
- `NetFlowTemplater` defaults to `templates.DefaultTemplateGenerator` (one
  `netflow.CreateTemplateSystem()` per source) when nil.
- `DecodeFlow` expects `msg` to be `*utils.Message` (exactly what the receiver workers
  pass); anything else returns `fmt.Errorf("flow is not *Message")`.
- `SFlowPipe.DecodeFlow`: decodes `sflow.Packet` via `sflow.DecodeMessageVersion`,
  builds `producer.ProduceArgs{Src, Dst, TimeReceived: pkt.Received, SamplerAddress: pkt.Src.Addr()}`,
  calls `p.producer.Produce(&packet, &args)`, **`defer p.producer.Commit(flowMessageSet)`**,
  then formats/sends.
- `NetFlowPipe.DecodeFlow`: reads the first uint16 version itself, then dispatches:
  `5` → `netflowlegacy.DecodeMessage(buf, &packetV5)`,
  `9` → `netflow.DecodeMessageNetFlow(buf, templates, &packetNFv9)`,
  `10` → `netflow.DecodeMessageIPFIX(buf, templates, &packetIPFIX)`,
  else `"not a NetFlow packet"`. It keeps a per-source template system in
  `map[string]netflow.NetFlowTemplateSystem` keyed by **`pkt.Src.String()` — the full
  `ip:port` AddrPort string**, guarded by a RWMutex.
- `AutoFlowPipe.DecodeFlow` sniffs the first uint32: `5` → sFlow, high 16 bits in
  {5,9,10} → NetFlow.
- Decode/produce errors are wrapped as
  `&PipeMessageError{Message *utils.Message; Err error}` (has `Unwrap()`).

---

## 2. Producer interface and writing a custom producer

`github.com/netsampler/goflow2/v2/producer` (producer/producer.go) — entire package:

```go
// ProducerMessage is the generic type returned by producers.
type ProducerMessage interface{}

// ProducerInterface converts decoded packets into producer messages.
type ProducerInterface interface {
	// Converts a message into a list of flow samples
	Produce(msg interface{}, args *ProduceArgs) ([]ProducerMessage, error)
	// Indicates to the producer the messages returned were processed
	Commit([]ProducerMessage)
	Close()
}

// ProduceArgs captures metadata about the received packet.
type ProduceArgs struct {
	Src            netip.AddrPort
	Dst            netip.AddrPort
	SamplerAddress netip.Addr
	TimeReceived   time.Time
}
```

Note: the task brief said `producer.ProcessArgs` — the actual name is
**`producer.ProduceArgs`**. The pipes fill `Src`/`Dst` from the UDP packet,
`TimeReceived` from receive time, and `SamplerAddress = pkt.Src.Addr()` (UDP source IP).

### Concrete decoded types arriving at `Produce(msg, args)` (always pointers)

| Wire protocol | `msg` dynamic type | Import path |
|---|---|---|
| sFlow v5 | `*sflow.Packet` | `github.com/netsampler/goflow2/v2/decoders/sflow` |
| NetFlow v5 | `*netflowlegacy.PacketNetFlowV5` | `github.com/netsampler/goflow2/v2/decoders/netflowlegacy` |
| NetFlow v9 | `*netflow.NFv9Packet` | `github.com/netsampler/goflow2/v2/decoders/netflow` |
| IPFIX | `*netflow.IPFIXPacket` | `github.com/netsampler/goflow2/v2/decoders/netflow` |

Key shapes (from source):

```go
// sflow (decoders/sflow/packet.go, datastructure.go)
type Packet struct {
	Version        uint32          `json:"version"`
	IPVersion      uint32          `json:"ip-version"`
	AgentIP        utils.IPAddress `json:"agent-ip"`   // []byte, 4 or 16
	SubAgentId     uint32          `json:"sub-agent-id"`
	SequenceNumber uint32          `json:"sequence-number"`
	Uptime         uint32          `json:"uptime"`
	SamplesCount   uint32          `json:"samples-count"`
	Samples        []interface{}   `json:"samples"`    // sflow.FlowSample | sflow.ExpandedFlowSample | sflow.CounterSample | sflow.DropSample (values, not pointers)
}
type FlowSample struct {
	Header SampleHeader
	SamplingRate     uint32
	SamplePool       uint32
	Drops            uint32
	Input            uint32
	Output           uint32
	FlowRecordsCount uint32
	Records          []FlowRecord    // .Data: sflow.SampledHeader | SampledIPv4 | SampledIPv6 | SampledEthernet | ExtendedSwitch | ExtendedRouter | ExtendedGateway | RawRecord | ...
}

// netflowlegacy (decoders/netflowlegacy/packet.go)
type PacketNetFlowV5 struct {
	Version uint16; Count uint16; SysUptime uint32; UnixSecs uint32; UnixNSecs uint32
	FlowSequence uint32; EngineType uint8; EngineId uint8
	SamplingInterval uint16              // top 2 bits = mode, low 14 bits = interval
	Records []RecordsNetFlowV5           // SrcAddr/DstAddr/NextHop are IPAddress(uint32)
}

// netflow (decoders/netflow/nfv9.go, ipfix.go)
type NFv9Packet struct {
	Version uint16; Count uint16; SystemUptime uint32; UnixSeconds uint32
	SequenceNumber uint32; SourceId uint32
	FlowSets []interface{}   // netflow.TemplateFlowSet | NFv9OptionsTemplateFlowSet | DataFlowSet | OptionsDataFlowSet | RawFlowSet (values)
}
type IPFIXPacket struct {
	Version uint16; Length uint16; ExportTime uint32; SequenceNumber uint32
	ObservationDomainId uint32
	FlowSets []interface{}   // netflow.TemplateFlowSet | IPFIXOptionsTemplateFlowSet | DataFlowSet | OptionsDataFlowSet | RawFlowSet (values)
}
type DataFlowSet struct { FlowSetHeader; Records []DataRecord }
type DataRecord struct { Values []DataField }
type DataField struct {
	PenProvided bool; Type uint16; Pen uint32
	Value interface{}   // in practice []byte slices ALIASING the UDP payload buffer
}
```

A custom producer is any struct implementing the three methods. Plug it into
`PipeConfig.Producer`. Helpers for raw NetFlow field extraction live in
`producer/proto/producer_nf.go`: `NetFlowLookFor`, `NetFlowPopulate`, `DecodeUNumber`,
`DecodeUNumberLE`, plus `SplitNetFlowSets` / `SplitIPFIXSets` to partition `FlowSets` by
type. `producer/raw` (`rawproducer.RawProducer`) just wraps the decoded packet in a
`RawMessage{Message, Src, TimeReceived}` — a good reference for the minimal shape.

**Critical lifetime rule**: NetFlow `DataField.Value`, sFlow `SampledHeader.HeaderData`,
`SampledIPBase.SrcIP/DstIP`, `RawFlowSet.Records`, and the proto producer's
`SrcAddr/DstAddr/NextHop/...` byte slices all alias the pooled 9000-byte UDP buffer.
**Copy everything you keep before `Produce` returns** (the pipe also `defer`s
`Commit`, and the receiver worker returns the buffer to the pool right after
`decodeFunc` returns).

---

## 3. Alternative: the proto producer (`producer/proto`)

Import `protoproducer "github.com/netsampler/goflow2/v2/producer/proto"` and
`flowmessage "github.com/netsampler/goflow2/v2/pb"`.

```go
func CreateProtoProducer(cfg ProtoProducerConfig, samplingRateSystem func() SamplingRateSystem) (producer.ProducerInterface, error)

type SamplingRateSystem interface {
	GetSamplingRate(version uint16, obsDomainId uint32) (uint32, error)
	AddSamplingRate(version uint16, obsDomainId uint32, samplingRate uint32)
}
func CreateSamplingSystem() SamplingRateSystem        // per-(version,obsDomainId) map
type SingleSamplingRateSystem struct { Sampling uint32 } // fixed override

// Config: build from the YAML-shaped struct, even when empty:
type ProducerConfig struct { Formatter FormatterConfig; IPFIX ...; NetFlowV9 ...; SFlow ... }
func (c *ProducerConfig) Compile() (ProtoProducerConfig, error)  // works on a nil *ProducerConfig
```

The messages it returns are `*protoproducer.ProtoProducerMessage`, which **embeds**
`flowmessage.FlowMessage` (pb/flow.pb.go), so all fields below are directly on the
message. Messages are pooled (`sync.Pool`); `ProtoProducer.Commit` puts them back.

### flowpb.FlowMessage fields you care about (exact Go names, proto names)

| Purpose | Go field | type | proto field |
|---|---|---|---|
| protocol of the flow export | `Type` | `FlowMessage_FlowType` enum: `FlowMessage_FLOWUNKNOWN`=0, `FlowMessage_SFLOW_5`=1, `FlowMessage_NETFLOW_V5`=2, `FlowMessage_NETFLOW_V9`=3, `FlowMessage_IPFIX`=4 | `type` |
| receive time | `TimeReceivedNs` | `uint64` (UnixNano) | `time_received_ns` |
| flow start/end | `TimeFlowStartNs`, `TimeFlowEndNs` | `uint64` | `time_flow_start_ns`, `time_flow_end_ns` |
| sequence | `SequenceNum` | `uint32` | `sequence_num` |
| sampling rate | `SamplingRate` | `uint64` | `sampling_rate` |
| sampler/exporter address | `SamplerAddress` | `[]byte` (4 or 16) | `sampler_address` |
| counters | `Bytes`, `Packets` | `uint64` | `bytes`, `packets` |
| addresses | `SrcAddr`, `DstAddr` | `[]byte` (4 or 16) | `src_addr`, `dst_addr` |
| ethertype (v4 vs v6) | `Etype` | `uint32` (0x800 / 0x86dd) | `etype` |
| IP protocol | `Proto` | `uint32` | `proto` |
| L4 ports | `SrcPort`, `DstPort` | `uint32` | `src_port`, `dst_port` |
| TCP flags | `TcpFlags` | `uint32` | `tcp_flags` |
| interfaces | `InIf`, `OutIf` | `uint32` | `in_if`, `out_if` |
| obs domain | `ObservationDomainId` | `uint32` | `observation_domain_id` |

(Also available: `SrcMac`/`DstMac uint64`, `SrcVlan`/`DstVlan`/`VlanId`, `IpTos`,
`ForwardingStatus`, `IpTtl`, `IpFlags`, `IcmpType`/`IcmpCode`, `Ipv6FlowLabel`,
`FragmentId`/`FragmentOffset`, `SrcAs`/`DstAs`, `NextHop []byte`, `NextHopAs`,
`SrcNet`/`DstNet` (mask lengths), `BgpNextHop`, `BgpCommunities`, `AsPath`,
`MplsTtl/MplsLabel/MplsIp`, `LayerStack`/`LayerSize`.)

### Where each protocol's values come from

- **sFlow v5** (`producer/proto/producer_sf.go`): only `FlowSample` and
  `ExpandedFlowSample` are converted (counter & drop samples are ignored by this
  producer). `SamplingRate = uint64(flowSample.SamplingRate)` — **directly from the
  sample header, always populated**. `SamplerAddress = packet.AgentIP` (the **sFlow
  agent IP from the datagram, not the UDP source**). `Packets = 1`,
  `Bytes = FrameLength` (raw header record) or `Length` (sampled IPv4/IPv6 record).
  `TimeFlowStartNs = TimeFlowEndNs = TimeReceivedNs` (sFlow has no flow duration).
  If the record is `SampledHeader` (FLOW_TYPE_RAW), the embedded Ethernet frame is
  parsed by the packet mapper to fill addresses/ports/flags.
- **NetFlow v5** (`producer_nflegacy.go`): `SamplingRate = packet.SamplingInterval & 0x3FFF`
  — **from the packet header, always populated** (0 if unsampled).
  Times from `UnixSecs/UnixNSecs` minus `SysUptime - First/Last` (ms). `SamplerAddress`
  is set by `ProtoProducer.Produce` enrichment to `args.SamplerAddress` (UDP src IP).
- **NetFlow v9 / IPFIX** (`producer_nf.go` → `ProcessMessageNetFlowV9Config` /
  `ProcessMessageIPFIXConfig`): `SamplingRate` is **NOT in data records**. It is scraped
  from **options data records** via `SearchNetFlowOptionDataSets`, which probes option
  fields in order **305 (`samplingPacketInterval`), 50 (`samplerRandomInterval`),
  34 (`samplingInterval`)** and caches the value in the `SamplingRateSystem` keyed by
  `(version, obsDomainId)`; the system itself is held per exporter IP
  (`args.Src.Addr().String()`). **Until an options-data packet arrives,
  `GetSamplingRate` errors and `SamplingRate` stays 0.** If your exporters never send
  sampling options (or sampling lives in a scope you don't parse), pass
  `func() protoproducer.SamplingRateSystem { return &protoproducer.SingleSamplingRateSystem{Sampling: N} }`.
  v9 times: `FIRST_SWITCHED/LAST_SWITCHED` sysuptime deltas against
  `UnixSeconds`/`SystemUptime`; IPFIX times: `flowStart/End{Seconds,Milliseconds,
  Microseconds,Nanoseconds,DeltaMicroseconds}`, defaulting both to `ExportTime` when the
  template has no timing fields. `SamplerAddress` = UDP source IP (enrichment).
  `ObservationDomainId` = `SourceId` (v9) / `ObservationDomainId` (IPFIX).

**Important**: `ProtoProducer.Produce` unconditionally calls `p.cfg.GetFormatter()` — a
nil `ProtoProducerConfig` interface will nil-panic. Always pass a compiled config, e.g.
`(&protoproducer.ProducerConfig{}).Compile()` (a nil `*ProducerConfig` receiver is also
explicitly handled by `Compile`/`mapConfig`).

---

## 4. NetFlow v9 / IPFIX template handling

`github.com/netsampler/goflow2/v2/decoders/netflow` (templates.go):

```go
var ErrorTemplateNotFound = fmt.Errorf("Error template not found")

type NetFlowTemplateSystem interface {
	RemoveTemplate(version uint16, obsDomainId uint32, templateId uint16) (interface{}, error)
	GetTemplate(version uint16, obsDomainId uint32, templateId uint16) (interface{}, error)
	AddTemplate(version uint16, obsDomainId uint32, templateId uint16, template interface{}) error
	GetTemplates() FlowBaseTemplateSet
}

func CreateTemplateSystem() NetFlowTemplateSystem   // in-memory map + RWMutex
```

- Key = `(version<<48) | (obsDomainId<<16) | templateId` in a `map[uint64]interface{}`.
  Stored values are `TemplateRecord`, `NFv9OptionsTemplateRecord`, or
  `IPFIXOptionsTemplateRecord`.
- `NetFlowPipe` creates one template system per **source `ip:port` string** via
  `PipeConfig.NetFlowTemplater` (`templates.TemplateSystemGenerator func(key string) NetFlowTemplateSystem`).
  Templates are **in-memory only and lost on restart**; until each exporter re-sends
  templates, data records cannot be decoded. (To persist, implement
  `NetFlowTemplateSystem` yourself and plug it in via `NetFlowTemplater`.)
- **Data before template**: in `DecodeMessageCommonFlowSet`, a data set
  (`fsheader.Id >= 256`) whose template is missing is kept as
  `netflow.RawFlowSet{FlowSetHeader, Records []byte}` in `packet.FlowSets`, and the error
  `&FlowError{version, "Decode", obsDomainId, templateId, ErrorTemplateNotFound}` is
  produced. `DecodeMessageCommon` does **not abort** on template-not-found: it
  `errors.Join`s those and keeps decoding remaining flow sets (any other error aborts).
  The joined error bubbles up wrapped as `&DecoderError{"NetFlowV9"|"IPFIX", err}`, so
  **`errors.Is(err, netflow.ErrorTemplateNotFound)` works through the whole chain**
  (DecoderError → joined → FlowError all implement `Unwrap`).
- **Pipe behavior on that error**: `NetFlowPipe.DecodeFlow` returns
  `&PipeMessageError{...}` *before calling Produce* — so a packet containing both
  known and unknown templates produces **no flow messages at all** for that packet (the
  templates in it are still registered). If you write your own decode path you can choose
  to call `Produce` anyway when `errors.Is(err, netflow.ErrorTemplateNotFound)`, since
  `packet.FlowSets` still contains all decodable `DataFlowSet`s.
- Template flow set IDs: v9 templates=0, v9 options templates=1, IPFIX templates=2,
  IPFIX options templates=3, data ≥256; anything else → `"ID error"`.

---

## 5. Error handling / panics

- Every decoder returns typed, unwrappable errors — no panics in the decoders themselves,
  and they carry DDoS guards (sFlow: max 1000 samples, 1000 records per sample, 1000-entry
  AS path/communities; NetFlow: negative-length checks; truncation →
  `io.ErrUnexpectedEOF` from `decoders/utils.BinaryRead`).
  - sFlow: `*sflow.DecoderError{Err}`, `*sflow.FlowError{Format, Seq, Err}`,
    `*sflow.RecordError{DataFormat, Err}`.
  - NetFlow v9/IPFIX: `*netflow.DecoderError{Decoder string, Err}`,
    `*netflow.FlowError{Version, Type, ObsDomainId, TemplateId, Err}`,
    sentinel `netflow.ErrorTemplateNotFound`.
  - NetFlow v5: `*netflowlegacy.DecoderError{Err}`.
  - Pipes: `*utils.PipeMessageError{Message, Err}`; receiver workers wrap everything in
    `*utils.ReceiverError{Err}` before pushing to `Errors()`.
- The **producers can panic** on adversarial input (notably the packet parser used for
  sFlow raw headers / IPFIX dataLinkFrameSection); the goflow2 CLI defensively wraps with
  `github.com/netsampler/goflow2/v2/utils/debug`:
  `debug.PanicDecoderWrapper(decodeFunc) utils.DecoderFunc` and
  `debug.WrapPanicProducer(producer.ProducerInterface) producer.ProducerInterface`, which
  `recover()` and yield `*debug.PanicErrorMessage` (`errors.Is(err, debug.ErrPanic)`).
  Do the same in library mode.
- Useful classifications when draining `recv.Errors()` (mirrors cmd/goflow2/main.go):
  `errors.Is(err, net.ErrClosed)` (socket closed during Stop — ignore),
  `errors.Is(err, netflow.ErrorTemplateNotFound)` (warm-up noise — rate-limit log),
  `errors.Is(err, debug.ErrPanic)` (bug — log with stacktrace).

---

## 6. Minimal complete sketch (two ports → channel of custom structs)

```go
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	flowpb "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/producer"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/utils"
	"github.com/netsampler/goflow2/v2/utils/debug"
)

// Flow is our internal representation. Plain values only — no aliased []byte.
type Flow struct {
	Proto        string // "sflow" | "nfv5" | "nfv9" | "ipfix"
	TimeReceived time.Time
	Start, End   time.Time
	Sampler      netip.Addr
	SrcAddr      netip.Addr
	DstAddr      netip.Addr
	IPProto      uint8
	SrcPort      uint16
	DstPort      uint16
	Bytes        uint64
	Packets      uint64
	TCPFlags     uint8
	SamplingRate uint64
	InIf, OutIf  uint32
}

func flowType(t flowpb.FlowMessage_FlowType) string {
	switch t {
	case flowpb.FlowMessage_SFLOW_5:
		return "sflow"
	case flowpb.FlowMessage_NETFLOW_V5:
		return "nfv5"
	case flowpb.FlowMessage_NETFLOW_V9:
		return "nfv9"
	case flowpb.FlowMessage_IPFIX:
		return "ipfix"
	}
	return "unknown"
}

// channelProducer wraps the proto producer: convert (deep copy!) -> push to channel.
// Produce is called concurrently by every receiver worker; chan send is safe.
type channelProducer struct {
	inner producer.ProducerInterface
	out   chan<- Flow
}

func (c *channelProducer) Produce(msg interface{}, args *producer.ProduceArgs) ([]producer.ProducerMessage, error) {
	set, err := c.inner.Produce(msg, args) // err may coexist with partial results
	for _, m := range set {
		pm, ok := m.(*protoproducer.ProtoProducerMessage)
		if !ok {
			continue
		}
		src, _ := netip.AddrFromSlice(pm.SrcAddr) // AddrFromSlice copies — required,
		dst, _ := netip.AddrFromSlice(pm.DstAddr) // pm fields alias the pooled UDP buffer
		smp, _ := netip.AddrFromSlice(pm.SamplerAddress)
		f := Flow{
			Proto:        flowType(pm.Type),
			TimeReceived: time.Unix(0, int64(pm.TimeReceivedNs)),
			Start:        time.Unix(0, int64(pm.TimeFlowStartNs)),
			End:          time.Unix(0, int64(pm.TimeFlowEndNs)),
			Sampler:      smp.Unmap(),
			SrcAddr:      src.Unmap(),
			DstAddr:      dst.Unmap(),
			IPProto:      uint8(pm.Proto),
			SrcPort:      uint16(pm.SrcPort),
			DstPort:      uint16(pm.DstPort),
			Bytes:        pm.Bytes,
			Packets:      pm.Packets,
			TCPFlags:     uint8(pm.TcpFlags),
			SamplingRate: pm.SamplingRate,
			InIf:         pm.InIf,
			OutIf:        pm.OutIf,
		}
		select {
		case c.out <- f:
		default: // drop on backpressure; count it in real code
		}
	}
	return set, err // return the original set so Commit recycles pooled messages
}

func (c *channelProducer) Commit(set []producer.ProducerMessage) { c.inner.Commit(set) }
func (c *channelProducer) Close()                                { c.inner.Close() }

func main() {
	flows := make(chan Flow, 65536)

	// Proto producer with an empty (default) mapping config. Never pass a nil config.
	cfg, err := (&protoproducer.ProducerConfig{}).Compile()
	if err != nil {
		slog.Error("compile", "err", err)
		os.Exit(1)
	}
	inner, err := protoproducer.CreateProtoProducer(cfg, protoproducer.CreateSamplingSystem)
	if err != nil {
		slog.Error("producer", "err", err)
		os.Exit(1)
	}
	var flowProducer producer.ProducerInterface = &channelProducer{inner: inner, out: flows}
	flowProducer = debug.WrapPanicProducer(flowProducer) // panics -> errors

	// One pipe per protocol family. Format/Transport nil => producer-only mode.
	sfPipe := utils.NewSFlowPipe(&utils.PipeConfig{Producer: flowProducer})
	nfPipe := utils.NewNetFlowPipe(&utils.PipeConfig{Producer: flowProducer})

	// One receiver per port.
	mkRecv := func() *utils.UDPReceiver {
		r, err := utils.NewUDPReceiver(&utils.UDPReceiverConfig{
			Sockets:   2,       // SO_REUSEPORT listeners
			Workers:   4,       // concurrent decode goroutines
			QueueSize: 1000000, // 0 would mean an UNBUFFERED dispatch channel
		})
		if err != nil {
			slog.Error("receiver", "err", err)
			os.Exit(1)
		}
		return r
	}
	sfRecv, nfRecv := mkRecv(), mkRecv()

	if err := sfRecv.Start("", 6343, debug.PanicDecoderWrapper(sfPipe.DecodeFlow)); err != nil {
		slog.Error("start sflow", "err", err)
		os.Exit(1)
	}
	if err := nfRecv.Start("", 2055, debug.PanicDecoderWrapper(nfPipe.DecodeFlow)); err != nil {
		slog.Error("start netflow", "err", err)
		os.Exit(1)
	}

	// Drain error channels (non-blocking sender side: unread errors are dropped).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for name, r := range map[string]*utils.UDPReceiver{"sflow": sfRecv, "netflow": nfRecv} {
		go func(name string, r *utils.UDPReceiver) {
			for {
				select {
				case <-ctx.Done():
					return
				case err := <-r.Errors():
					switch {
					case errors.Is(err, net.ErrClosed): // shutdown
					case errors.Is(err, netflow.ErrorTemplateNotFound):
						slog.Warn("data before template", "proto", name)
					case errors.Is(err, debug.ErrPanic):
						slog.Error("recovered panic", "proto", name, "err", err)
					default:
						slog.Error("decode", "proto", name, "err", err)
					}
				}
			}
		}(name, r)
	}

	// Consume flows.
	go func() {
		for f := range flows {
			_ = f // hand off to the rest of the pipeline
		}
	}()

	<-ctx.Done()
	// Shutdown order (mirrors cmd/goflow2): receivers -> pipes -> producer -> sinks.
	_ = sfRecv.Stop() // blocks until socket + worker goroutines exit
	_ = nfRecv.Stop()
	sfPipe.Close()
	nfPipe.Close()
	flowProducer.Close()
	close(flows)
}
```

Fully custom producer variant (skip protobuf entirely): implement
`Produce(msg interface{}, args *producer.ProduceArgs)` and type-switch on
`*sflow.Packet / *netflowlegacy.PacketNetFlowV5 / *netflow.NFv9Packet / *netflow.IPFIXPacket`,
walking `Samples`/`Records`/`FlowSets` yourself (use `protoproducer.SplitNetFlowSets`,
`SplitIPFIXSets`, `DecodeUNumber` as helpers). You then own sampling-rate extraction
(options fields 34/50/305) and v9 uptime time math — for most uses, wrapping the proto
producer as above is far less code.

---

## 7. Metrics hooks (`github.com/netsampler/goflow2/v2/metrics`)

All hooks are Prometheus (`prometheus/client_golang` default registry); expose with
`promhttp.Handler()` yourself.

- `metrics.PromDecoderWrapper(wrapped utils.DecoderFunc, name string) utils.DecoderFunc` —
  wrap each pipe's `DecodeFlow` (the `name` becomes the `type` label, e.g. "sflow"):
  `flow_traffic_bytes_total`, `flow_traffic_packets_total`, `flow_traffic_size_bytes`
  (labels remote_ip/local_ip/local_port/type), `flow_decoding_time_seconds`,
  `flow_decoder_error_total`, and `flow_process_nf_errors_total{error="template_not_found"}`.
- `metrics.NewReceiverMetric() *ReceiverMetric` — set as
  `UDPReceiverConfig.ReceiverCallback`; counts queue drops:
  `flow_dropped_packets_total`, `flow_dropped_bytes_total`.
- `metrics.WrapPromProducer(wrapped producer.ProducerInterface) producer.ProducerInterface` —
  per-packet/per-sample stats: `flow_process_nf_total`, `flow_process_nf_flowset_total`,
  `flow_process_nf_flowset_records_total`, `flow_process_nf_delay_seconds`,
  `flow_process_sf_total`, `flow_process_sf_samples_total`,
  `flow_process_sf_samples_records_total`. (Wrap order in the CLI:
  `WrapPromProducer(WrapPanicProducer(producer))` — Prom on the outside.)
- `metrics.NewDefaultPromTemplateSystem(key string) netflow.NetFlowTemplateSystem` /
  `metrics.NewPromTemplateSystem(key, wrapped)` — set as `PipeConfig.NetFlowTemplater`
  to count templates: `flow_process_nf_templates_total{router,version,obs_domain_id,template_id,type}`.

---

## 8. Gotcha summary

See StructuredOutput list; the load-bearing ones are payload-buffer aliasing (§1.1, §2),
Commit/pool semantics (§3), template-not-found dropping whole packets in `NetFlowPipe`
(§4), v9/IPFIX sampling-rate via options templates only (§3), and `QueueSize: 0`
meaning unbuffered (§1.1).
