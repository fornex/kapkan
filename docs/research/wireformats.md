# NetFlow v9 & sFlow v5 wire formats for goflow2 v2.2.6

Ground truth source (read, not guessed):
`$(go env GOMODCACHE)/github.com/netsampler/goflow2/v2@v2.2.6/`
- `decoders/netflow/{netflow.go,nfv9.go,packet.go,templates.go}`
- `decoders/sflow/{sflow.go,packet.go,datastructure.go}`
- `decoders/utils/utils.go` (BinaryDecoder)
- `producer/proto/{producer_nf.go,producer_sf.go,producer_packet.go}` (field -> FlowMessage mapping)

**Everything is big-endian** (`utils.BinaryDecoder` always uses `binary.BigEndian`). This applies to
both NetFlow v9 and sFlow v5, and to the synthetic Ethernet/IP/L4 header bytes inside sFlow raw records
(network byte order anyway).

---

## 1. NetFlow v9

### 1.1 Packet header (20 bytes, all big-endian)
Decoder: `DecodeMessageVersion` reads `version` first, then `DecodeMessageNetFlow` reads the rest.

| Offset | Size | Field            | Notes |
|--------|------|------------------|-------|
| 0      | 2    | Version = 9      | read by `DecodeMessageVersion`; must be `0x0009` |
| 2      | 2    | Count            | **number of FlowSets** (see gotcha), NOT records |
| 4      | 4    | SystemUptime     | router uptime in **milliseconds** |
| 8      | 4    | UnixSeconds      | export time, seconds; becomes `TimeFlowStart/EndNs` base |
| 12     | 4    | SequenceNumber   | |
| 16     | 4    | SourceId         | = Observation Domain ID; key for template lookup |

After the header come `Count` FlowSets. The decode loop (`DecodeMessageCommon`) for v9 is
`for i := 0; i < int(Count) && payload.Len() > 0; i++`. So Count is literally the number of FlowSets
to read. A template flowset + a data flowset = **Count must be >= 2** to decode both.

### 1.2 FlowSet header (4 bytes) — common to every flowset
Decoder: `DecodeMessageCommonFlowSet` reads `FlowSetHeader{Id uint16, Length uint16}`.

| Size | Field  | Semantics |
|------|--------|-----------|
| 2    | Id     | `0`=Template, `1`=OptionsTemplate, `>=256`=Data (Id == TemplateId) |
| 2    | Length | total bytes of this flowset **including the 4-byte header and any padding** |

`nextrelpos = Length - 4` (= `binary.Size(fsheader)`). Must be `>= 0` or decode errors with
"negative length". The decoder slices exactly `nextrelpos` bytes into a sub-buffer for the body.
=> **Length must be exact** or you eat into/short the next flowset.

### 1.3 Template FlowSet (Id = 0)
Body = one or more Template Records. Loop runs `for payload.Len() >= 4` (lenient: trailing <4 bytes of
padding are ignored).

Template Record:
| Size | Field      | Notes |
|------|------------|-------|
| 2    | TemplateId | **must be >= 256** (used as data FlowSet Id) |
| 2    | FieldCount | number of (type,length) field specifiers that follow |

Then `FieldCount` field specifiers, each 4 bytes:
| Size | Field  |
|------|--------|
| 2    | Type   (information element ID) |
| 2    | Length (bytes the value occupies in each data record) |

NOTE: for v9 (version==9) the PEN/enterprise bit (`Type & 0x8000`) is **only** honored when
version==10 (IPFIX). In v9 templates there is no enterprise number — just type+length pairs.

### 1.4 Data FlowSet (Id >= 256, Id == TemplateId)
Body is parsed with the stored template's fields (`DecodeDataSet` -> `DecodeDataSetUsingFields`).
- Record size = sum of all field `Length`s (`GetTemplateSize`; fields with Length==0xffff are
  variable-length and skipped from the fixed sum).
- Loop: `for payload.Len() >= listFieldsSize` => decoder reads **as many whole records as fit**.
- Each field value is taken as raw bytes via `payload.Next(Length)`; producer later interprets them
  with `DecodeUNumber` (big-endian unsigned, any width 1/2/4/8 or generic <8).

**Padding rule:** the Data FlowSet `Length` should be padded so the flowset ends on a 4-byte boundary
(recommended by RFC 3954). The decoder is lenient about trailing padding because the record loop stops
once `< listFieldsSize` bytes remain — leftover padding bytes are simply ignored. So padding is
optional for goflow2 to decode, but include it to be RFC-correct and to keep `Length` consistent.

### 1.5 Field type numbers goflow2 maps (from `nfv9.go` consts + `producer_nf.go` switch)
These are the canonical IE IDs and they are wired into `ConvertNetFlowDataSet`:

| Field                | Type | Typical len | FlowMessage target |
|----------------------|------|-------------|--------------------|
| IN_BYTES             | 1    | 4 (or 8)    | `Bytes` |
| IN_PKTS              | 2    | 4 (or 8)    | `Packets` |
| PROTOCOL             | 4    | 1           | `Proto` |
| SRC_TOS              | 5    | 1           | `IpTos` |
| TCP_FLAGS            | 6    | 1           | `TcpFlags` |
| L4_SRC_PORT          | 7    | 2           | `SrcPort` |
| IPV4_SRC_ADDR        | 8    | 4           | `SrcAddr` (sets Etype=0x0800) |
| L4_DST_PORT          | 11   | 2           | `DstPort` |
| IPV4_DST_ADDR        | 12   | 4           | `DstAddr` (sets Etype=0x0800) |
| OUT_BYTES            | 23   | 4 (or 8)    | `Bytes` |
| OUT_PKTS             | 24   | 4 (or 8)    | `Packets` |
| IPV6_SRC_ADDR        | 27   | 16          | `SrcAddr` (sets Etype=0x86dd) |
| IPV6_DST_ADDR        | 28   | 16          | `DstAddr` (sets Etype=0x86dd) |
| SAMPLING_INTERVAL    | 34   | 4           | sampling (options only, see below) |
| SAMPLING_ALGORITHM   | 35   | 1           | **NOT used for SamplingRate** anywhere |
| FIRST_SWITCHED       | 22   | 4           | TimeFlowStartNs (uptime-relative) |
| LAST_SWITCHED        | 21   | 4           | TimeFlowEndNs (uptime-relative) |

`addrReplaceCheck` sets `Etype` from the address field, so emitting IPV4_SRC/DST_ADDR is enough to get
`Etype=0x0800`; IPV6_SRC/DST_ADDR yields `0x86dd`.

### 1.6 SamplingRate — VERIFIED in producer mapping
Crucial finding from `producer_nf.go`:

- The **data-record path** (`ConvertNetFlowDataSet`) does **NOT** read field 34 or 35 into
  SamplingRate. There is no `case NFV9_FIELD_SAMPLING_INTERVAL` in that switch. Putting field 34 in a
  normal data record is decoded as a value but **never sets `FlowMessage.SamplingRate`**.
- SamplingRate is set **only** from an **Options Data record**, via
  `SearchNetFlowOptionDataSets(...)`, which probes the OptionsValues for these IE IDs, in order:
  1. `305` (IPFIX samplingPacketInterval)
  2. `50`  (FLOW_SAMPLER_RANDOM_INTERVAL)
  3. `34`  (SAMPLING_INTERVAL)
  First match wins -> `samplingRateSys.AddSamplingRate(9, obsDomainId, rate)` -> applied to every
  message of that obsDomain (SourceId).

So to make goflow2 report a non-zero `SamplingRate` for v9 you MUST emit an **Options Template
(FlowSet Id=1)** + an **Options Data FlowSet** carrying field 34 (or 50/305) in the *options* part.
A plain data record with field 34 will decode fine but SamplingRate stays 0 (or whatever a prior
options packet set for that SourceId).

### 1.7 v9 Options Template FlowSet (Id = 1) layout
Decoder `DecodeNFv9OptionsTemplateSet`, loop `for payload.Len() >= 4`:
| Size | Field        |
|------|--------------|
| 2    | TemplateId (>=256) |
| 2    | ScopeLength  (bytes of scope field specifiers; `sizeScope = ScopeLength/4`) |
| 2    | OptionLength (bytes of option field specifiers; `sizeOptions = OptionLength/4`) |

Then `ScopeLength/4` scope specifiers (4 bytes each: type,len) then `OptionLength/4` option
specifiers (4 bytes each). Scope type 1 = "System".

Options Data FlowSet uses Id == that TemplateId. `DecodeOptionsDataSet` reads
`GetTemplateSize(scopes)+GetTemplateSize(options)` bytes per record, looping while enough bytes remain.
Field 34 must appear in the **options** field list to be found by `NetFlowPopulate(record.OptionsValues, 34, ...)`.

---

## 2. sFlow v5

XDR-style, **all fields uint32 big-endian, 4-byte aligned**.

### 2.1 Datagram header
`DecodeMessageVersion` reads version; `DecodeMessage` reads the rest.

| Size | Field          | Notes |
|------|----------------|-------|
| 4    | Version = 5    | must be `0x00000005` |
| 4    | IP version     | `1`=IPv4 (agent addr 4 bytes), `2`=IPv6 (16 bytes); anything else => error |
| 4/16 | AgentIP        | raw address bytes, length per IP version |
| 4    | SubAgentId     | |
| 4    | SequenceNumber | datagram seq |
| 4    | Uptime         | sysUptime ms |
| 4    | SamplesCount   | number of samples; **> 1000 => hard error** |

Then SamplesCount samples. Loop: `for i < SamplesCount && payload.Len() >= 8`.

### 2.2 Sample header (per sample)
| Size | Field  | Notes |
|------|--------|-------|
| 4    | Format | enterprise(20 bits)<<12 | format(12 bits). For standard flow sample enterprise=0 => **Format = 1** |
| 4    | Length | byte length of the sample body that follows (header excluded). `if Length > payload.Len() { break }` — too-large length silently stops the loop (lenient), so it must be exact-or-smaller |

The decoder slices exactly `Length` bytes into a sub-buffer (`payload.Next(Length)`) and decodes the
sample from that. **Length must cover the whole sample body** (seq + source id + sample fields + all
records incl. their headers and padding) or records get truncated.

Format codes (`sflow.go` consts): `1`=FLOW, `2`=COUNTER, `3`=EXPANDED_FLOW, `4`=EXPANDED_COUNTER,
`5`=DROP.

### 2.3 Flow sample body (Format = 1) — field order
`DecodeSample` first reads `SampleSequenceNumber` (4), then for FLOW/COUNTER reads a packed
`sourceId uint32` (type = `sourceId>>24`, value = `sourceId & 0x00ffffff`). Then for FLOW:

| Size | Field            | Notes |
|------|------------------|-------|
| 4    | SampleSequenceNumber | (read before sourceId) |
| 4    | sourceId (packed type<<24 | value) | |
| 4    | **SamplingRate**     | -> `FlowMessage.SamplingRate` directly (no options dance) |
| 4    | SamplePool       | |
| 4    | Drops            | |
| 4    | Input            | -> `InIf` |
| 4    | Output           | -> `OutIf` |
| 4    | FlowRecordsCount | **> 1000 => hard error** |

Then FlowRecordsCount flow records. (Expanded flow sample, Format=3, splits Input/Output into
format+value pairs: SamplingRate, SamplePool, Drops, InputIfFormat, InputIfValue, OutputIfFormat,
OutputIfValue, FlowRecordsCount.)

`producer_sf.go::SearchSFlowSampleConfig` sets `flowMessage.SamplingRate = flowSample.SamplingRate`
unconditionally for both FlowSample and ExpandedFlowSample, and `Packets = 1`.

### 2.4 Flow record header + raw packet header record (enterprise=0, format=1)
Record loop: `for i < recordsCount && payload.Len() >= 8`.

Record header:
| Size | Field      | Notes |
|------|------------|-------|
| 4    | DataFormat | enterprise<<12 | format. Raw packet header => **1** (`FLOW_TYPE_RAW`) |
| 4    | Length     | body length; sub-buffer sliced; `if Length > payload.Len() { break }` |

Raw packet header body (`SampledHeader`, `DecodeFlowRecord` case `FLOW_TYPE_RAW`):
| Size | Field          | Notes |
|------|----------------|-------|
| 4    | Protocol       | header protocol; **`1` = Ethernet/ISO88023** (only value goflow2 parses into L2/L3/L4) |
| 4    | FrameLength    | original on-wire frame length -> `FlowMessage.Bytes` |
| 4    | Stripped       | bytes stripped (e.g. FCS); informational |
| 4    | OriginalLength | header_length = number of captured header bytes that follow |
| N    | HeaderData     | `payload.Bytes()` — all remaining bytes of the record buffer (NOT bounded by OriginalLength in code) |

Because `HeaderData = payload.Bytes()` (the whole sliced record buffer minus the 16 header bytes),
the **record Length** governs how many header bytes are passed to the packet parser. OriginalLength is
informational for the decoder; keep it == actual header byte count for correctness.

### 2.5 How goflow2 extracts IPs/ports from the raw header
`producer_sf.go::ParseSampledHeaderConfig`: if `Protocol == 1` it calls `DefaultEnvironment.ParsePacket`
(`producer_packet.go::ParsePacket`) starting at `parserEthernet`. The chain (all big-endian, fixed
offsets, length-guarded — too-short layers just stop, no error):

- **Ethernet (14 B):** dst mac[0:6], src mac[6:12], ethertype[12:14]. EtherType `0x0800`->IPv4,
  `0x86dd`->IPv6, `0x8100`->802.1Q (4 B, then inner ethertype), `0x8847`->MPLS.
- **IPv4 (20 B):** proto=data[9] -> `Proto`; src=data[12:16] -> `SrcAddr`; dst=data[16:20] ->
  `DstAddr`; tos=data[1]; ttl=data[8]. Next parser by proto: 6->TCP, 17->UDP, 1->ICMP.
- **IPv6 (40 B):** nextHeader=data[6]; src=data[8:24]; dst=data[24:40].
- **TCP (>=20 B):** src port=data[0:2], dst port=data[2:4], flags=data[13] -> `TcpFlags`.
- **UDP (8 B):** src port=data[0:2], dst port=data[2:4].

So a clean raw record = `Ethernet(14) + IPv4(20) + UDP(8 or TCP 20)` gives SrcAddr/DstAddr/Proto/
SrcPort/DstPort/Etype/TcpFlags. `Bytes` comes from `FrameLength` (set by producer before parsing).

### 2.6 XDR 4-byte alignment (CRITICAL)
Every sFlow opaque (the raw header bytes) **must be padded to a 4-byte boundary**. The record `Length`
field is the unpadded header length, but the bytes on the wire (and the count consumed) must round up
to a multiple of 4. goflow2 slices `payload.Next(Length)` for the record; if you do NOT pad, the next
sample/record header reads from a misaligned offset and decodes garbage / breaks the loop. The test
datagram in `sflow_test.go` uses header_length=78 (0x4e) and appends `0x00 0x00` to reach 80 (a
multiple of 4). Always pad HeaderData with zeros to a multiple of 4, and account for that padding in
the enclosing sample `Length`.

---

## 3. Gotchas (strict vs lenient)

1. **NetFlow v9 `Count` = number of FlowSets, not records.** Loop is `i < Count`. Set Count to the
   number of flowsets you emit (e.g. 2 for template + data). If too low, later flowsets are silently
   dropped; the decoder won't error.
2. **FlowSet `Length` must include the 4-byte flowset header and any padding, and be exact.**
   `nextrelpos = Length-4`; the decoder slices exactly that many bytes. Wrong Length corrupts the next
   flowset. Negative (`Length<4`) => "negative length" error.
3. **Data record decode is lenient on trailing bytes** — record loop stops at `< templateSize`
   remaining, so padding bytes are ignored, but they DO count toward the flowset `Length`.
4. **v9 SamplingRate is options-only.** Field 34/35 in a *data* record never set SamplingRate.
   Use an Options Template (Id=1) + Options Data set with field 34 (or 50, or 305). Field 35
   (SAMPLING_ALGORITHM) is never consulted for the rate.
5. **Template must arrive before (or in same packet, earlier than) the data set.** Data FlowSet with
   no known template returns `ErrorTemplateNotFound`, which `DecodeMessageCommon` treats as non-fatal
   (joins the error but continues) — but you get a RawFlowSet, no decoded values. Put the template
   flowset first in the datagram.
6. **TemplateId must be >= 256** (it doubles as the data FlowSet Id; IDs 0/1 are reserved for template/
   options-template, 2/3 for IPFIX).
7. **sFlow counts are DDoS-guarded:** `SamplesCount > 1000`, `FlowRecordsCount > 1000`,
   `CounterRecordsCount > 1000` => hard errors. Keep counts small/accurate.
8. **sFlow `Length` fields (sample and record) are sliced exactly and `if Length > remaining: break`**
   — too-large length silently truncates the loop (no error but missing data); too-small length cuts
   the body short. Compute them precisely including 4-byte padding.
9. **sFlow XDR 4-byte alignment of the raw header opaque is mandatory** (see 2.6). Misalignment breaks
   all following records/samples.
10. **Only `Protocol == 1` (Ethernet) in a raw record gets L2/L3/L4 parsed.** Other protocol values
    leave SrcAddr/ports empty. The header must start at the Ethernet frame (dst mac first).
11. **Everything big-endian**, including inner IP/TCP/UDP header bytes (network order, which is what you
    want anyway). `binary.BigEndian` throughout.
12. **Address fields auto-set Etype in v9** (`addrReplaceCheck`): emitting IPV4 addr fields => Etype
    0x0800, IPV6 => 0x86dd. No need for a separate ethertype field.

---

## 4. Go code sketches (encoding/binary, big-endian)

### 4.1 NetFlow v9: header + template flowset + 1 data record
Template id 260, 8 fields: IPV4_SRC(8), IPV4_DST(12), L4_SRC(7), L4_DST(11), PROTOCOL(4),
TCP_FLAGS(6), IN_BYTES(1), IN_PKTS(2). Count=2 (template flowset + data flowset).

```go
package flowgen

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

// be is a tiny helper to append big-endian values.
func beU16(b *bytes.Buffer, v uint16) { var t [2]byte; binary.BigEndian.PutUint16(t[:], v); b.Write(t[:]) }
func beU32(b *bytes.Buffer, v uint32) { var t [4]byte; binary.BigEndian.PutUint32(t[:], v); b.Write(t[:]) }

func BuildNetFlowV9() []byte {
	const templateID = 260

	// --- Template FlowSet (Id=0) body: TemplateRecord ---
	tbody := &bytes.Buffer{}
	beU16(tbody, templateID) // TemplateId (>=256)
	beU16(tbody, 8)          // FieldCount
	// (type, length) pairs:
	fields := [][2]uint16{
		{8, 4},  // IPV4_SRC_ADDR
		{12, 4}, // IPV4_DST_ADDR
		{7, 2},  // L4_SRC_PORT
		{11, 2}, // L4_DST_PORT
		{4, 1},  // PROTOCOL
		{6, 1},  // TCP_FLAGS
		{1, 4},  // IN_BYTES
		{2, 4},  // IN_PKTS
	}
	for _, f := range fields {
		beU16(tbody, f[0])
		beU16(tbody, f[1])
	}
	// Template flowset = 4-byte header + body. Body is 4 + 8*4 = 36 -> total 40 (already %4==0).
	tset := &bytes.Buffer{}
	beU16(tset, 0)                          // FlowSet Id = 0 (template)
	beU16(tset, uint16(4+tbody.Len()))      // Length incl. header
	tset.Write(tbody.Bytes())

	// --- Data FlowSet (Id=templateID) body: one record ---
	// record size = 4+4+2+2+1+1+4+4 = 22 bytes
	dbody := &bytes.Buffer{}
	src := netip.MustParseAddr("10.0.0.1").As4()
	dst := netip.MustParseAddr("10.0.0.2").As4()
	dbody.Write(src[:])      // IPV4_SRC_ADDR
	dbody.Write(dst[:])      // IPV4_DST_ADDR
	beU16(dbody, 12345)      // L4_SRC_PORT
	beU16(dbody, 443)        // L4_DST_PORT
	dbody.WriteByte(6)       // PROTOCOL = TCP
	dbody.WriteByte(0x18)    // TCP_FLAGS (PSH+ACK)
	beU32(dbody, 1500)       // IN_BYTES
	beU32(dbody, 3)          // IN_PKTS
	// pad data flowset to 4-byte boundary: header(4)+record(22)=26 -> pad 2 -> 28
	dset := &bytes.Buffer{}
	beU16(dset, templateID)                 // FlowSet Id == TemplateId
	bodyLen := dbody.Len()
	pad := (4 - (4+bodyLen)%4) % 4
	beU16(dset, uint16(4+bodyLen+pad))      // Length incl. header + padding
	dset.Write(dbody.Bytes())
	dset.Write(make([]byte, pad))

	// --- Packet header (Count = number of flowsets = 2) ---
	pkt := &bytes.Buffer{}
	beU16(pkt, 9)            // Version
	beU16(pkt, 2)            // Count = 2 flowsets
	beU32(pkt, 100000)       // SystemUptime (ms)
	beU32(pkt, 1700000000)   // UnixSeconds
	beU32(pkt, 1)            // SequenceNumber
	beU32(pkt, 256)          // SourceId (observation domain)
	pkt.Write(tset.Bytes())  // template first!
	pkt.Write(dset.Bytes())
	return pkt.Bytes()
}
```

To also drive a non-zero SamplingRate, additionally emit an Options Template (FlowSet Id=1) with one
scope (type=1 System, len=4) + one option (type=34 SAMPLING_INTERVAL, len=4), and an Options Data
FlowSet (Id == that template id) whose options value carries the rate. Bump packet Count accordingly.

### 4.2 sFlow v5: 1 flow sample with a raw Ethernet+IPv4+UDP header
```go
package flowgen

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

func BuildSFlowV5() []byte {
	// --- inner raw packet header: Ethernet(14) + IPv4(20) + UDP(8) = 42 bytes ---
	hdr := &bytes.Buffer{}
	// Ethernet
	hdr.Write([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // dst mac
	hdr.Write([]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}) // src mac
	hdr.Write([]byte{0x08, 0x00})                          // ethertype IPv4
	// IPv4 (minimal, 20 bytes, no options)
	hdr.WriteByte(0x45)             // version+IHL
	hdr.WriteByte(0x00)             // DSCP/ECN (tos)
	beU16(hdr, 20+8)                // total length (informational for parser)
	beU16(hdr, 0)                   // id
	beU16(hdr, 0)                   // flags+frag
	hdr.WriteByte(64)               // TTL (offset 8)
	hdr.WriteByte(17)               // proto = UDP (offset 9)
	beU16(hdr, 0)                   // checksum (parser ignores)
	src := netip.MustParseAddr("192.0.2.1").As4()  // offset 12..15
	dst := netip.MustParseAddr("192.0.2.2").As4()  // offset 16..19
	hdr.Write(src[:])
	hdr.Write(dst[:])
	// UDP (8 bytes)
	beU16(hdr, 53000) // src port
	beU16(hdr, 53)    // dst port
	beU16(hdr, 8)     // length
	beU16(hdr, 0)     // checksum
	headerBytes := hdr.Bytes()
	headerLen := len(headerBytes) // 42

	// --- raw flow record (data_format=1) ---
	rec := &bytes.Buffer{}
	beU32(rec, 1)                   // Protocol = 1 (Ethernet) -- REQUIRED for parsing
	beU32(rec, uint32(headerLen))   // FrameLength -> Bytes
	beU32(rec, 0)                   // Stripped
	beU32(rec, uint32(headerLen))   // OriginalLength (== captured header len)
	rec.Write(headerBytes)
	// XDR pad header opaque to 4-byte boundary
	if p := (4 - headerLen%4) % 4; p > 0 {
		rec.Write(make([]byte, p))
	}
	recBody := rec.Bytes()

	recWrapped := &bytes.Buffer{}
	beU32(recWrapped, 1)                   // record DataFormat = 1 (raw packet header)
	beU32(recWrapped, uint32(len(recBody)))// record Length (16 + padded header)
	recWrapped.Write(recBody)

	// --- flow sample body (format=1) ---
	sb := &bytes.Buffer{}
	beU32(sb, 7)                    // SampleSequenceNumber
	beU32(sb, (0<<24)|5)            // sourceId: type=0, value=5 (ifIndex)
	beU32(sb, 1024)                 // SamplingRate -> FlowMessage.SamplingRate
	beU32(sb, 100000)               // SamplePool
	beU32(sb, 0)                    // Drops
	beU32(sb, 5)                    // Input ifIndex
	beU32(sb, 8)                    // Output ifIndex
	beU32(sb, 1)                    // FlowRecordsCount
	sb.Write(recWrapped.Bytes())
	sampleBody := sb.Bytes()

	// --- sample header (format=1) ---
	sample := &bytes.Buffer{}
	beU32(sample, 1)                       // Format = 1 (flow sample)
	beU32(sample, uint32(len(sampleBody))) // Length (whole body)
	sample.Write(sampleBody)

	// --- datagram header ---
	pkt := &bytes.Buffer{}
	beU32(pkt, 5)                   // Version = 5
	beU32(pkt, 1)                   // IP version = 1 (IPv4)
	agent := netip.MustParseAddr("198.51.100.1").As4()
	pkt.Write(agent[:])             // AgentIP (4 bytes)
	beU32(pkt, 0)                   // SubAgentId
	beU32(pkt, 42)                  // SequenceNumber
	beU32(pkt, 123456)              // Uptime
	beU32(pkt, 1)                   // SamplesCount = 1
	pkt.Write(sample.Bytes())
	return pkt.Bytes()
}
```

Both builders use only `encoding/binary` (big-endian) and emit byte sequences that match the structures
goflow2 v2.2.6 decodes in `decoders/netflow` and `decoders/sflow`, with field IDs / format codes the
`producer/proto` mappers recognize to populate SrcAddr/DstAddr/ports/proto/bytes/packets/tcpflags and
SamplingRate.
