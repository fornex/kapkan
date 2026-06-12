# gobgp v3 (library mode) — implementation notes for RTBH announcer

Target: `github.com/osrg/gobgp/v3 v3.37.0`.
Sources read at `$(go env GOMODCACHE)/github.com/osrg/gobgp/v3@v3.37.0`
(= `/Users/fornex/go/pkg/mod/github.com/osrg/gobgp/v3@v3.37.0`).

**Everything below was verified by compiling and running a two-in-process-server
harness against v3.37.0** (sender announces v4 /32 + v6 /128 with communities and
explicit next-hops to a passive receiver over 127.0.0.1; withdraw by UUID, by full
path, and by bare NLRI were all exercised). The harness lives at
`/tmp/gobgp-rtbh-check/main.go` if you want to re-run it.

Module facts:
- One Go module; the proto API is `github.com/osrg/gobgp/v3/api`, Go package name
  `apipb` (import it as `api "github.com/osrg/gobgp/v3/api"`).
- gobgp is NOT yet in kapkan's `go.mod` — add with
  `go get github.com/osrg/gobgp/v3@v3.37.0`. It drags in grpc, logrus,
  `eapache/channels`, `dgryski/go-farm`, `google/uuid`, viper (config defaults), k8s
  apimachinery (dynamic peers), etc. logrus is linked even if you inject your own logger
  (it's referenced by `pkg/log.DefaultLogger`), but it never emits unless used.
- `internal/pkg/table` is internal — you cannot import `table.*`. Everything needed is
  reachable via `pkg/server`, `pkg/apiutil`, `pkg/packet/bgp`, `pkg/log`, `api`.

---

## 1. Core lifecycle API (exact signatures, `pkg/server/server.go`)

```go
func NewBgpServer(opt ...ServerOption) *BgpServer

type ServerOption func(*options)
func GrpcListenAddress(addr string) ServerOption       // e.g. "127.0.0.1:50051"; omit entirely for no gRPC
func GrpcOption(opt []grpc.ServerOption) ServerOption
func LoggerOption(logger log.Logger) ServerOption      // pkg/log.Logger, see §4
func TimingHookOption(hook FSMTimingHook) ServerOption // FSM latency metrics, optional

func (s *BgpServer) Serve()                                                  // BLOCKING event loop; run in goroutine; NEVER returns
func (s *BgpServer) Stop()                                                   // = StopBgp(ctx, &api.StopBgpRequest{}) + grpcServer.Stop()
func (s *BgpServer) StartBgp(ctx context.Context, r *api.StartBgpRequest) error
func (s *BgpServer) StopBgp(ctx context.Context, r *api.StopBgpRequest) error
func (s *BgpServer) AddPeer(ctx context.Context, r *api.AddPeerRequest) error
func (s *BgpServer) DeletePeer(ctx context.Context, r *api.DeletePeerRequest) error   // r.Address = neighbor IP string
func (s *BgpServer) ListPeer(ctx context.Context, r *api.ListPeerRequest, fn func(*api.Peer)) error
func (s *BgpServer) AddPath(ctx context.Context, r *api.AddPathRequest) (*api.AddPathResponse, error) // resp.Uuid: 16 bytes
func (s *BgpServer) DeletePath(ctx context.Context, r *api.DeletePathRequest) error
func (s *BgpServer) ListPath(ctx context.Context, r *api.ListPathRequest, fn func(*api.Destination)) error
func (s *BgpServer) WatchEvent(ctx context.Context, r *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error
func (s *BgpServer) SetLogLevel(ctx context.Context, r *api.SetLogLevelRequest) error
func (s *BgpServer) Log() log.Logger
```

Key mechanics:
- **Every API call is serialized through `s.mgmtCh` and handled inside `Serve()`.**
  If you forget `go s.Serve()`, the first API call blocks forever. The passed `ctx` is
  NOT honored while waiting on the mgmt channel (mgmtOperation ignores it).
- gRPC: `NewBgpServer()` without `GrpcListenAddress` creates **no gRPC server at all**
  (`apiServer == nil`, nothing listens). Perfect for pure library mode.
- `Stop()`: `StopBgp` sends CEASE/peer-deconfigured NOTIFICATION to every neighbor,
  closes the TCP listeners, zeroes global config, and **waits** (via `shutdownWG`)
  until all peer FSM channels drain. It is synchronous and safe to call from main.
  The `Serve()` goroutine itself never exits (infinite `for{reflect.Select}` loop) —
  one goroutine per BgpServer leaks after Stop. Fine for a daemon; in tests just let
  the process exit, don't create servers in a hot loop.

### StartBgpRequest / api.Global (proto `api/gobgp.proto`)

```go
err := s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
    Asn:             65001,           // uint32 — 4-byte ASN natively supported
    RouterId:        "192.0.2.11",    // REQUIRED, must parse as an IP; use IPv4 dotted-quad
    ListenPort:      -1,              // int32: -1 = don't listen at all; 0 = default 179; >0 = that port
    ListenAddresses: []string{"127.0.0.1"}, // optional; default ["0.0.0.0", "::"]
    // Families  []uint32, UseMultiplePaths bool, ApplyPolicy, GracefulRestart, Confederation, BindToDevice...
}})
```

- `RouterId` is validated with `net.ParseIP` and required — there is no default.
  Use a dotted-quad IPv4; internally it's used as 4-byte BGP Identifier via `.To4()`.
- `ListenPort: -1` is the documented way to run a dial-out-only speaker (no root /
  no port-179 capability needed). `0` defaults to 179 (`oc.SetDefaultGlobalConfigValues`).
- StartBgp can only be called once per server ("gobgp is already started" otherwise);
  StopBgp resets `bgpConfig.Global` so in theory restartable, but fresh server per
  lifecycle is the tested path.

### AddPeer / api.Peer

```go
err := s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
    Conf: &api.PeerConf{
        NeighborAddress: "203.0.113.1",
        PeerAsn:         64512,       // uint32; != local ASN ⇒ eBGP automatically (PeerType derived)
        // LocalAsn, Description, AuthPassword (TCP-MD5), AdminDown, Vrf, ...
    },
    Transport: &api.Transport{
        PassiveMode:  false,          // true = never dial, only accept
        RemotePort:   179,            // uint32; dial port — non-standard ports fine (tests use 10179)
        LocalAddress: "",             // source address; defaults 0.0.0.0/:: by neighbor AF
        BindInterface: "",            // SO_BINDTODEVICE (linux)
    },
    Timers: &api.Timers{Config: &api.TimersConfig{
        ConnectRetry:           5,    // uint64 seconds; DEFAULT 120 (!) — lower it for fast reconnect
        HoldTime:               90,   // default 90, keepalive = hold/3
        IdleHoldTimeAfterReset: 5,    // default 30 — time stuck in idle after a reset
    }},
    EbgpMultihop: &api.EbgpMultihop{Enabled: true, MultihopTtl: 2}, // only if peer >1 hop away
    AfiSafis: []*api.AfiSafi{ // see gotcha below — needed to carry v6 over a v4 session
        {Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP,  Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
        {Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
    },
}})
```

- **AfiSafi defaults (verified the hard way):** with no `AfiSafis`, a peer whose
  `NeighborAddress` is IPv4 negotiates **IPv4-unicast only**; IPv6 paths are silently
  not advertised to it (no error from AddPath). To announce both /32s and /128s over
  one IPv4 eBGP session, set both families explicitly **on both ends**
  (`pkg/config/oc/default.go:163`).
- localhost eBGP needs nothing special: no multihop, no TTL security tweaks
  (TTL handling only kicks in via `EbgpMultihop`/`TtlSecurity` if you set them).
- `DeletePeer`: `&api.DeletePeerRequest{Address: "203.0.113.1"}` — sends CEASE and
  drops all paths from that peer.

### WatchEvent (peer state changes)

```go
watchCtx, watchCancel := context.WithCancel(context.Background())
err := s.WatchEvent(watchCtx, &api.WatchEventRequest{
    Peer: &api.WatchEventRequest_Peer{},   // empty struct = subscribe to peer events
    // Table: &api.WatchEventRequest_Table{Filters: ...} for route events (BEST/ADJIN/POST_POLICY/EOR)
}, func(r *api.WatchEventResponse) {
    if p := r.GetPeer(); p != nil && p.Type == api.WatchEventResponse_PeerEvent_STATE {
        st := p.Peer.State // *api.PeerState: NeighborAddress, PeerAsn, SessionState, RouterId...
        if st.SessionState == api.PeerState_ESTABLISHED { ... }
    }
})
```

- Peer event types: `UNKNOWN/INIT/END_OF_INIT/STATE`. On subscribe you immediately get
  one `INIT` event per existing neighbor (with its current state) then `END_OF_INIT`,
  then `STATE` events on every transition — so subscribing late is race-free.
- `SessionState` enum: `UNKNOWN=0 IDLE=1 CONNECT=2 ACTIVE=3 OPENSENT=4 OPENCONFIRM=5 ESTABLISHED=6`.
- The callback runs on a dedicated goroutine that exits **only when `ctx` is
  canceled** — always pass a cancellable context and cancel it on shutdown, otherwise
  the watcher goroutine outlives your interest. Callbacks must not block.
- Alternative to watching: poll `ListPeer(ctx, &api.ListPeerRequest{Address: ip}, fn)`
  and check `peer.State.SessionState` (upstream tests use the WatchEvent approach,
  helper `waitState` in `pkg/server/server_test.go:219`).

---

## 2. AddPath / DeletePath for RTBH paths

### Encoding a community string `"65000:666"`

A standard community is one `uint32`: `asn<<16 | value`.

```go
func community(asn, val uint16) uint32 { return uint32(asn)<<16 | uint32(val) }
// "65000:666" -> 4259840666
// Well-known BLACKHOLE (RFC 7999, 65535:666) is a constant:
//   bgp.COMMUNITY_BLACKHOLE = 0xFFFF029A  (pkg/packet/bgp, type WellKnownCommunity)
// also: bgp.COMMUNITY_NO_EXPORT = 0xFFFFFF01, COMMUNITY_NO_ADVERTISE = 0xFFFFFF02
```

### IPv4 unicast /32 (verified)

```go
import apb "google.golang.org/protobuf/types/known/anypb"

v4 := &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}

nlri, _   := apb.New(&api.IPAddressPrefix{Prefix: "203.0.113.66", PrefixLen: 32})
origin, _ := apb.New(&api.OriginAttribute{Origin: 2})                  // 2 = INCOMPLETE; REQUIRED (see gotchas)
nexthop, _:= apb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})      // explicit discard next-hop
comms, _  := apb.New(&api.CommunitiesAttribute{Communities: []uint32{
    community(65000, 666),
    uint32(bgp.COMMUNITY_BLACKHOLE),
}})

resp, err := s.AddPath(ctx, &api.AddPathRequest{
    // TableType defaults to GLOBAL (0); VrfId "" for global RIB
    Path: &api.Path{
        Family: v4,
        Nlri:   nlri,
        Pattrs: []*apb.Any{origin, nexthop, comms},
    },
})
// resp.Uuid: 16 random bytes (github.com/google/uuid), keep it if you want delete-by-uuid
```

### IPv6 unicast /128 (verified)

```go
v6 := &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}

nlri6, _ := apb.New(&api.IPAddressPrefix{Prefix: "2001:db8::bad", PrefixLen: 128})
mp6, _   := apb.New(&api.MpReachNLRIAttribute{
    Family:   v6,
    NextHops: []string{"100::1"},        // RFC 6666 discard prefix next-hop
    Nlris:    []*apb.Any{nlri6},
})

_, err := s.AddPath(ctx, &api.AddPathRequest{
    Path: &api.Path{
        Family: v6,
        Nlri:   nlri6,                    // top-level Nlri is still required
        Pattrs: []*apb.Any{origin, mp6, comms},
    },
})
```

How the server consumes this (`api2Path`, `pkg/server/grpc_server.go:336`): it
extracts only the **next-hop string** from `NextHopAttribute`/`MpReachNLRIAttribute`
(both are removed from the attr list), then re-synthesizes: IPv4-unicast + v4 nexthop
⇒ `NEXT_HOP` attr; anything else ⇒ a fresh `MP_REACH_NLRI` containing the top-level
NLRI. Consequences:
- Passing `NextHopAttribute{NextHop: "100::1"}` on a v6 path also works (it gets
  converted to MP_REACH). The `MpReachNLRIAttribute` form is just convention.
- Duplicate attribute types are rejected ("duplicated path attribute type").
- A non-withdraw path with no next-hop fails: `"nexthop not found"`.
- A non-withdraw path with no `OriginAttribute` fails inside `fixupApiPath`.

### apiutil alternative (build attrs natively, skip manual anypb)

`pkg/apiutil` has helpers if you prefer constructing `pkg/packet/bgp` native types:

```go
func apiutil.MarshalNLRI(value bgp.AddrPrefixInterface) (*apb.Any, error)
func apiutil.MarshalNLRIs(values []bgp.AddrPrefixInterface) ([]*apb.Any, error)
func apiutil.UnmarshalNLRI(rf bgp.RouteFamily, an *apb.Any) (bgp.AddrPrefixInterface, error)
func apiutil.MarshalPathAttributes(attrList []bgp.PathAttributeInterface) ([]*apb.Any, error)
func apiutil.UnmarshalPathAttributes(values []*apb.Any) ([]bgp.PathAttributeInterface, error)
func apiutil.NewPath(nlri bgp.AddrPrefixInterface, isWithdraw bool,
                     attrs []bgp.PathAttributeInterface, age time.Time) (*api.Path, error)
func apiutil.GetNativeNlri(p *api.Path) (bgp.AddrPrefixInterface, error)          // for reading ListPath results
func apiutil.GetNativePathAttributes(p *api.Path) ([]bgp.PathAttributeInterface, error)
func apiutil.ToRouteFamily(f *api.Family) bgp.RouteFamily
func apiutil.ToApiFamily(afi uint16, safi uint8) *api.Family
```

e.g.

```go
p, _ := apiutil.NewPath(
    bgp.NewIPAddrPrefix(32, "203.0.113.66"), false,
    []bgp.PathAttributeInterface{
        bgp.NewPathAttributeOrigin(2),
        bgp.NewPathAttributeNextHop("192.0.2.1"),
        bgp.NewPathAttributeCommunities([]uint32{community(65000, 666)}),
    }, time.Now())
// p.Family is filled by NewPath; for v6 use bgp.NewIPv6AddrPrefix(128, "2001:db8::bad")
// and bgp.NewPathAttributeMpReachNLRI("100::1", []bgp.AddrPrefixInterface{...})
```

### DeletePath — how a path is identified (verified)

```go
message DeletePathRequest {
  TableType table_type = 1;  string vrf_id = 2;
  Family family = 3;  Path path = 4;  bytes uuid = 5;
}
```

Three modes (`pkg/server/server.go:2358`):
1. **By UUID** (`Uuid: resp.Uuid` from AddPath): looks up an internal
   `uuidMap[pathIdentifier:prefix] -> uuid`, then linear-scans the global RIB for the
   matching local path. Errors `"can't find a specified path"` if unknown/stale.
2. **By Path** (`Path: ...`): NLRI match — family + prefix (+ path identifier). The
   path is converted with `api2Path(..., isWithdraw=true)` and propagated as a
   withdraw; the RIB then removes the local path with the same NLRI. Attribute values
   don't need to match. **Gotcha (verified):** the "nexthop not found" validation
   checks `path.IsWithdraw`, not the function's isWithdraw arg — so either re-send the
   same Pattrs you used in AddPath, or send the bare NLRI with `IsWithdraw: true`:
   ```go
   s.DeletePath(ctx, &api.DeletePathRequest{
       Path: &api.Path{Family: v4, Nlri: nlri, IsWithdraw: true},  // works, verified
   })
   // bare NLRI without IsWithdraw and without next-hop attr => error "nexthop not found"
   ```
3. **Neither Path nor Uuid:** deletes ALL locally generated paths (optionally
   restricted by `Family`). Handy for "withdraw everything" on shutdown.

UUID notes: re-adding the same prefix (same path identifier) overwrites the
`uuidMap` entry — the old UUID silently becomes unusable. Delete-by-UUID is O(RIB).
For an RTBH controller keyed by prefix, delete-by-NLRI (`IsWithdraw: true`) is the
simplest and most robust; UUIDs add nothing.

### Next-hop survival over eBGP (verified)

`internal/pkg/table/path.go: UpdatePathAttrs` — for eBGP peers the next-hop is
rewritten to the session's local address **only when the path is not local or the
next-hop is unspecified**. Locally injected paths (AddPath) with an explicit
next-hop keep it verbatim (verified: receiver saw `192.0.2.1` / `100::1`, not
127.0.0.1). The sender's ASN is automatically prepended to AS_PATH; you do not
add an AsPathAttribute for normal origination.

---

## 3. Two in-process BgpServers peering over localhost (test pattern, verified)

Pattern straight from `pkg/server/server_test.go` (`TestListPathEnableFiltered`):

```go
// receiver ("the router"): listens on a high port, passive
recv := server.NewBgpServer()        // no gRPC
go recv.Serve()
recv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
    Asn: 65002, RouterId: "2.2.2.2", ListenPort: 10179, ListenAddresses: []string{"127.0.0.1"},
}})
recv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
    Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65001},
    Transport: &api.Transport{PassiveMode: true},
    AfiSafis:  bothFamilies, // v4+v6 unicast if the test sends both
}})

// sender ("our RTBH speaker"): no listener, dials the high port
snd := server.NewBgpServer()
go snd.Serve()
snd.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
    Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1,
}})
snd.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
    Conf:      &api.PeerConf{NeighborAddress: "127.0.0.1", PeerAsn: 65002},
    Transport: &api.Transport{RemotePort: 10179},
    Timers:    &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1, IdleHoldTimeAfterReset: 1}},
    AfiSafis:  bothFamilies,
}})
```

- Both speak from 127.0.0.1, distinguished only by who listens. One side MUST be
  `PassiveMode: true` (or `ListenPort: -1` so it can't accept) or both may dial and
  you get collision churn; upstream tests always make the listener passive.
- `ConnectRetry: 1, IdleHoldTimeAfterReset: 1` make tests fast (defaults 120/30 s).
- Wait for ESTABLISHED via the `WatchEvent` helper (subscribe on either server
  **before** adding the second peer to avoid missing the transition — though INIT
  events make late subscription safe too):

```go
func waitEstablished(s *server.BgpServer, ch chan struct{}) {
    watchCtx, cancel := context.WithCancel(context.Background())
    s.WatchEvent(watchCtx, &api.WatchEventRequest{Peer: &api.WatchEventRequest_Peer{}},
        func(r *api.WatchEventResponse) {
            if p := r.GetPeer(); p != nil && p.Type == api.WatchEventResponse_PeerEvent_STATE &&
                p.Peer.State.SessionState == api.PeerState_ESTABLISHED {
                close(ch); cancel()
            }
        })
}
```

- The receiving side asserts on routes with ListPath (propagation is async — poll):

```go
var got []*api.Destination
recv.ListPath(ctx, &api.ListPathRequest{
    TableType: api.TableType_GLOBAL,            // or ADJ_IN with Name: "127.0.0.1"
    Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
}, func(d *api.Destination) { got = append(got, d) })
// d.Prefix == "203.0.113.66/32"; d.Paths[0].Pattrs are []*anypb.Any —
// decode with a.UnmarshalNew() and type-switch on *api.NextHopAttribute /
// *api.CommunitiesAttribute / *api.MpReachNLRIAttribute, or use apiutil.GetNativePathAttributes.
```

- For ADJ_IN/ADJ_OUT, `ListPathRequest.Name` is the neighbor address.
- Teardown: `defer s.StopBgp(ctx, &api.StopBgpRequest{})` per server (what upstream
  tests do), or `s.Stop()`. Expect one leaked `Serve` goroutine per server — harmless
  in tests that end with the process; use unique ports per test if running parallel.

---

## 4. Logger integration (pkg/log)

```go
// pkg/log/logger.go
type LogLevel uint32
const (PanicLevel LogLevel = iota; FatalLevel; ErrorLevel; WarnLevel; InfoLevel; DebugLevel; TraceLevel)
type Fields map[string]interface{}

type Logger interface {
    Panic(msg string, fields Fields)
    Fatal(msg string, fields Fields)
    Error(msg string, fields Fields)
    Warn(msg string, fields Fields)
    Info(msg string, fields Fields)
    Debug(msg string, fields Fields)
    SetLevel(level LogLevel)
    GetLevel() LogLevel
}
```

- Default (when no `LoggerOption`) is `log.NewDefaultLogger()` = a fresh
  `logrus.New()` writing text to stderr at Info level. **Passing `LoggerOption`
  replaces it entirely — that's how you silence/redirect logrus**; there is no other
  global logrus hook to worry about.
- gobgp calls `GetLevel()` to skip building expensive Debug fields, so implement it
  honestly. `SetLevel` is only invoked via the `SetLogLevel` API.
- Verified slog adapter:

```go
type slogLogger struct{ l *slog.Logger; level log.LogLevel }

func (s *slogLogger) kv(f log.Fields) []any {
    out := make([]any, 0, len(f)*2)
    for k, v := range f { out = append(out, k, v) }
    return out
}
func (s *slogLogger) Panic(m string, f log.Fields) { s.l.Error(m, s.kv(f)...); panic(m) }
func (s *slogLogger) Fatal(m string, f log.Fields) { s.l.Error(m, s.kv(f)...); os.Exit(1) }
func (s *slogLogger) Error(m string, f log.Fields) { s.l.Error(m, s.kv(f)...) }
func (s *slogLogger) Warn(m string, f log.Fields)  { s.l.Warn(m, s.kv(f)...) }
func (s *slogLogger) Info(m string, f log.Fields)  { s.l.Info(m, s.kv(f)...) }
func (s *slogLogger) Debug(m string, f log.Fields) { s.l.Debug(m, s.kv(f)...) }
func (s *slogLogger) SetLevel(lv log.LogLevel)     { s.level = lv } // optionally map to a slog.LevelVar
func (s *slogLogger) GetLevel() log.LogLevel       { return s.level }
```

(gobgp's own Fatal usage is rare — failed gRPC listen, config file errors; an
`os.Exit` there matches upstream semantics, or log-and-continue if you prefer.)

---

## 5. Gotchas

1. **`go s.Serve()` is mandatory before any API call** — all calls funnel through an
   internal mgmt channel processed by Serve; without it everything deadlocks. The ctx
   you pass to API calls is ignored while queued.
2. **`Serve()` never returns.** `Stop()`/`StopBgp()` shuts BGP down cleanly (CEASE to
   peers, listeners closed, waits for FSM drain) but the Serve goroutine stays parked
   forever. One leak per server instance; don't churn BgpServers in a loop.
3. **No gRPC by default** — only `GrpcListenAddress(...)` creates a gRPC server. Pure
   library mode needs no port at all (with `ListenPort: -1`, zero sockets).
4. **`OriginAttribute` is mandatory** on every announced path (checked in
   `fixupApiPath`); omitting it fails AddPath. Use Origin 2 (INCOMPLETE) for RTBH.
5. **Explicit next-hop survives eBGP only because the path is local** — gobgp rewrites
   next-hop to the session local address for non-local or unspecified next-hops. Your
   192.0.2.1/100::1 discard next-hops pass through verbatim (verified on the wire).
6. **IPv6 over an IPv4 session needs explicit `AfiSafis` on both peers**; default for
   an IPv4 neighbor is IPv4-unicast only, and AddPath of a v6 route succeeds silently
   without advertising anything.
7. **DeletePath by bare NLRI errors "nexthop not found" unless `IsWithdraw: true`**
   is set on the Path (validation bug-ish: it checks the field, not the internal
   withdraw flag). Recommended withdraw:
   `DeletePath(ctx, {Path: {Family, Nlri, IsWithdraw: true}})` — attrs not needed.
8. **AddPath UUIDs go stale on re-add**: announcing the same prefix again replaces the
   uuidMap entry; the old UUID then returns "can't find a specified path". Delete-by-
   UUID also scans the whole RIB. Prefer delete-by-NLRI; treat prefix as the key.
9. **Default timers are slow for tests/failover**: ConnectRetry 120 s, IdleHoldAfterReset
   30 s, HoldTime 90 s. Set `Timers.Config.ConnectRetry`/`IdleHoldTimeAfterReset` to 1–5 s.
10. **ASN/RouterId**: `Asn` is uint32 (4-byte ASNs native, capability automatic);
    `RouterId` is required, no default, must be IPv4 dotted-quad (an IPv6 string passes
    the `net.ParseIP` check but breaks `.To4()` use downstream).
11. **WatchEvent callback goroutine lives until its ctx is canceled** — keep the cancel
    func and call it on shutdown. Don't block in the callback (it's called inline from
    the event fan-out goroutine).
12. **`ListPath`/`ListPeer` callbacks run synchronously** after an internal snapshot;
    they're cheap to call, fine for polling, and don't hold server locks during fn.
13. On macOS dev machines the TCP listener may trigger the firewall prompt once when
    using a real `ListenPort`; `127.0.0.1`-bound listeners (set `ListenAddresses`)
    avoid it.

---

## 6. Minimal verified sketch (announce → withdraw → stop)

This compiled and ran against v3.37.0 (full harness incl. the test receiver:
`/tmp/gobgp-rtbh-check/main.go`).

```go
package main

import (
    "context"
    "fmt"
    "time"

    api "github.com/osrg/gobgp/v3/api"
    "github.com/osrg/gobgp/v3/pkg/packet/bgp"
    "github.com/osrg/gobgp/v3/pkg/server"
    apb "google.golang.org/protobuf/types/known/anypb"
)

func community(asn, val uint16) uint32 { return uint32(asn)<<16 | uint32(val) }

func main() {
    ctx := context.Background()

    s := server.NewBgpServer(server.LoggerOption(newSlogAdapter())) // §4; no gRPC, no sockets yet
    go s.Serve()

    if err := s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
        Asn:        65001,
        RouterId:   "192.0.2.11",
        ListenPort: -1, // dial-out only
    }}); err != nil {
        panic(err)
    }

    // watch peer state (cancel on shutdown)
    watchCtx, watchCancel := context.WithCancel(ctx)
    defer watchCancel()
    _ = s.WatchEvent(watchCtx, &api.WatchEventRequest{Peer: &api.WatchEventRequest_Peer{}},
        func(r *api.WatchEventResponse) {
            if p := r.GetPeer(); p != nil && p.Type == api.WatchEventResponse_PeerEvent_STATE {
                fmt.Printf("peer %s -> %s\n", p.Peer.State.NeighborAddress, p.Peer.State.SessionState)
            }
        })

    // one eBGP neighbor (v4+v6 unicast over the v4 session)
    if err := s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
        Conf:   &api.PeerConf{NeighborAddress: "203.0.113.1", PeerAsn: 64512},
        Timers: &api.Timers{Config: &api.TimersConfig{ConnectRetry: 5, IdleHoldTimeAfterReset: 5}},
        AfiSafis: []*api.AfiSafi{
            {Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
            {Config: &api.AfiSafiConfig{Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}, Enabled: true}},
        },
    }}); err != nil {
        panic(err)
    }

    // announce 203.0.113.66/32 with 65000:666 + BLACKHOLE, next-hop 192.0.2.1
    v4 := &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}
    nlri, _ := apb.New(&api.IPAddressPrefix{Prefix: "203.0.113.66", PrefixLen: 32})
    origin, _ := apb.New(&api.OriginAttribute{Origin: 2})
    nh, _ := apb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
    comm, _ := apb.New(&api.CommunitiesAttribute{Communities: []uint32{
        community(65000, 666), uint32(bgp.COMMUNITY_BLACKHOLE),
    }})
    if _, err := s.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{
        Family: v4, Nlri: nlri, Pattrs: []*apb.Any{origin, nh, comm},
    }}); err != nil {
        panic(err)
    }

    time.Sleep(time.Minute) // ... mitigation window ...

    // withdraw by NLRI (no attrs needed, IsWithdraw required)
    if err := s.DeletePath(ctx, &api.DeletePathRequest{Path: &api.Path{
        Family: v4, Nlri: nlri, IsWithdraw: true,
    }}); err != nil {
        panic(err)
    }

    // clean shutdown: withdraws + CEASE notifications + listener close, synchronous
    s.Stop() // (Serve goroutine remains parked; process exit reclaims it)
}
```

For the IPv6 /128: same shape with
`api.IPAddressPrefix{Prefix: "2001:db8::bad", PrefixLen: 128}`, family AFI_IP6, and
`api.MpReachNLRIAttribute{Family: v6, NextHops: []string{"100::1"}, Nlris: []*apb.Any{nlri6}}`
in place of `NextHopAttribute` (plus the same Origin/Communities attrs).
