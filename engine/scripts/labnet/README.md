# network-integration lab

The recipes in [`docs/en/network-integration.mdx`](../../../docs/en/network-integration.mdx)
are executed here before they are written down — the guide never documents a
command that was not run against a real kernel. This directory is that harness.

Two scripts, run in a privileged container on the Docker Desktop linuxkit kernel
(6.12; the same kernel `make dataplane-test` uses):

- **`plumbing.sh`** — the pure-network recipes, no kapkan needed: GRE diversion +
  MSS clamping (with the failure signature — handshakes complete, large responses
  stall), IPIP, L2 bridged insertion, the `rp_filter` asymmetric-return trap, and
  the route-leaking (policy-routing) return path. Each recipe builds a throwaway
  netns topology, asserts the outcome, and tears it down.

  ```sh
  docker run --privileged --rm -v "$PWD:/w" -w /w debian:12-slim \
    sh -c 'apt-get update -qq && apt-get install -y -qq iproute2 iptables \
           iputils-ping curl python3 procps >/dev/null \
           && bash engine/scripts/labnet/plumbing.sh'
  ```

- **`scrub-loop.sh`** — the full control loop on real kernel objects: a kapkan
  brain detects a flowgen attack, escalates to divert toward a managed node, and
  a real `kapkan scrub` agent attaches XDP to a veth and installs the drop rules.
  Needs the `kapkan` and `flowinject` binaries cross-compiled for the container:

  ```sh
  mkdir -p /tmp/lab
  (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan     ./cmd/kapkan)
  (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/flowinject ./scripts/flowinject)
  docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:12-slim \
    sh -c 'apt-get update -qq && apt-get install -y -qq iproute2 curl python3 >/dev/null \
           && KAPKAN=/lab/kapkan FLOWINJECT=/lab/flowinject bash engine/scripts/labnet/scrub-loop.sh'
  ```

  (`GOARCH` matches the host: `arm64` on Apple Silicon, `amd64` elsewhere.)

- **`edge-e1.sh`** — the edge track's E1 acceptance ("protect your own proxy",
  [`engine/docs/edge-spec.md`](../../docs/edge-spec.md)) on real kernel objects: a
  stock nginx behind a kapkan daemon whose **local** XDP data plane meters
  handshakes and enforces source blocks. It proves the three E1 promises end to
  end — a **TLS** ClientHello flood and a **QUIC** Initial flood each shed
  in-kernel per source while a legit client is untouched, and an
  `nginx-exporter`-reported source blocked in XDP within ~1s with a TTL and an
  audit record. The attacker sits *outside* the protected networks on purpose
  (a source inside `networks` is a ban, not a source block). Needs only the
  `kapkan` binary cross-compiled for the container:

  ```sh
  mkdir -p /tmp/lab
  (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan)
  docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:12-slim \
    sh -c 'apt-get update -qq && apt-get install -y -qq \
             iproute2 nginx openssl curl python3 procps iputils-ping >/dev/null \
           && KAPKAN=/lab/kapkan bash engine/scripts/labnet/edge-e1.sh'
  ```

  Unlike the pcap block-rate suite (detector-driven mitigation, replayed
  captures), this exercises the *operator*-driven path — static payload rules
  and the source-block API — with real TLS/QUIC traffic, the one shape the
  block-rate fixtures deliberately do not cover.

- **`edge-e2.sh`** — the edge track's E2 acceptance ("fingerprint plane,
  off-path", [`engine/docs/edge-spec.md`](../../docs/edge-spec.md)) on real
  kernel objects: the same nginx behind a kapkan daemon, but now the kernel
  **copies** a bounded, sampled prefix of each TLS ClientHello to userspace, the
  daemon computes **JA4**, and a blocklisted JA4 becomes a source block on the
  existing XDP path. It proves the E2 promises end to end — (A) a TLS client whose
  JA4 is blocklisted is blocked in XDP purely from the copied ClientHello (nginx
  never completes or logs the crafted handshake, so nothing on the terminator
  drove it — off-path); (B) a **QUIC** v1 Initial is DECRYPTED off-path with keys
  derived from its Destination Connection ID, and its `q…` JA4 blocked the same
  way; and (C) the copy volume stays capped under a ClientHello flood (the per-CPU
  sampler sheds most copies while emitting only a bounded few, so the plane never
  becomes its own DoS). Both the ClientHello and the QUIC Initial are fixed records
  whose JA4 is computed by `engine/internal/fingerprint` from the exact wire bytes,
  so packet and blocklist cannot drift. Same one-binary recipe as E1:

  ```sh
  mkdir -p /tmp/lab
  (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan)
  docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:12-slim \
    sh -c 'apt-get update -qq && apt-get install -y -qq \
             iproute2 nginx openssl curl python3 procps iputils-ping >/dev/null \
           && KAPKAN=/lab/kapkan bash engine/scripts/labnet/edge-e2.sh'
  ```

  A reader-initiated JA4 block is logged, metered, and written to the audit store
  as a `source="auto"` `source_block` record (the app's Blocker adapter attributes
  it to the engine, not an operator). This rig runs with storage disabled (no
  ClickHouse), so it asserts the reader's block log rather than the audit row.

- **`edge-e5.sh`** — the edge track's E5 acceptance ("QUIC/HTTP-3 in earnest",
  [`engine/docs/edge-spec.md`](../../docs/edge-spec.md) §8) with a **real HTTP/3**:
  the E4 rig's topology on **Debian 13** (stock nginx 1.26.3 with the HTTP/3
  module, curl 8.14.1 with HTTP3 — no third-party repository), the brain inside
  the edge netns with its **XDP data plane on the edge's interface** in front of
  nginx's UDP/443, and a second node whose `nginx -V` is wrapped to hide the
  module. Arms A–M of the E5 plan's acceptance table (G, shared ticket keys, is
  absent: E5.6 was cut): per-zone h3 as the slow path and nothing else reloading;
  decisions and the rung over h3; **Retry** seen by `h3probe` and by tcpdump,
  tokens outliving a reload because the host key does; the Initial-rate cap
  shedding a flood in-kernel while a real handshake completes; 0-RTT provably
  off; the **kill lever** (drop UDP/443) with clients back on TCP within a
  second, previewed in dry-run; fail-static across the brain's death and a node
  restart; honest degrade on the wrapped node beside a serving one; h3 vs h2
  p50; MTU 1200 breaking h3 cleanly; the `advertise: false` canary. Needs
  `kapkan`, Pebble and `h3probe` (from `engine/hack/h3probe`, its own module)
  cross-compiled for the container:

  ```sh
  mkdir -p /tmp/lab
  (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan)
  (cd engine/hack/h3probe && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/h3probe .)
  git clone --depth 1 https://github.com/letsencrypt/pebble /tmp/pebble-src \
    && (cd /tmp/pebble-src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/pebble ./cmd/pebble)
  docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:13-slim \
    sh -c 'apt-get update -qq && apt-get install -y -qq \
             iproute2 nginx openssl curl python3 procps iputils-ping ca-certificates tcpdump >/dev/null \
           && KAPKAN=/lab/kapkan PEBBLE=/lab/pebble H3PROBE=/lab/h3probe bash engine/scripts/labnet/edge-e5.sh'
  ```

  The run's logs, rendered configurations and the Retry pcap land in
  `/tmp/lab/logs/`; the recorded h3-vs-h2 figures are the source of the §8
  acceptance paragraph.

- **`edge-e6-anycast.sh`** — the edge track's E6.9 acceptance ("one address,
  many nodes", [`engine/docs/edge-spec.md`](../../docs/edge-spec.md) §8) and the
  transcript behind every command and number in the anycast/ECMP guide. This is
  the first rig with a **real router hop**, because the kernel's
  `fib_multipath_hash_policy` is itself the subject: a `rtr` netns forwards one
  VIP `/32` to two nodes as an ECMP route over two point-to-point legs, and the
  policy is switched per arm. Each node holds the VIP on `lo`, runs stock nginx
  under `unshare -u` so its `$hostname` names the node, and runs its own
  `kapkan edge` with its own state, sockets, pid file and **its own agent token
  bound with `api.tokens[].node`** — the guide asks for one token per node, so
  the rig models exactly that. The brain lives in its own netns and is reached
  only by unicast; the Pebble CA resolves the zone to the VIP, so every HTTP-01
  validation crosses the hash. There is no XDP here — routing and per-node
  ceilings are the subject, not the data plane.

  A request is attributed to the node that served it two ways, each used where
  it is honest: per-node `/metrics`, and `add_header X-Kapkan-Node $hostname
  always;` injected through the zone's `extra_directives_file` (an operator's
  debugging trick, never a product header — and one that does not ride a 429,
  since the render's `@kapkan_denied` declares an `add_header` of its own).

  The arms are the guide's claims: a deterministic **fan-out** (the route pinned
  to one node for the whole issuance, so the other's certificate can only have
  been validated through the challenge the brain fanned out); the two **hash
  forms** (layer 3 pins one client to one node, layer 4 spreads it over both —
  over TCP and over HTTP/3, since the same policy hashes the UDP 4-tuple); the
  **per-node ceilings**, whose L3-vs-L4 shares are recorded because they are the
  guide's "up to N× the ceiling"; a node **dying with nobody withdrawing**, then
  the same node behind a downed link (a dead nexthop needs no operator, a dead
  node does) and the withdrawal as the RIB effect it is, timed; the
  **withdrawal signal** — `/healthz` 503 yes, `converged:false` no, the
  inventory's `alive` no; the brain dead; the two **cross-node facts** (a TLS
  session is not resumable on the other node, a clearance cookie is honoured
  there); and **MTU** 1200 on one leg breaking HTTP/3 for that node's share
  while TCP is untouched. Needs `kapkan` and Pebble cross-compiled for the
  container:

  ```sh
  mkdir -p /tmp/lab
  (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan)
  git clone --depth 1 https://github.com/letsencrypt/pebble /tmp/pebble-src \
    && (cd /tmp/pebble-src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/pebble ./cmd/pebble)
  docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:13-slim \
    sh -c 'apt-get update -qq && apt-get install -y -qq \
             iproute2 nginx openssl curl python3 procps iputils-ping ca-certificates tcpdump util-linux >/dev/null \
           && KAPKAN=/lab/kapkan PEBBLE=/lab/pebble bash engine/scripts/labnet/edge-e6-anycast.sh'
  ```

  `ANYCAST_BGP=1` adds a stretch arm, **outside** the acceptance path, that
  installs bird2 and drives the same withdrawal contract with a real speaker on
  each node, enabled and disabled by a once-a-second `/healthz` probe. The run's
  logs and the recorded numbers land in `/tmp/lab/logs/` (`numbers.txt` and
  `arm-c.txt` are what the guide quotes).

## Never two rigs at once

Each of these scripts owns the whole container's network namespaces, `/etc/hosts`
and its `/tmp`, and several bind privileged ports. Check `docker ps` for a
running privileged `debian:13-slim` before starting one — another session may be
part-way through `edge-e6.sh` — and wait for it to finish.

## VRF

The return-path recipe is verified with **policy routing** (route-leaking:
`ip rule` + a dedicated table), the portable form that works on every kernel
with `CONFIG_IP_MULTIPLE_TABLES`. A VRF *device* gives the same isolation as a
cleaner abstraction on kernels built with `CONFIG_NET_VRF` — which the linuxkit
kernel is not — so the guide presents VRF as a variant of the verified
route-leaking recipe, not as a separately lab-run transcript.
