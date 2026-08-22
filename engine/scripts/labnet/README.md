# network-integration lab

The recipes in [`https://kapkan.io/docs/network-integration`](https://kapkan.io/docs/network-integration)
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

## VRF

The return-path recipe is verified with **policy routing** (route-leaking:
`ip rule` + a dedicated table), the portable form that works on every kernel
with `CONFIG_IP_MULTIPLE_TABLES`. A VRF *device* gives the same isolation as a
cleaner abstraction on kernels built with `CONFIG_NET_VRF` — which the linuxkit
kernel is not — so the guide presents VRF as a variant of the verified
route-leaking recipe, not as a separately lab-run transcript.
