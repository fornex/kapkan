#!/usr/bin/env bash
#
# E1 acceptance, on a real kernel: the "protect your own proxy" scene from the
# edge spec (engine/docs/edge-spec.md, milestone E1). A stock nginx sits behind
# a kapkan daemon whose LOCAL XDP data plane meters handshakes and enforces
# source blocks, and this proves the three things E1 promises:
#
#   A. a TLS handshake flood is shed in-kernel while a legit client's handshake
#      still completes            — per-source metering of `tls_client_hello`;
#   B. a QUIC Initial flood is shed the same way, while a non-flooding source's
#      Initial still reaches the socket — per-source metering of `quic_initial`;
#   C. an nginx-reported source is blocked in XDP within ~1s, with a TTL and an
#      audit record — the `kapkan nginx-exporter` -> POST /sources -> XDP path.
#
# Topology (all in netns, one bridge, real distinct source IPs). The attacker
# sits OUTSIDE the protected networks (198.51.100/24, routed via br0) because a
# source block deliberately refuses a source inside `networks` — an internal
# host is a ban, not a source block — which is exactly a real edge attacker:
#
#     legit    203.0.113.2  ─┐  br0 203.0.113.1
#                            ├──────┤          ── vv 203.0.113.10  victim
#     attacker 198.51.100.3 ─┘  br0 198.51.100.1   (nginx + kapkan, XDP on vv)
#
# Build the binary for the container arch first (from engine/), then run this
# inside one privileged debian container on a BPF/XDP-capable kernel — the same
# linuxkit kernel `make dataplane-test` already uses:
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan
#   docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:12-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq \
#              iproute2 nginx openssl curl python3 procps iputils-ping >/dev/null \
#            && KAPKAN=/lab/kapkan bash engine/scripts/labnet/edge-e1.sh'
#
set -uo pipefail
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
KAPKAN=${KAPKAN:-/lab/kapkan}
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
say() { echo; echo "== $1 =="; }

command -v "$KAPKAN" >/dev/null 2>&1 || [ -x "$KAPKAN" ] || { echo "kapkan binary not found at $KAPKAN"; exit 2; }

# A dedicated bpffs mount: on this linuxkit host /sys/fs/bpf is occupied by
# another filesystem, and kapkan rightly refuses to pin onto a non-bpffs path.
BPFFS=/run/kapkan-bpf
PIN="$BPFFS/kapkan-edge"
mkdir -p "$BPFFS"
mountpoint -q "$BPFFS" || mount -t bpf bpf "$BPFFS" || { echo "cannot mount bpffs at $BPFFS"; exit 2; }

cleanup() {
  pkill -f "$KAPKAN" 2>/dev/null
  pkill -f nginx 2>/dev/null
  pkill -f udp-listener 2>/dev/null
  for ns in victim legit attacker; do ip netns del "$ns" 2>/dev/null; done
  ip link del br0 2>/dev/null
}
trap cleanup EXIT
cleanup  # a stale run must never poison a fresh one

# vc REASON -> the packet count kapkan dataplane status reports for that verdict
# (0 when the line is absent). The proof that shedding happened in the KERNEL,
# not in a client's timeout: drop_rl is an emptied token bucket, drop_dyn_src a
# source block.
vc() {
  ip netns exec victim "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null \
    | grep -E "^  $1 " | grep -oE '[0-9,]+ pkts' | grep -oE '[0-9,]+' | tr -d , | head -1
}

# ---------------------------------------------------------------- topology
say "building the netns topology"
sysctl -wq net.ipv4.ip_forward=1
ip link add br0 type bridge
ip addr add 203.0.113.1/24 dev br0
ip addr add 198.51.100.1/24 dev br0   # gateway for the out-of-networks attacker
ip link set br0 up
add_ns() { # name ip cidr gw ; interface is v<first-letter-of-name>
  local ns=$1 ip=$2 cidr=$3 gw=$4 h="v${1:0:1}"
  ip netns add "$ns"
  ip link add "$h" type veth peer name "${h}p"
  ip link set "${h}p" master br0; ip link set "${h}p" up
  ip link set "$h" netns "$ns"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "$ip/$cidr" dev "$h"
  ip netns exec "$ns" ip link set "$h" up
  ip netns exec "$ns" ip route add default via "$gw"
}
add_ns victim   203.0.113.10  24 203.0.113.1    # interface vv — XDP sees inbound client traffic
add_ns legit    203.0.113.2   24 203.0.113.1    # interface vl — inside networks (a real client)
add_ns attacker 198.51.100.3  24 198.51.100.1   # interface va — outside networks (a real attacker)
ip netns exec legit    ping -c1 -W1 203.0.113.10 >/dev/null 2>&1 \
  && ok "legit (in-networks) can reach the victim" \
  || bad "no path legit -> victim (topology broken; nothing below is meaningful)"
ip netns exec attacker ping -c1 -W1 203.0.113.10 >/dev/null 2>&1 \
  && ok "attacker (out-of-networks) can reach the victim across the router" \
  || bad "no routed path attacker -> victim"

# ---------------------------------------------------------------- nginx (stock)
say "starting stock nginx on the victim (TLS 443, kapkan JSON access log)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/edge.key -out /tmp/edge.crt \
  -days 1 -subj "/CN=203.0.113.10" >/dev/null 2>&1
cat > /tmp/nginx.conf <<'CONF'
daemon off;
worker_processes 1;
pid /tmp/nginx.pid;
events { worker_connections 1024; }
http {
  access_log off;
  log_format kapkan escape=json '{"src":"$remote_addr","dst":"$server_addr","status":"$status"}';
  server {
    listen 203.0.113.10:443 ssl;
    ssl_certificate     /tmp/edge.crt;
    ssl_certificate_key /tmp/edge.key;
    access_log /tmp/nginx-access.log kapkan;
    location = /health { return 200 "ok\n"; }
    location / { return 404 "no\n"; }
  }
}
CONF
: > /tmp/nginx-access.log
ip netns exec victim nginx -c /tmp/nginx.conf >/tmp/nginx.log 2>&1 &
for i in $(seq 1 20); do ip netns exec victim ss -ltn 2>/dev/null | grep -q ':443' && break; sleep 0.3; done
ip netns exec legit curl -sk --max-time 5 -o /dev/null -w '%{http_code}' https://203.0.113.10/health 2>/dev/null \
  | grep -q 200 && ok "stock nginx serves a legit TLS request (baseline, no kapkan yet)" \
                || bad "nginx not serving TLS (see /tmp/nginx.log)"

# ---------------------------------------------------------------- brain config, phase 1
# Phase 1 carries the payload-metering rules (arms A and B). Phase 2 swaps to a
# clean config for the source-block arm so the TLS meter cannot choke the very
# flood arm C needs nginx to see and log.
edge_yaml() { # $1 = extra dataplane rules block (may be empty)
cat <<YAML
dry_run: false
listen: { netflow: "127.0.0.1:2055" }
sampling: { default_rate: 1000 }
networks: ["203.0.113.0/24"]
thresholds: { pps: 80000, mbps: 1000, flows_per_sec: 35000 }
ban: { ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50, state_file: /tmp/edge-bans.json }
bgp:
  local_asn: 65010
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65010:666"
  neighbors: [{ address: "127.0.0.2", remote_asn: 65000 }]
dataplane:
  enabled: true
  interfaces: [vv]
  xdp_mode: generic
  pin_path: $PIN
$1
api:
  listen: "127.0.0.1:8080"
  tokens:
    - { name: op, token_env: KAPKAN_API_TOKEN, role: operator }
YAML
}
export KAPKAN_API_TOKEN=optok

start_edge() { # $1 = config path ; waits for the API and XDP attach
  ip netns exec victim "$KAPKAN" -config "$1" -log-format text -log-level info >>/tmp/edge.log 2>&1 &
  for i in $(seq 1 30); do ip netns exec victim curl -s -m1 http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done
}

say "starting the kapkan edge daemon: local XDP on vv, payload metering (pps 3)"
: > /tmp/edge.log
edge_yaml "  ratelimit_profiles:
    - { name: hs, pps: 3 }
    - { name: qs, pps: 3 }
  static_rules:
    - { name: cap_tls, match: { proto: tcp, dst_port: 443, payload: tls_client_hello }, action: ratelimit, profile: hs }
    - { name: cap_quic, match: { proto: udp, dst_port: 443, payload: quic_initial }, action: ratelimit, profile: qs }" > /tmp/edge1.yaml
start_edge /tmp/edge1.yaml

grep -qi "attached" /tmp/edge.log && ok "the daemon attached XDP to vv" || bad "the daemon did not attach XDP (see /tmp/edge.log)"
sc=$(ip netns exec victim "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null | grep -oE 'static +[0-9]+' | grep -oE '[0-9]+' | head -1)
[ "${sc:-0}" -ge 2 ] && ok "dataplane status shows the payload static rules live ($sc encoded slots)" \
                     || bad "dataplane status shows no static rules"

# ================================================================ ARM A: TLS
say "ARM A — TLS handshake flood shed in-kernel, legit unharmed"
before=$(vc drop_rl); before=${before:-0}
# legit: slow (under its own per-source bucket), every handshake must complete.
legit_ok=0
for i in $(seq 1 6); do
  [ "$(ip netns exec legit curl -sk --max-time 4 -o /dev/null -w '%{http_code}' https://203.0.113.10/health 2>/dev/null)" = 200 ] \
    && legit_ok=$((legit_ok+1))
  sleep 0.6
done
# attacker: 60 real TLS handshakes at once — its bucket empties and the rest are
# dropped mid-handshake (the ClientHello never reaches nginx).
: > /tmp/atk.ok
( for i in $(seq 1 60); do
    ( ip netns exec attacker curl -sk --max-time 3 -o /dev/null https://203.0.113.10/health 2>/dev/null && echo x >>/tmp/atk.ok ) &
  done; wait ) & wait $!
atk_ok=$(wc -l </tmp/atk.ok 2>/dev/null | tr -d ' '); atk_ok=${atk_ok:-0}
after=$(vc drop_rl); after=${after:-0}
shed=$((after - before))

[ "$legit_ok" -eq 6 ] && ok "all 6 legit TLS handshakes completed during the flood" \
                      || bad "legit lost handshakes ($legit_ok/6) — the meter is not per-source"
[ "$shed" -ge 1 ]     && ok "the kernel shed $shed attacker ClientHello(s) on an empty bucket (drop_rl)" \
                      || bad "drop_rl did not move — nothing was shed in-kernel"
[ "$atk_ok" -lt 30 ]  && ok "attacker completed only $atk_ok/60 handshakes (throttled to its bucket)" \
                      || bad "attacker completed $atk_ok/60 — the flood was not throttled"

# ================================================================ ARM B: QUIC
say "ARM B — QUIC Initial flood shed in-kernel, a non-flooding source still passes"
cat > /tmp/udp-listener.py <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("203.0.113.10", 443))
open("/tmp/udp.seen", "w").close()
while True:
    _, a = s.recvfrom(2048)
    with open("/tmp/udp.seen", "a") as f:
        f.write(a[0] + "\n")
PY
ip netns exec victim python3 /tmp/udp-listener.py >/tmp/udp-listener.log 2>&1 &
sleep 0.5
cat > /tmp/quicsend.py <<'PY'
import socket, sys, time
n, gap = int(sys.argv[1]), float(sys.argv[2])
# A QUIC v1 Initial: first byte 0xC3 (long header, fixed bit, type Initial),
# version 1, padded toward the 1200-byte floor. Exactly what the matcher reads.
pkt = bytes([0xC3, 0, 0, 0, 1]) + bytes(1195)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(n):
    s.sendto(pkt, ("203.0.113.10", 443))
    if gap:
        time.sleep(gap)
PY
before=$(vc drop_rl); before=${before:-0}
ip netns exec legit    python3 /tmp/quicsend.py 5 0.5    # slow, under the bucket
ip netns exec attacker python3 /tmp/quicsend.py 120 0    # flood
sleep 1
legit_seen=$(grep -c '^203.0.113.2$' /tmp/udp.seen 2>/dev/null); legit_seen=${legit_seen:-0}
atk_seen=$(grep -c '^198.51.100.3$' /tmp/udp.seen 2>/dev/null); atk_seen=${atk_seen:-0}
after=$(vc drop_rl); after=${after:-0}
shed=$((after - before))

[ "$legit_seen" -eq 5 ]  && ok "all 5 legit QUIC Initials reached the socket" \
                         || bad "legit lost Initials ($legit_seen/5) — the meter is not per-source"
[ "$shed" -ge 1 ]        && ok "the kernel shed $shed attacker Initial(s) on an empty bucket (drop_rl)" \
                         || bad "drop_rl did not move for QUIC — nothing was shed"
[ "$atk_seen" -lt 60 ]   && ok "only $atk_seen/120 attacker Initials reached the socket (throttled)" \
                         || bad "attacker landed $atk_seen/120 Initials — not throttled"
pkill -f udp-listener 2>/dev/null

# ================================================================ ARM C: source block
say "ARM C — nginx-reported source blocked in XDP within ~1s, with TTL + audit"
pkill -f "$KAPKAN" 2>/dev/null; sleep 1  # stop phase 1; the pins persist
edge_yaml "  ratelimit_profiles: []
  static_rules: []" > /tmp/edge2.yaml
start_edge /tmp/edge2.yaml
# The exporter tails nginx's log from its END, so start it BEFORE the flood.
: > /tmp/nginx-access.log
ip netns exec victim "$KAPKAN" nginx-exporter \
  -log /tmp/nginx-access.log -api http://127.0.0.1:8080 -token-env KAPKAN_API_TOKEN \
  -victim 203.0.113.10 -window 1s -ttl 30s -rps 5 -min-requests 3 \
  -log-format text -log-level info >/tmp/exporter.log 2>&1 &
sleep 1

before=$(vc drop_dyn_src); before=${before:-0}
t0=$(date +%s.%N)
# attacker: a burst of real (completing) HTTP requests nginx logs as 404s.
( for i in $(seq 1 40); do ip netns exec attacker curl -sk --max-time 3 -o /dev/null https://203.0.113.10/ 2>/dev/null & done; wait ) & wait $!

# Poll for the block to appear as a dynamic rule; record how long it took.
installed=0
for i in $(seq 1 20); do
  dyn=$(ip netns exec victim "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null \
        | grep -oE 'dynamic +[0-9]+' | grep -oE '[0-9]+' | head -1)
  [ "${dyn:-0}" -ge 1 ] && { installed=1; break; }
  sleep 0.25
done
t1=$(date +%s.%N)
latency=$(awk "BEGIN{printf \"%.2f\", $t1-$t0}")

[ "$installed" -eq 1 ] && ok "the exporter's block reached XDP in ${latency}s (dynamic rule live)" \
                       || bad "no dynamic source block installed within 5s"
grep -qi "source_block" /tmp/edge.log && grep -q "198.51.100.3" /tmp/edge.log \
  && ok "the daemon logged a source_block audit event for 198.51.100.3" \
  || bad "no source_block audit record for the attacker (see /tmp/edge.log)"

# Enforcement + scope: the attacker is now dropped in XDP, the legit client is not.
sleep 0.5
atk_code=$(ip netns exec attacker curl -sk --max-time 3 -o /dev/null -w '%{http_code}' https://203.0.113.10/health 2>/dev/null)
legit_code=$(ip netns exec legit curl -sk --max-time 4 -o /dev/null -w '%{http_code}' https://203.0.113.10/health 2>/dev/null)
after=$(vc drop_dyn_src); after=${after:-0}
[ -z "$atk_code" ] || [ "$atk_code" = 000 ] \
  && ok "the blocked attacker is now dropped in XDP (curl got no response)" \
  || bad "attacker still reached nginx (code $atk_code) — the block is not enforcing"
[ "$legit_code" = 200 ] && ok "the legit client is untouched by the block (200)" \
                        || bad "legit was collateral damage (code $legit_code)"
[ "$after" -gt "$before" ] && ok "drop_dyn_src moved (+$((after-before))) — packets dropped by the source block" \
                           || bad "drop_dyn_src did not move — the block matched nothing"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
