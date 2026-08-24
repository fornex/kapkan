#!/usr/bin/env bash
#
# E2 acceptance, on a real kernel: the "fingerprint plane, off-path" milestone
# from the edge spec (engine/docs/edge-spec.md, milestone E2). The same stock
# nginx behind a kapkan daemon as E1, but here the daemon runs the FINGERPRINT
# plane: the kernel COPIES a bounded, sampled prefix of each TLS ClientHello to
# userspace, userspace computes JA4, and a JA4 on the operator's blocklist turns
# into a source block on the existing XDP path. This proves the two things E2
# promises:
#
#   A. a client whose JA4 is blocklisted is source-blocked in XDP purely from the
#      COPIED ClientHello — nginx never completes or logs the crafted handshake,
#      so nothing on the terminator drove the decision (off-path); the block then
#      enforces (attacker dropped, legit untouched);
#   B. the copy volume stays capped under a ClientHello flood — the per-CPU
#      sampler sheds most copies (fp_throttled) while emitting only a bounded few
#      (fp_emitted), so the plane never becomes its own DoS, and a legit client is
#      served throughout.
#
# The attacker's ClientHello is a fixed, minimal, valid record whose JA4 is known
# ahead of time — computed by engine/internal/fingerprint from these exact bytes,
# so the wire bytes and the blocklisted JA4 cannot drift apart:
#
#   JA4 = t12d020100_62ed6f6ca7ad_000000000000
#         (TLS, no supported_versions -> legacy 1.2, SNI present, 2 ciphers,
#          1 extension (SNI), no ALPN; ciphers 1301,1302; no other exts/sigalgs)
#
# NOTE: a reader-initiated JA4 block is logged and metered but not yet written to
# the audit store (the mitigator has no audit handle from the fp reader — the same
# known source=auto deferral); auditing reader blocks is tracked for E2.4. This
# rig therefore asserts the reader's block log, not an audit record.
#
# Topology (identical to edge-e1.sh): the attacker sits OUTSIDE the protected
# networks (198.51.100/24, routed via br0), because a source block deliberately
# refuses a source inside `networks` — an internal host is a ban, not a source
# block — which is exactly a real edge attacker:
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
#            && KAPKAN=/lab/kapkan bash engine/scripts/labnet/edge-e2.sh'
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
  for ns in victim legit attacker; do ip netns del "$ns" 2>/dev/null; done
  ip link del br0 2>/dev/null
}
trap cleanup EXIT
cleanup  # a stale run must never poison a fresh one

# vc REASON -> the packet count kapkan dataplane status reports for that counter
# (0 when the line is absent). drop_dyn_src is a source block enforcing; the fp_*
# observation counters are the copy sampler: fp_emitted copied to userspace,
# fp_throttled shed by the per-CPU token bucket.
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

# ---------------------------------------------------------------- the attacker's ClientHello
# A fixed, minimal, valid TLS ClientHello whose JA4 the fingerprint library
# computes as t12d020100_62ed6f6ca7ad_000000000000 (see the header). The sender
# opens a TCP connection to :443 and writes just the ClientHello: nginx cannot
# complete the handshake (2 ciphers, an SNI it does not serve) and resets it, but
# the kernel has already COPIED the record off-path — which is the whole point.
cat > /tmp/ja4send.py <<'PY'
import socket, sys, time
n, gap = int(sys.argv[1]), float(sys.argv[2])
ch = bytes.fromhex(
    "160301004701000043030300000000000000000000000000000000000000000000000000000000000000000000041301"
    "13020100001600000012001000000d61747461636b65722e74657374")
for _ in range(n):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("203.0.113.10", 443))
        s.sendall(ch)
        s.close()
    except OSError:
        pass
    if gap:
        time.sleep(gap)
PY

# ---------------------------------------------------------------- brain config
export KAPKAN_API_TOKEN=optok
edge_yaml() { # $1 = the dataplane.fingerprint block (indented under dataplane)
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

start_edge() { # $1 = config path ; waits for the API and XDP attach
  ip netns exec victim "$KAPKAN" -config "$1" -log-format text -log-level info >>/tmp/edge.log 2>&1 &
  for i in $(seq 1 30); do ip netns exec victim curl -s -m1 http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done
}

# ================================================================ ARM A: off-path JA4 block
say "ARM A — a blocklisted JA4 is source-blocked in XDP from the COPIED ClientHello (no terminator)"
: > /tmp/edge.log
edge_yaml "  fingerprint:
    enabled: true
    sample_pps: 200
    block_ttl_seconds: 30
    ja4_blocklist: [\"t12d020100_62ed6f6ca7ad_000000000000\"]" > /tmp/edge-a.yaml
start_edge /tmp/edge-a.yaml
grep -qi "attached" /tmp/edge.log && ok "the daemon attached XDP to vv with the fingerprint plane on" \
                                  || bad "the daemon did not attach XDP (see /tmp/edge.log)"

# No nginx-exporter is running: nothing on the terminator can drive a block here.
before=$(vc drop_dyn_src); before=${before:-0}
: > /tmp/nginx-access.log
t0=$(date +%s.%N)
# The attacker sends its blocklisted ClientHello a handful of times (a fresh
# per-CPU token bucket emits the first copy regardless of the rate). Send in the
# BACKGROUND and poll concurrently: once the block installs, the attacker's own
# later connects are dropped in XDP and hit the socket timeout, so a foreground
# sender's wall-clock would measure those timeouts, not the true install latency.
( ip netns exec attacker python3 /tmp/ja4send.py 8 0.25 ) &
sender=$!

# Poll for the reader's block to appear as a dynamic rule; record how long it took.
installed=0
for i in $(seq 1 40); do
  dyn=$(ip netns exec victim "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null \
        | grep -oE 'dynamic +[0-9]+' | grep -oE '[0-9]+' | head -1)
  [ "${dyn:-0}" -ge 1 ] && { installed=1; break; }
  sleep 0.25
done
t1=$(date +%s.%N)
latency=$(awk "BEGIN{printf \"%.2f\", $t1-$t0}")
kill "$sender" 2>/dev/null; wait "$sender" 2>/dev/null

emitted=$(vc fp_emitted); emitted=${emitted:-0}
[ "$emitted" -ge 1 ] && ok "the kernel copied the attacker's ClientHello off-path ($emitted fp_emitted)" \
                     || bad "fp_emitted did not move — the kernel copied nothing (fingerprint plane off?)"
[ "$installed" -eq 1 ] && ok "the reader's JA4 block reached XDP in ${latency}s (dynamic rule live)" \
                       || bad "no dynamic source block installed within 10s (see /tmp/edge.log)"
grep -qi "source blocked on JA4 fingerprint" /tmp/edge.log && grep -q "198.51.100.3" /tmp/edge.log \
  && ok "the reader logged a JA4 source block for 198.51.100.3" \
  || bad "no JA4 source-block log for the attacker (see /tmp/edge.log)"
# The crux of E2: nginx never completed the crafted handshake, so it logged
# nothing for the attacker — the block came purely from the off-path copy.
atk_logged=$(grep -c '"src":"198.51.100.3"' /tmp/nginx-access.log 2>/dev/null); atk_logged=${atk_logged:-0}
[ "$atk_logged" -eq 0 ] && ok "nginx logged no request from the attacker — the block was off-path, not terminator-driven" \
                        || bad "nginx logged $atk_logged attacker request(s) — the trigger was not purely off-path"

# Enforcement + scope: the attacker is now dropped in XDP, the legit client is not.
sleep 0.5
atk_code=$(ip netns exec attacker curl -sk --max-time 3 -o /dev/null -w '%{http_code}' https://203.0.113.10/health 2>/dev/null)
legit_code=$(ip netns exec legit curl -sk --max-time 4 -o /dev/null -w '%{http_code}' https://203.0.113.10/health 2>/dev/null)
after=$(vc drop_dyn_src); after=${after:-0}
{ [ -z "$atk_code" ] || [ "$atk_code" = 000 ]; } \
  && ok "the blocked attacker is now dropped in XDP (curl got no response)" \
  || bad "attacker still reached nginx (code $atk_code) — the block is not enforcing"
[ "$legit_code" = 200 ] && ok "the legit client (different JA4) is untouched by the block (200)" \
                        || bad "legit was collateral damage (code $legit_code)"
[ "$after" -gt "$before" ] && ok "drop_dyn_src moved (+$((after-before))) — packets dropped by the JA4 source block" \
                           || bad "drop_dyn_src did not move — the block matched nothing"

# ================================================================ ARM B: copy volume capped
say "ARM B — the copy sampler caps volume under a ClientHello flood (no self-DoS)"
pkill -f "$KAPKAN" 2>/dev/null; sleep 1  # restart: sample_pps and an empty blocklist need a fresh attach
: > /tmp/edge.log
# sample_pps 1 with an EMPTY blocklist: nothing gets blocked, so every flooded
# ClientHello reaches the kernel and is either emitted (a bounded few) or
# throttled (the rest) — a clean read of the sampler with no source block in the
# way.
edge_yaml "  fingerprint:
    enabled: true
    sample_pps: 1
    block_ttl_seconds: 30
    ja4_blocklist: []" > /tmp/edge-b.yaml
start_edge /tmp/edge-b.yaml
grep -qi "attached" /tmp/edge.log && ok "the daemon re-attached with the sampler at 1 pps/CPU" \
                                  || bad "the daemon did not re-attach (see /tmp/edge.log)"

FLOOD=300
em0=$(vc fp_emitted);   em0=${em0:-0}
th0=$(vc fp_throttled); th0=${th0:-0}
# Flood in the BACKGROUND and probe the legit client WHILE it runs, so the
# "served throughout" check actually exercises during-flood behaviour (a plane
# that wedged the reader mid-burst but recovered before a foreground flood
# returned would otherwise pass spuriously).
( ip netns exec attacker python3 /tmp/ja4send.py "$FLOOD" 0 ) &
flood=$!
legit_code=$(ip netns exec legit curl -sk --max-time 4 -o /dev/null -w '%{http_code}' https://203.0.113.10/health 2>/dev/null)
wait "$flood" 2>/dev/null
sleep 0.5
em1=$(vc fp_emitted);   em1=${em1:-0}
th1=$(vc fp_throttled); th1=${th1:-0}
emitted=$((em1 - em0)); throttled=$((th1 - th0)); seen=$((emitted + throttled))

[ "$throttled" -ge 100 ] && ok "the sampler shed $throttled of the flood's copies (fp_throttled) — capped, not its own DoS" \
                         || bad "fp_throttled only moved by $throttled under a $FLOOD-CH flood — the sampler is not capping"
[ "$emitted" -ge 1 ] && [ "$emitted" -lt 100 ] \
  && ok "only $emitted copies emitted to userspace (bounded, << $FLOOD sent)" \
  || bad "fp_emitted moved by $emitted — copy volume is not bounded as expected"
[ "$seen" -ge 200 ] && ok "the plane observed $seen of $FLOOD flooded ClientHellos (emitted+throttled)" \
                    || bad "the plane observed only $seen of $FLOOD — packets went missing before the sampler"
[ "$legit_code" = 200 ] && ok "a legit client is served throughout the flood (200) — the plane held up" \
                        || bad "legit failed during the flood (code $legit_code) — the plane self-DoSed"

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
