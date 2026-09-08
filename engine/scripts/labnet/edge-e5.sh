#!/usr/bin/env bash
#
# E5 acceptance, on a real kernel with a real nginx and real HTTP/3: QUIC in the
# configuration kapkan renders (engine/docs/edge-spec.md §8, milestone E5), on
# the E4 rig's topology with three changes — the box is Debian 13 (stock nginx
# 1.26.3 with the HTTP/3 module, curl 8.14.1 with HTTP3), the brain runs INSIDE
# the edge netns with its XDP data plane on the edge's interface (in front of
# nginx's UDP/443 — the E1 "protect your own proxy" placement), and a second node
# appears for the honest-degrade arm. The arms map to the acceptance table of the
# E5 plan and to the charter:
#
#   A. per-zone h3, default off; the toggle is the slow path and nothing else
#      reloads: one install, `ss` shows UDP/443, curl --http3-only reaches the
#      zone over HTTP/3 and the origin sees it, the TCP answer carries Alt-Svc
#      and a client with the cache upgrades, the zone that did not ask has no
#      Alt-Svc and refuses QUIC, a rate change moves only the accepted ETag,
#      h3: false is one install after which QUIC is refused, the fleet status
#      names the serving node and counts h3 requests;
#   B. decisions and the rung over h3 exactly as over TCP: 429 + Retry-After,
#      the clearance page, a cleared browser's cookie honoured over h3, a
#      watch-only zone marking would-deny at the origin;
#   C. Retry: on for every h3 zone at the http level, seen on the wire by the
#      instrumented client and by tcpdump (the server's first datagram is a
#      long-header Retry, shorter than the Initial), tokens survive a reload
#      because the host key does, and quic.retry: false turns it off;
#   D. the Initial-rate cap in XDP: a spoofable Initial flood is shed in-kernel
#      before nginx while a legitimate h3 handshake completes; in dry-run the
#      same flood is counted, not dropped;
#   E. 0-RTT is off and provably so: no ssl_early_data rendered, early data is
#      not accepted, and the node reports early_data_capable honestly;
#   F. the kill lever: drop UDP/443 in the data plane and every client is back
#      on TCP within a second; previewed under dry-run; undone;
#   H. fail-static: h3 lives with the brain dead and across a node restart from
#      disk, with the same host key;
#   J. honest degrade on a build without the module (a wrapper hides it from
#      -V): TCP-only render, the comment that says why, the node's report and
#      the fleet status name it — beside a node that serves h3;
#   K. cost: h3 versus h2 p50 to a mode:none and a decide zone (recorded);
#   L. MTU: a path below QUIC's floor breaks h3 cleanly and TCP survives;
#   M. the canary: advertise: false renders the listener without the
#      announcement, then a short ma.
#
# Arm G (shared ticket keys, E5.6) is absent: E5.6 was cut — nginx binds a TLS
# session to the node's certificate through the session id context, so shared
# keys cannot resume across per-node certificates (edge-spec §3).
#
# Build the binaries for the container arch first (from engine/), then run this
# inside one privileged debian:13-slim container (never two rigs at once):
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan
#   (cd hack/h3probe && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/h3probe .)
#   git clone --depth 1 https://github.com/letsencrypt/pebble /tmp/pebble-src \
#     && (cd /tmp/pebble-src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/pebble ./cmd/pebble)
#   docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:13-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq \
#              iproute2 nginx openssl curl python3 procps iputils-ping ca-certificates tcpdump >/dev/null \
#            && KAPKAN=/lab/kapkan PEBBLE=/lab/pebble H3PROBE=/lab/h3probe bash engine/scripts/labnet/edge-e5.sh'
#
set -uo pipefail
export PATH=/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin
KAPKAN=${KAPKAN:-/lab/kapkan}
PEBBLE=${PEBBLE:-/lab/pebble}
H3PROBE=${H3PROBE:-/lab/h3probe}
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
say() { echo; echo "== $1 =="; }
[ -x "$KAPKAN" ] || { echo "kapkan binary not found at $KAPKAN"; exit 2; }
[ -x "$PEBBLE" ] || { echo "pebble binary not found at $PEBBLE"; exit 2; }
[ -x "$H3PROBE" ] || { echo "h3probe binary not found at $H3PROBE"; exit 2; }
# The rig is about HTTP/3: a box whose nginx or curl cannot speak it must fail
# here, loudly, not pass every h3 arm over TCP.
nginx -V 2>&1 | grep -q -- --with-http_v3_module || { echo "this nginx has no http_v3_module: $(nginx -v 2>&1)"; exit 2; }
curl -V | grep -q HTTP3 || { echo "this curl has no HTTP3: $(curl -V | head -1)"; exit 2; }
command -v tcpdump >/dev/null || { echo "tcpdump is required (arm C)"; exit 2; }

EDGE=203.0.113.10; EDGE2=203.0.113.11; BRAIN=203.0.113.20; ORIGIN=203.0.113.30; CA=203.0.113.40
ZONE=shop.test; ZONE2=static.test
STATE=/var/lib/kapkan-edge; SOCKS=/run/kapkan-edge
STATE2=/var/lib/kapkan-edge2; SOCKS2=/run/kapkan-edge2
export KAPKAN_API_TOKEN=optok KAPKAN_EDGE_TOKEN=agenttok

# A dedicated bpffs mount: on this linuxkit host /sys/fs/bpf is occupied by
# another filesystem, and kapkan rightly refuses to pin onto a non-bpffs path.
BPFFS=/run/kapkan-bpf
PIN="$BPFFS/kapkan-e5"
mkdir -p "$BPFFS"
mountpoint -q "$BPFFS" || mount -t bpf bpf "$BPFFS" || { echo "cannot mount bpffs at $BPFFS"; exit 2; }

cleanup() {
  if [ -d /lab ]; then mkdir -p /lab/logs && cp -f /tmp/*.log /tmp/*.out /tmp/*.txt /tmp/*.pcap /tmp/hdr-* /lab/logs/ 2>/dev/null; cp -f /tmp/zones.yaml /tmp/edge.yaml /tmp/edge2.yaml /tmp/brain.yaml /lab/logs/ 2>/dev/null; fi
  kill "$(cat /tmp/brain.pid 2>/dev/null)" "$(cat /tmp/edge-nginx.pid 2>/dev/null)" "$(cat /tmp/edge2-nginx.pid 2>/dev/null)" 2>/dev/null
  pkill -f "^$KAPKAN " 2>/dev/null; pkill -f "^$PEBBLE " 2>/dev/null
  pkill -f '^nginx: master' 2>/dev/null; pkill -f '^python3 /tmp/origin.py' 2>/dev/null
  pkill -f '^python3 /tmp/quicsend.py' 2>/dev/null; pkill -f '^python3 /tmp/browser.py' 2>/dev/null; pkill -f '^tcpdump' 2>/dev/null
  for ns in edge edge2 origin ca legit attacker bursty; do ip netns del "$ns" 2>/dev/null; done
  ip link del br0 2>/dev/null
  sed -i "/ $ZONE\$/d;/ $ZONE2\$/d" /etc/hosts 2>/dev/null
}
trap cleanup EXIT
cleanup

# ---------------------------------------------------------------- topology
say "building the netns topology (brain inside the edge netns, XDP on vedge)"
sysctl -wq net.ipv4.ip_forward=1
ip link add br0 type bridge
ip addr add 203.0.113.1/24 dev br0
ip addr add 198.51.100.1/24 dev br0
ip link set br0 up
add_ns() { # name ip cidr gw ; interface is v<name>
  local ns=$1 ip=$2 cidr=$3 gw=$4 h="v$1"
  ip netns add "$ns"
  ip link add "$h" type veth peer name "${h}p"
  ip link set "${h}p" master br0; ip link set "${h}p" up
  ip link set "$h" netns "$ns"
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "$ip/$cidr" dev "$h"
  ip netns exec "$ns" ip link set "$h" up
  ip netns exec "$ns" ip route add default via "$gw"
}
add_ns edge     $EDGE        24 203.0.113.1
# The brain's address is an alias on the edge's own interface: its XDP program
# on vedge sits in front of everything the edge receives, nginx's UDP/443 first.
ip netns exec edge ip addr add $BRAIN/24 dev vedge
add_ns edge2    $EDGE2       24 203.0.113.1
add_ns origin   $ORIGIN      24 203.0.113.1
add_ns ca       $CA          24 203.0.113.1
add_ns legit    203.0.113.2  24 203.0.113.1
add_ns attacker 198.51.100.3 24 198.51.100.1
add_ns bursty   203.0.113.4  24 203.0.113.1
for i in 5 6 7 8; do ip netns exec bursty ip addr add 203.0.113.$i/24 dev vbursty; done
printf '%s %s\n%s %s\n' "$EDGE" "$ZONE" "$EDGE" "$ZONE2" >> /etc/hosts
ip netns exec legit ping -c1 -W1 $EDGE >/dev/null 2>&1 && ok "legit reaches the edge" || bad "no path legit -> edge (topology broken; nothing below is meaningful)"
ip netns exec legit ping -c1 -W1 $BRAIN >/dev/null 2>&1 && ok "the brain's alias on vedge is reachable" || bad "no path to the brain alias"

# ---------------------------------------------------------------- origin
say "starting the origin (echoes the headers kapkan sets)"
cat > /tmp/origin.py <<'PY'
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        body = json.dumps({"path": self.path, "zone": self.headers.get("X-Kapkan-Zone", ""), "mark": self.headers.get("X-Kapkan-Mark", "")}).encode()
        with open("/tmp/origin.log", "a") as f:
            f.write(body.decode() + "\n")
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_GET(self): self._answer()
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        self._answer()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8081), H).serve_forever()
PY
: > /tmp/origin.log
ip netns exec origin python3 /tmp/origin.py &
for i in $(seq 1 20); do ip netns exec legit curl -s -m1 http://$ORIGIN:8081/ >/dev/null 2>&1 && break; sleep 0.3; done
grep -q '"path"' <<< "$(ip netns exec legit curl -s -m2 http://$ORIGIN:8081/)" && ok "origin answers directly" || bad "origin not answering"

# ---------------------------------------------------------------- Pebble (ACME CA)
say "starting Pebble: a real ACME CA validating HTTP-01 on the edge's :80"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout /tmp/pebble.key -out /tmp/pebble.crt -subj "/CN=pebble" \
  -addext "subjectAltName=IP:$CA" >/dev/null 2>&1
cat > /tmp/pebble.json <<JSON
{ "pebble": { "listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/tmp/pebble.crt", "privateKey": "/tmp/pebble.key",
  "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false } }
JSON
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 ip netns exec ca "$PEBBLE" -config /tmp/pebble.json -strict=false >/tmp/pebble.log 2>&1 &
for i in $(seq 1 30); do ip netns exec edge curl -sk -m1 https://$CA:14000/dir >/dev/null 2>&1 && break; sleep 0.3; done
grep -q newOrder <<< "$(ip netns exec edge curl -sk -m2 https://$CA:14000/dir)" && ok "Pebble directory is up" || bad "Pebble not answering (see /tmp/pebble.log)"

# ---------------------------------------------------------------- the brain
say "starting the brain in the edge netns: zones file, edge block, XDP data plane on vedge"
# zones_yaml H3 ADVERTISE MA CHALLENGE RUNG_DRY ZONE_DRY RPS [ZONE2_H3] — shop.test
# is the h3 zone under test (h3_options only when h3 is on: the file refuses
# them otherwise); static.test is the mode:none zone that never asks, except
# where an arm needs a deciding-vs-none comparison over h3 (ZONE2_H3 true).
zones_yaml() {
  local h3opts="" z2tls=""
  [ "$1" = "true" ] && h3opts="
      h3_options: { advertise: $2, alt_svc_max_age_seconds: $3 }"
  [ "${8:-false}" = "true" ] && z2tls="
    tls: { h3: true }"
cat > /tmp/zones.yaml <<YAML
zones:
  - name: $ZONE
    origins: ["$ORIGIN:8081"]
    tls:
      min_version: "1.2"
      h3: $1$h3opts
    acme: { directory: "https://$CA:14000/dir" }
    policy:
      mode: decide
      failure_mode: open
      dry_run: $6
      challenge: "$4"
      challenge_options:
        dry_run: $5
        difficulty: 12
        cookie_ttl_seconds: 120
        exempt_paths: ["/api/"]
      rate: { rps: $7 }
  - name: $ZONE2
    origins: ["$ORIGIN:8081"]$z2tls
    acme: { directory: "https://$CA:14000/dir" }
    policy: { mode: none }
YAML
}
# brain_yaml DRYRUN RULES — the brain's own dry_run governs the data plane's
# verdicts (drop vs. dryrun_would_drop); RULES is the static_rules/profiles
# block the arms turn on and off.
brain_yaml() {
cat > /tmp/brain.yaml <<YAML
dry_run: $1
listen: { netflow: "127.0.0.1:2055" }
sampling: { default_rate: 1000 }
networks: ["203.0.113.0/24"]
thresholds: { pps: 80000, mbps: 1000, flows_per_sec: 35000 }
ban: { ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50 }
bgp:
  local_asn: 65010
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65010:666"
  neighbors: [{ address: "127.0.0.2", remote_asn: 65000 }]
dataplane:
  enabled: true
  interfaces: [vedge]
  xdp_mode: generic
  pin_path: $PIN
$2
api:
  listen: "$BRAIN:8080"
  tokens:
    - { name: op, token_env: KAPKAN_API_TOKEN, role: operator }
    - { name: edge-agent, token_env: KAPKAN_EDGE_TOKEN, role: agent }
edge:
  zones_file: /tmp/zones.yaml
  state_file: /tmp/edge-state.json
  stale_after_seconds: 5
  nodes:
    - name: edge-1
    - name: edge-2
YAML
}
NO_RULES="  ratelimit_profiles: []
  static_rules: []"
zones_yaml true true 86400 off true false 5
brain_yaml false "$NO_RULES"
start_brain() {
  ip netns exec edge "$KAPKAN" -config /tmp/brain.yaml -log-format text -log-level info -pid-file /tmp/brain.pid >>/tmp/brain.log 2>&1 &
  for i in $(seq 1 40); do ip netns exec edge curl -s -m1 http://$BRAIN:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done
}
brain_api() { ip netns exec edge curl -s -m3 -H "Authorization: Bearer optok" "$@"; }
reload_brain() { ip netns exec edge "$KAPKAN" -s reload -pid-file /tmp/brain.pid >/dev/null 2>&1; sleep 0.7; }
kill_brain() { kill "$(cat /tmp/brain.pid 2>/dev/null)" 2>/dev/null; for i in $(seq 1 30); do ip netns exec edge curl -s -m1 "http://$BRAIN:8080/healthz" >/dev/null 2>&1 || return 0; sleep 0.2; done; return 1; }
# vc REASON -> the packet count the data plane reports for that verdict
vc() {
  ip netns exec edge "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null \
    | grep -E "^  $1 " | grep -oE '[0-9,]+ pkts' | grep -oE '[0-9,]+' | tr -d , | head -1
}
: > /tmp/brain.log
start_brain
code=$(ip netns exec edge curl -s -o /dev/null -w '%{http_code}' -m3 -H "Authorization: Bearer agenttok" "http://$BRAIN:8080/api/v1/edge/zones?node=edge-1")
[ "$code" = "200" ] && ok "brain serves the zones document to the agent" || { bad "brain does not serve the zones document (got '$code')"; tail -15 /tmp/brain.log; }
grep -q '"h3":true' <<< "$(ip netns exec edge curl -s -m3 -H "Authorization: Bearer agenttok" "http://$BRAIN:8080/api/v1/edge/zones?node=edge-1")" && ok "the document carries tls.h3 for $ZONE" || bad "no tls.h3 in the document"
grep -qi "attached" /tmp/brain.log && ok "the brain attached XDP to vedge (in front of nginx's UDP/443)" || bad "the brain did not attach XDP (see /tmp/brain.log)"

# ---------------------------------------------------------------- nginx on the edge
say "starting stock nginx on the edge with kapkan's include"
mkdir -p $STATE/conf
cat > /tmp/edge-nginx.conf <<CONF
daemon off;
user www-data;
worker_processes 1;
pid /tmp/edge-nginx.pid;
error_log /tmp/edge-nginx-error.log warn;
events { worker_connections 1024; }
http {
  access_log off;
  include $STATE/conf/live/*.conf;
}
CONF
ip netns exec edge nginx -c /tmp/edge-nginx.conf >/tmp/edge-nginx.log 2>&1 &
sleep 0.5
pgrep -f 'nginx: master' >/dev/null && ok "nginx master is up ($(nginx -v 2>&1 | grep -oE '[0-9.]+$'))" || bad "nginx did not start (see /tmp/edge-nginx.log)"

# ---------------------------------------------------------------- kapkan edge
# edge_yaml DRYRUN RETRY — the node's watch-only switch and its node-wide QUIC
# Retry (edge.yaml quic.retry; read at start, so a change is a restart).
edge_yaml() {
cat > /tmp/edge.yaml <<YAML
dry_run: $1
controller: { url: "http://$BRAIN:8080", token_env: KAPKAN_EDGE_TOKEN, name: edge-1, report_interval_seconds: 1 }
state_dir: $STATE
sockets_dir: $SOCKS
socket_group: www-data
terminator: { binary: nginx, main_conf: /tmp/edge-nginx.conf, reload: exec, pid_file: /tmp/edge-nginx.pid }
acme: { contact: ["mailto:lab@example.test"] }
quic: { h3: auto, retry: $2 }
status_listen: 127.0.0.1:9102
YAML
}
start_edge() {
  SSL_CERT_FILE=/tmp/pebble.crt ip netns exec edge "$KAPKAN" edge -config /tmp/edge.yaml -log-format text -log-level info >>/tmp/edge.log 2>&1 &
}
stop_edge() {
  local t0=$(date +%s%N); pkill -f "^$KAPKAN edge -config /tmp/edge.yaml" 2>/dev/null
  for i in $(seq 1 100); do pgrep -f "^$KAPKAN edge -config /tmp/edge.yaml" >/dev/null || break; sleep 0.1; done
  pgrep -f "^$KAPKAN edge -config /tmp/edge.yaml" >/dev/null && bad "the node did not stop within 10 s of SIGTERM" || echo "  (node stopped in $(( ($(date +%s%N) - t0) / 1000000 )) ms)"
}
status() { ip netns exec edge curl -s -m2 http://127.0.0.1:9102/healthz 2>/dev/null; }
sfield() { status | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('$1',''); print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }
# h3field EXPR -> a field of /healthz's h3 object (python expression over h)
h3field() { status | python3 -c "
import json,sys
d=json.load(sys.stdin); h=d.get('h3') or {}
try: v=eval(sys.argv[1], {}, {'h': h, 'len': len, 'sorted': sorted})
except Exception: v=''
print(v if not isinstance(v,bool) else str(v).lower())" "$1" 2>/dev/null; }
wait_status() { local i; for i in $(seq 1 $(( $3 * 5 ))); do [ "$(sfield "$1")" = "$2" ] && return 0; sleep 0.2; done; return 1; }
wait_etag() { local i e; for i in $(seq 1 100); do e=$(sfield accepted_etag); [ -n "$e" ] && [ "$e" != "$1" ] && return 0; sleep 0.2; done; return 1; }
wait_gen() { # wait until generation == $1 and converged (a slow-path change installed)
  local i; for i in $(seq 1 150); do [ "$(sfield generation)" = "$1" ] && [ "$(sfield converged)" = "true" ] && return 0; sleep 0.2; done; return 1
}
RESOLVE=(--resolve "$ZONE:443:$EDGE" --resolve "$ZONE2:443:$EDGE")
# get NS URL [curl args...] -> http code (TCP, h2 or h1.1 as negotiated)
get() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -o /dev/null -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" "$@" "$url" 2>/dev/null; }
# h3get NS URL [curl args...] -> "code version" over --http3-only ("000 0" when QUIC failed: -w prints on failure too)
h3get() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -o /dev/null -w '%{http_code} %{http_version}' -m5 --http3-only --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" "$@" "$url" 2>/dev/null; }
# h3body NS URL [curl args...] -> the body over --http3-only
h3body() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -m5 --http3-only --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" "$@" "$url" 2>/dev/null; }
# hdrs NS URL [curl args...] -> the response headers (TCP)
hdrs() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -o /dev/null -D - -m5 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" "$@" "$url" 2>/dev/null; }
# probe [h3probe flags...] -> h3probe's JSON, from the legit netns against ZONE
probe() { ip netns exec legit "$H3PROBE" get -url "https://$ZONE/" -ca /tmp/pebble-root.crt -timeout 6s "$@" 2>/dev/null; }
pfield() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); v=d.get('$2',''); print(v if not isinstance(v,bool) else str(v).lower())" "$1" 2>/dev/null; }
installs() { grep -c 'configuration installed' /tmp/edge.log; }
metric() { # metric name with labels as a grep pattern -> its value (0 when absent)
  ip netns exec edge curl -s -m2 http://127.0.0.1:9102/metrics 2>/dev/null | grep "^$1" | awk '{s+=$NF} END {print s+0}'
}
# zstatus EXPR -> a field of the brain's GET /api/v1/edge/zones/status for ZONE
zstatus() { brain_api "http://$BRAIN:8080/api/v1/edge/zones/status" | python3 -c "
import json,sys
d=json.load(sys.stdin)
z=[z for z in d.get('zones',[]) if z.get('zone')=='$ZONE']
z=z[0] if z else {}
try:
    v=eval(sys.argv[1], {}, {'z': z, 'd': d, 'len': len, 'sorted': sorted, 'set': set})
except Exception as e:
    v=''
print(v if not isinstance(v,bool) else str(v).lower())" "$1" 2>/dev/null; }
wait_zstatus() { local i; for i in $(seq 1 $(( $3 * 2 ))); do [ "$(zstatus "$1")" = "$2" ] && return 0; sleep 0.5; done; return 1; }
# nodefield NODE EXPR -> a field of the node's entry in GET /api/v1/edge/nodes (python over n)
nodefield() { brain_api "http://$BRAIN:8080/api/v1/edge/nodes" | python3 -c "
import json,sys
d=json.load(sys.stdin)
n=[n for n in d.get('nodes',[]) if n.get('name')==sys.argv[1]]
n=n[0] if n else {}
try: v=eval(sys.argv[2], {}, {'n': n, 'len': len})
except Exception: v=''
print(v if not isinstance(v,bool) else str(v).lower())" "$1" "$2" 2>/dev/null; }
is_page() { grep -q 'kapkan-puzzle' <<< "$1"; }
keysum() { sha256sum $STATE/tls/quic_host.key 2>/dev/null | cut -c1-16; }
jget() { python3 -c "import json,sys; d=json.load(open('$1')); v=d$2; print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }

# browser.py ZONE PATHPREFIX COUNT INTERVAL COOKIEFILE [BINDIP]: E4's browser —
# solves the puzzle over TCP once and keeps the cookie (arm B offers it over h3).
cat > /tmp/browser.py <<'PY'
import http.client, ssl, sys, time, json, re, hashlib, urllib.parse
zone, prefix, count, interval, cookiefile = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), sys.argv[5]
bind = sys.argv[6] if len(sys.argv) > 6 else None
ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
def conn():
    return http.client.HTTPSConnection(zone, 443, context=ctx, timeout=5, source_address=(bind, 0) if bind else None)
def bits(nonce, sol):
    h = hashlib.sha256((nonce + sol).encode()).digest()
    return 256 - int.from_bytes(h, "big").bit_length()
cookie = ""
codes, solved, pages, cleared_gets = {}, 0, 0, 0
for n in range(count):
    t0 = time.time()
    try:
        c = conn(); h = {"Cookie": "kapkan_clr=" + cookie} if cookie else {}
        c.request("GET", "%s-%d" % (prefix, n), headers=h); r = c.getresponse(); b = r.read().decode(errors="replace")
        codes[r.status] = codes.get(r.status, 0) + 1
        if r.status == 403 and "kapkan-puzzle" in b:
            pages += 1
            m = re.search(r'id="kapkan-puzzle">(.*?)</script>', b, re.S)
            p = json.loads(m.group(1))
            i = 0
            while bits(p["nonce"], str(i)) < p["difficulty"]:
                i += 1
            form = urllib.parse.urlencode({"nonce": p["nonce"], "solution": str(i), "return": p["return"]})
            c2 = conn(); c2.request("POST", "/_kapkan/clearance/answer", body=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
            r2 = c2.getresponse(); r2.read()
            sc = r2.getheader("Set-Cookie") or ""
            m2 = re.search(r"kapkan_clr=([^;]+)", sc)
            if r2.status == 303 and m2:
                cookie = m2.group(1); solved += 1
                open(cookiefile, "w").write(cookie)
            c2.close()
        elif r.status == 200 and cookie:
            cleared_gets += 1
        c.close()
    except Exception as e:
        codes["err"] = codes.get("err", 0) + 1
    dt = interval - (time.time() - t0)
    if dt > 0: time.sleep(dt)
print(json.dumps({"codes": codes, "solved": solved, "pages": pages, "cleared_gets": cleared_gets, "cookie": bool(cookie)}))
PY
# quicsend.py N GAP: N QUIC v1 Initial-shaped datagrams at the edge's :443 — the
# first byte and version the data plane's quic_initial matcher reads, padded to
# the 1200-byte floor. Syntactically incomplete (no connection IDs), so nginx
# drops them silently: the FLOOD is what this measures, never a handshake.
cat > /tmp/quicsend.py <<'PY'
import socket, sys, time
n, gap = int(sys.argv[1]), float(sys.argv[2])
pkt = bytes([0xC3, 0, 0, 0, 1]) + bytes(1195)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(n):
    s.sendto(pkt, ("203.0.113.10", 443))
    if gap:
        time.sleep(gap)
PY
# nginx-noh3: the same nginx, whose -V hides the HTTP/3 module — what the probe
# gate sees on a build without it (the real 1.22 refusal is pinned in the
# matrix; here the honest degrade of a whole node is the subject, arm J).
cat > /usr/local/bin/nginx-noh3 <<'SH'
#!/bin/sh
case " $* " in
  *" -V "*) nginx -V 2>&1 | sed 's/ --with-http_v3_module//' >&2; exit 0;;
esac
exec nginx "$@"
SH
chmod 755 /usr/local/bin/nginx-noh3

# ================================================================ ARM A
say "ARM A — per-zone h3: one install, served over HTTP/3, announced, toggled on the slow path"
: > /tmp/edge.log
edge_yaml false true
"$KAPKAN" edge -config /tmp/edge.yaml -check 2>&1 | tee /tmp/check.out | grep -q 'is valid' && ok "edge.yaml passes -check" || bad "edge.yaml fails -check"
grep -q 'ready' /tmp/check.out && ok "-check reports the node's HTTP/3 readiness ($(grep -oiE 'h3[^,]*ready[^,]*' /tmp/check.out | head -1))" || bad "-check says nothing about HTTP/3 readiness: $(cat /tmp/check.out)"
start_edge
wait_status healthy true 30 && ok "node healthy: a tested generation is live" || { bad "node never became healthy (see /tmp/edge.log)"; tail -20 /tmp/edge.log; }
for i in $(seq 1 150); do [ "$(grep -c 'certificate issued' /tmp/edge.log)" -ge 2 ] && break; sleep 0.2; done
[ "$(grep -c 'certificate issued' /tmp/edge.log)" -ge 2 ] && ok "both zones issued by Pebble" || { bad "certificates not issued in 30 s"; grep -i 'acme\|certificate' /tmp/edge.log | tail -5; }
ip netns exec legit curl -sk -m3 https://$CA:15000/roots/0 > /tmp/pebble-root.crt 2>/dev/null
grep -q 'BEGIN CERTIFICATE' /tmp/pebble-root.crt && ok "fetched Pebble's root for the clients" || bad "could not fetch Pebble's root"
wait_status converged true 30 || true
for i in $(seq 1 50); do [ "$(get legit https://$ZONE/hello)" = "200" ] && break; sleep 0.2; done
[ "$(get legit https://$ZONE/hello)" = "200" ] && ok "the zone is served through nginx to the origin over TCP" || bad "zone not served over TLS (see /tmp/edge-nginx-error.log)"
for i in $(seq 1 20); do G1=$(sfield generation); sleep 3; [ "$(sfield generation)" = "$G1" ] && [ "$(sfield converged)" = "true" ] && break; done
GEN0=$(sfield generation); INST0=$(installs); ET=$(sfield accepted_etag)
[ "$GEN0" -ge 2 ] 2>/dev/null && ok "generations settled after issuance (generation $GEN0, $INST0 installs)" || bad "generation after issuance: $GEN0"
[ "$(h3field "h.get('state')")" = "ready" ] && ok "/healthz h3.state is ready ($(h3field "h.get('tls_library')"), module $(h3field "h.get('module')"))" || bad "h3.state: $(h3field "h.get('state')")"
[ "$(metric 'kapkan_edge_h3_ready')" = "1" ] && ok "kapkan_edge_h3_ready is 1" || bad "kapkan_edge_h3_ready: $(metric 'kapkan_edge_h3_ready')"
ip netns exec edge ss -lun | grep -q ':443 ' && ok "ss -lun: nginx holds UDP/443" || bad "no UDP/443 listener"
[ "$(h3field "h.get('listening')")" = "true" ] && ok "the report's local half agrees: h3.listening true" || bad "h3.listening: $(h3field "h.get('listening')")"
[ "$(grep -c 'quic_retry on' $STATE/conf/live/kapkan_00_common.conf)" = "1" ] && ok "quic_retry on rendered once, at the http level of the shared file" || bad "quic_retry in the shared file: $(grep -c 'quic_retry' $STATE/conf/live/kapkan_00_common.conf)"
grep -q 'listen 443 quic reuseport default_server' $STATE/conf/live/kapkan_00_common.conf && ok "the catch-all carries the address's one reuseport QUIC listener" || bad "no QUIC catch-all listener"
grep -q 'listen 443 quic;' $STATE/conf/live/kapkan_zone_$ZONE.conf && ok "the h3 zone carries listen 443 quic" || bad "no QUIC listener in the zone file"
grep -q 'quic' $STATE/conf/live/kapkan_zone_$ZONE2.conf && bad "the zone that did not ask carries QUIC" || ok "the zone that did not ask carries no QUIC"
: > /tmp/origin.log
r=$(h3get legit https://$ZONE/h3-hello); [ "$r" = "200 3" ] && ok "curl --http3-only reaches $ZONE over HTTP/3 (200, http_version 3)" || bad "h3 request: '$r' (see /tmp/edge-nginx-error.log)"
grep -q "\"path\": \"/h3-hello\", \"zone\": \"$ZONE\"" /tmp/origin.log && ok "the origin saw the h3 request with X-Kapkan-Zone" || bad "origin log: $(tail -1 /tmp/origin.log)"
sleep 1.2
H3REQ=$(metric "kapkan_edge_requests_total{.*protocol=\"h3\".*zone=\"$ZONE\"\|kapkan_edge_requests_total{.*zone=\"$ZONE\".*protocol=\"h3\"")
[ "${H3REQ:-0}" -ge 1 ] 2>/dev/null && ok "kapkan_edge_requests_total{protocol=\"h3\"} counted it ($H3REQ): the access log's proto is HTTP/3.0" || bad "no h3 request counted: $(ip netns exec edge curl -s -m2 http://127.0.0.1:9102/metrics | grep requests_total | head -3)"
hdrs legit https://$ZONE/tcp > /tmp/hdr-a; grep -qi 'alt-svc: h3=":443"; ma=86400' /tmp/hdr-a && ok "the TCP answer announces h3 (Alt-Svc h3=\":443\"; ma=86400)" || bad "Alt-Svc on the TCP answer: $(grep -i alt-svc /tmp/hdr-a)"
rm -f /tmp/altsvc.cache
v1=$(ip netns exec legit curl -s -o /dev/null -w '%{http_version}' -m5 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" --alt-svc /tmp/altsvc.cache https://$ZONE/upgrade-1 2>/dev/null)
v2=$(ip netns exec legit curl -s -o /dev/null -w '%{http_version}' -m5 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" --alt-svc /tmp/altsvc.cache https://$ZONE/upgrade-2 2>/dev/null)
[ "$v1" = "2" ] && [ "$v2" = "3" ] && ok "the browser path: first request h2, second — with the Alt-Svc cache — h3" || bad "alt-svc upgrade: first $v1, second $v2"
hdrs legit https://$ZONE2/tcp | grep -qi 'alt-svc' && bad "$ZONE2 (no h3) announced Alt-Svc" || ok "$ZONE2 announces nothing"
r=$(h3get legit https://$ZONE2/nope); [ "$r" != "200 3" ] && ok "QUIC to $ZONE2 is refused ('$r'), TCP serves it ($(get legit https://$ZONE2/tcp))" || bad "a zone without tls.h3 was served over h3"
zones_yaml true true 86400 off true false 7; reload_brain
wait_etag "$ET" && ok "a rate change reached the node (new accepted ETag)" || bad "the rate change never reached the node"
sleep 0.5
[ "$(sfield generation)" = "$GEN0" ] && [ "$(installs)" = "$INST0" ] && ok "the rate change on the h3 zone installed nothing (generation $GEN0) — the fast path (§2.2)" || bad "a rate change rendered or reloaded (gen $GEN0 -> $(sfield generation))"
wait_zstatus "sorted(z.get('h3',{}).get('serving',[]))" "['edge-1']" 10 && ok "fleet status: h3.serving names edge-1" || bad "h3.serving: $(zstatus "z.get('h3')")"
[ "$(zstatus "z.get('h3',{}).get('enabled')")" = "true" ] && ok "fleet status: h3.enabled (the file's word)" || bad "h3.enabled: $(zstatus "z.get('h3')")"
for i in $(seq 1 3); do h3get legit https://$ZONE/count-$i >/dev/null; done; sleep 2.5
[ "$(zstatus "z.get('h3',{}).get('requests',0) > 0")" = "true" ] && ok "fleet status: h3.requests counts the h3 requests ($(zstatus "z.get('h3',{}).get('requests')"))" || bad "h3.requests: $(zstatus "z.get('h3')")"
# h3: false — one install, the announcement gone, QUIC refused.
INST=$(installs); zones_yaml false true 86400 off true false 7; reload_brain
wait_gen $((GEN0+1)) && ok "h3: false is one new tested generation ($GEN0 -> $((GEN0+1)))" || bad "h3: false did not install one generation (gen $(sfield generation), converged $(sfield converged))"
[ "$(installs)" = "$((INST+1))" ] && ok "exactly one install for the toggle" || bad "installs $INST -> $(installs)"
hdrs legit https://$ZONE/off | grep -qi 'alt-svc' && bad "Alt-Svc still announced after h3: false" || ok "Alt-Svc gone"
r=$(h3get legit https://$ZONE/off); [ "$r" != "200 3" ] && ok "QUIC refused after h3: false ('$r')" || bad "h3 still served after h3: false"
grep -q 'quic' $STATE/conf/live/kapkan_00_common.conf && bad "the shared file still carries QUIC with no h3 zone" || ok "no QUIC left in the shared file: the http-level quic_* go with the last h3 zone"
wait_zstatus "sorted(z.get('h3',{}).get('serving',[]))" "[]" 10 && ok "fleet status: nobody serves h3 now" || bad "h3.serving after off: $(zstatus "z.get('h3')")"
# Back on for the arms below.
zones_yaml true true 86400 off true false 5; reload_brain
wait_gen $((GEN0+2)) && ok "h3: true again — one more generation ($((GEN0+2)))" || bad "h3 did not come back (gen $(sfield generation))"
GENA=$(sfield generation)

# ================================================================ ARM B
say "ARM B — decisions and the rung over h3, as over TCP"
ET=$(sfield accepted_etag); zones_yaml true true 86400 off true false 2; reload_brain; wait_etag "$ET"; sleep 0.5
codes=""; for i in $(seq 1 12); do codes="$codes $(h3get legit https://$ZONE/burst-$i | cut -d' ' -f1)"; done
grep -q 429 <<< "$codes" && ok "a client over its ceiling gets 429 over h3 ($(tr -s ' ' '\n' <<< "$codes" | sort | uniq -c | tr -s ' \n' ' '))" || bad "no 429 over h3 at rps 2: $codes"
ip netns exec legit curl -s -o /dev/null -D /tmp/hdr-b429 -m5 --http3-only --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" https://$ZONE/burst-x 2>/dev/null; ip netns exec legit curl -s -o /dev/null -D /tmp/hdr-b429 -m5 --http3-only --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" https://$ZONE/burst-y 2>/dev/null
grep -qi '^retry-after: 1' /tmp/hdr-b429 && ok "the h3 429 carries Retry-After: 1" || bad "no Retry-After on the h3 429: $(head -3 /tmp/hdr-b429 | tr '\n' ' ')"
sleep 1.5
ET=$(sfield accepted_etag); zones_yaml true true 86400 manual false false 50; reload_brain; wait_etag "$ET"; sleep 0.5
b=$(h3body legit https://$ZONE/shop); is_page "$b" && ok "under challenge: manual an h3 client gets the clearance page" || bad "no page over h3: $(cut -c1-120 <<< "$b")"
r=$(h3get legit https://$ZONE/shop2); [ "${r%% *}" = "403" ] && ok "the page is a 403 over h3" || bad "page status over h3: $r"
rm -f /tmp/cookie-b; ip netns exec legit python3 /tmp/browser.py $ZONE /browser 2 0.3 /tmp/cookie-b > /tmp/browser-b.out 2>&1
[ "$(jget /tmp/browser-b.out "['solved']")" = "1" ] && ok "a browser solved the puzzle over TCP and got its cookie" || bad "browser did not clear: $(cat /tmp/browser-b.out)"
COOKIE=$(cat /tmp/cookie-b 2>/dev/null); : > /tmp/origin.log
r=$(h3get legit https://$ZONE/cleared-h3 -H "Cookie: kapkan_clr=$COOKIE"); [ "$r" = "200 3" ] && ok "the cleared cookie is honoured over h3 (200 over HTTP/3)" || bad "cookie over h3: $r"
grep -q '"mark": "cleared"' /tmp/origin.log && ok "the origin sees X-Kapkan-Mark: cleared on the h3 request" || bad "no cleared mark at the origin: $(tail -1 /tmp/origin.log)"
ET=$(sfield accepted_etag); zones_yaml true true 86400 off true true 1; reload_brain; wait_etag "$ET"; sleep 0.5; : > /tmp/origin.log
for i in $(seq 1 6); do h3get legit https://$ZONE/dry-$i >/dev/null; done
grep -q '"mark": "would-deny:rate"' /tmp/origin.log && ok "a watch-only zone marks would-deny:rate at the origin over h3 (nothing refused)" || bad "no would-deny mark over h3: $(tail -2 /tmp/origin.log)"
ET=$(sfield accepted_etag); zones_yaml true true 86400 off true false 5; reload_brain; wait_etag "$ET"; sleep 0.5
[ "$(sfield generation)" = "$GENA" ] && ok "arm B moved no generation ($GENA): rate, rung, dry-run are the fast path" || bad "arm B reloaded (gen $GENA -> $(sfield generation))"

# ================================================================ ARM C
say "ARM C — Retry: on at the http level, seen on the wire, tokens outlive a reload, off with quic.retry: false"
[ "$(cat $STATE/conf/live/kapkan_zone_*.conf | grep -c 'quic_retry')" = "0" ] && ok "no quic_retry in any zone file (node-wide, not per zone)" || bad "quic_retry in a zone file"
p=$(probe); [ "$(pfield "$p" retry_seen)" = "true" ] && [ "$(pfield "$p" status)" = "200" ] && [ "$(pfield "$p" alpn)" = "h3" ] && ok "h3probe: retry_seen true, 200 over h3 ($(pfield "$p" proto))" || bad "h3probe: $p"
ip netns exec edge tcpdump -i vedge -nn -c 12 -w /tmp/retry.pcap 'udp port 443' >/tmp/tcpdump.log 2>&1 &
TCPD=$!; sleep 0.8
probe >/dev/null; sleep 1; kill $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
python3 - <<'PY' && ok "tcpdump: the server's first datagram is a long-header Retry (type 0x3), shorter than the client's Initial" || bad "tcpdump did not show a Retry first: $(cat /tmp/retry-parse.txt 2>/dev/null)"
import struct
data = open('/tmp/retry.pcap', 'rb').read()
magic = struct.unpack('<I', data[:4])[0]
le = magic in (0xa1b2c3d4, 0xa1b23c4d)
endian = '<' if le else '>'
off = 24; first_client = None; first_server = None
while off + 16 <= len(data):
    ts_sec, ts_usec, incl, orig = struct.unpack(endian + 'IIII', data[off:off+16]); off += 16
    pkt = data[off:off+incl]; off += incl
    if len(pkt) < 42: continue
    sport = struct.unpack('>H', pkt[34:36])[0]; q = pkt[42:]
    if sport == 443 and first_server is None: first_server = q
    elif sport != 443 and first_client is None: first_client = q
open('/tmp/retry-parse.txt', 'w').write(f"client_initial_len={len(first_client) if first_client else None} server_first_byte={hex(first_server[0]) if first_server else None} server_first_len={len(first_server) if first_server else None}")
ok_ = bool(first_client and first_server and (first_server[0] & 0xF0) == 0xF0 and len(first_server) < len(first_client))
raise SystemExit(0 if ok_ else 1)
PY
echo "  ($(cat /tmp/retry-parse.txt))"
KEY0=$(keysum); [ "$(stat -c '%a %s' $STATE/tls/quic_host.key)" = "600 32" ] && ok "the host key is 32 bytes, mode 0600 (sha $KEY0)" || bad "host key: $(stat -c '%a %s' $STATE/tls/quic_host.key 2>&1)"
# A slow-path change forces a reload: the TLS floor of the other zone.
GEN=$(sfield generation)
sed -i "s/^    policy: { mode: none }/    tls: { min_version: \"1.3\" }\n    policy: { mode: none }/" /tmp/zones.yaml; reload_brain
wait_gen $((GEN+1)) && ok "a forced reload landed (generation $((GEN+1)))" || bad "the forced reload did not land (gen $(sfield generation))"
p=$(probe); [ "$(pfield "$p" status)" = "200" ] && [ "$(pfield "$p" retry_seen)" = "true" ] && ok "after the reload a fresh h3 handshake completes, Retry still on" || bad "post-reload probe: $p"
[ "$(keysum)" = "$KEY0" ] && ok "quic_host.key unchanged across the reload — the tokens it derives stay valid" || bad "the host key changed across a reload"
zones_yaml true true 86400 off true false 5; reload_brain; wait_gen $((GEN+2)) || true
# quic.retry: false is edge.yaml, read at start: a restart, one new generation.
INST=$(installs); GEN=$(sfield generation)
edge_yaml false false; stop_edge; start_edge
wait_status healthy true 30 || bad "node did not come back after the retry change"
wait_gen $((GEN+1)) && ok "quic.retry: false is one new tested generation ($((GEN+1)))" || bad "retry off did not install one generation (gen $(sfield generation))"
[ "$(grep -c 'quic_retry off' $STATE/conf/live/kapkan_00_common.conf)" = "1" ] && ok "quic_retry off rendered at the http level" || bad "quic_retry after retry: false: $(grep quic_retry $STATE/conf/live/kapkan_00_common.conf)"
p=$(probe); [ "$(pfield "$p" retry_seen)" = "false" ] && [ "$(pfield "$p" status)" = "200" ] && ok "h3probe: no Retry, 200 over h3" || bad "h3probe with retry off: $p"
[ "$(keysum)" = "$KEY0" ] && ok "the host key survived the node's restart" || bad "the host key changed across a restart"
edge_yaml false true; stop_edge; start_edge; wait_status healthy true 30 || true; wait_gen $((GEN+2)) || true
GENC=$(sfield generation)

# ================================================================ ARM D
say "ARM D — the Initial-rate cap in XDP: the flood sheds in-kernel, a legitimate handshake completes"
brain_yaml false "  ratelimit_profiles:
    - { name: qs, pps: 3 }
  static_rules:
    - { name: cap_quic, match: { proto: udp, dst_port: 443, payload: quic_initial }, action: ratelimit, profile: qs }"; reload_brain
sc=$(ip netns exec edge "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null | grep -oE 'static +[0-9]+' | grep -oE '[0-9]+' | head -1)
[ "${sc:-0}" -ge 1 ] && ok "dataplane status shows the cap live ($sc static slot(s))" || bad "no static rule live after the reload"
# udp_in -> the edge netns' UDP InDatagrams: what reached the stack. XDP drops
# happen before it, so under the cap the flood must NOT move it; under dry-run
# (below) it must — that, not a counter, is the proof of "shed" vs "passed".
udp_in() { ip netns exec edge cat /proc/net/snmp | grep '^Udp:' | tail -1 | awk '{print $2}'; }
ERR0=$(wc -l < /tmp/edge-nginx-error.log); before=$(vc drop_rl); before=${before:-0}; in0=$(udp_in)
ip netns exec attacker python3 /tmp/quicsend.py 300 0 &
FLOOD=$!; sleep 0.1
r=$(h3get legit https://$ZONE/during-flood); wait $FLOOD; sleep 0.5
after=$(vc drop_rl); after=${after:-0}; shed=$((after - before)); in1=$(udp_in)
[ "$shed" -ge 100 ] && ok "the kernel shed $shed of 300 attacker Initials (drop_rl) before nginx" || bad "drop_rl moved by $shed for a 300-Initial flood"
[ $((in1 - in0)) -lt 100 ] && ok "the stack saw only $((in1 - in0)) UDP datagrams during the flood: the shed Initials never reached it" || bad "UDP InDatagrams grew by $((in1 - in0)) — the flood reached the stack"
[ "$r" = "200 3" ] && ok "a legitimate h3 handshake completed DURING the flood (200 over HTTP/3)" || bad "legit h3 during the flood: '$r'"
[ "$(get legit https://$ZONE/tcp-during)" = "200" ] && ok "TCP untouched" || bad "TCP during the flood failed"
[ "$(wc -l < /tmp/edge-nginx-error.log)" = "$ERR0" ] && ok "nginx's error log is silent: the flood never reached it" || bad "nginx logged during the flood: $(tail -2 /tmp/edge-nginx-error.log)"
# The kernel's dry-run flag lives in the config map and takes effect when the
# program is (re)attached — the "run with dry_run: true, satisfy yourself, set
# false, restart" flow the manager documents — so the dry-run half RESTARTS the
# brain rather than reloading it. The counters are read after the restart, so
# the deltas are the flood alone whether or not the pins persisted.
brain_yaml true "  ratelimit_profiles:
    - { name: qs, pps: 3 }
  static_rules:
    - { name: cap_quic, match: { proto: udp, dst_port: 443, payload: quic_initial }, action: ratelimit, profile: qs }"
kill_brain; start_brain
for i in $(seq 1 40); do [ "$(ip netns exec edge "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null | grep -oE 'static +[0-9]+' | grep -oE '[0-9]+' | head -1)" -ge 1 ] 2>/dev/null && break; sleep 0.3; done
[ "$(ip netns exec edge "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null | grep -ci 'dry_run on')" -ge 1 ] && ok "the data plane re-attached in dry-run (status: dry_run ON)" || bad "data plane not in dry-run after the restart: $(ip netns exec edge "$KAPKAN" dataplane status -pin-path "$PIN" 2>/dev/null | grep -i 'dry_run')"
# In dry-run the kernel still RECORDS the verdict it would have given (drop_rl
# moves exactly as in enforce mode, so the operator reads the same figures) and
# bumps dryrun_would_drop beside it for every drop rewritten to a pass. The proof
# that nothing was dropped is the stack: the flood's datagrams now arrive.
wd0=$(vc dryrun_would_drop); wd0=${wd0:-0}; rl0=$(vc drop_rl); rl0=${rl0:-0}; in0=$(udp_in)
ip netns exec attacker python3 /tmp/quicsend.py 300 0; sleep 0.5
wd=$(vc dryrun_would_drop); wd=${wd:-0}; rl=$(vc drop_rl); rl=${rl:-0}; in1=$(udp_in)
[ $((wd - wd0)) -ge 100 ] && ok "brain dry_run: the flood is counted as would-be drops (dryrun_would_drop +$((wd - wd0)); the recorded verdict drop_rl +$((rl - rl0)) reads as in enforce mode)" || bad "dry-run flood not counted: would_drop +$((wd - wd0)), drop_rl +$((rl - rl0))"
[ $((in1 - in0)) -ge 250 ] && ok "…and nothing was dropped: the stack received $((in1 - in0)) UDP datagrams — the flood passed through to nginx, which discards malformed Initials silently" || bad "UDP InDatagrams grew by only $((in1 - in0)) under dry-run — packets were still dropped"
brain_yaml false "$NO_RULES"; kill_brain; start_brain
for i in $(seq 1 40); do ip netns exec edge curl -s -m1 http://$BRAIN:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done
# The restarted brain's inventory is empty until the node reports again; the
# arms below read it.
for i in $(seq 1 50); do [ "$(nodefield edge-1 "bool(n.get('report'))")" = "true" ] && break; sleep 0.3; done

# ================================================================ ARM E
say "ARM E — 0-RTT is off, and provably"
[ "$(cat $STATE/conf/live/*.conf | grep -c ssl_early_data)" = "0" ] && ok "no ssl_early_data anywhere in the render" || bad "ssl_early_data rendered"
# kapkan renders ssl_session_tickets off, so nginx issues no resumption ticket
# at all — which is why 0-RTT is doubly impossible: no ticket to carry early
# data, and no ssl_early_data to accept it.
[ "$(grep -c 'ssl_session_tickets off' $STATE/conf/live/kapkan_zone_$ZONE.conf)" -ge 1 ] && ok "the h3 zone renders ssl_session_tickets off (no resumption ticket is ever issued)" || bad "ssl_session_tickets not off: $(grep ssl_session_tickets $STATE/conf/live/kapkan_zone_$ZONE.conf)"
# A first TLS 1.3 connection asks for a ticket; with tickets off none is saved,
# so an early-data replay has nothing to offer — and even were one offered, no
# ssl_early_data means it could not be accepted. Either way: not accepted.
printf 'GET /early HTTP/1.1\r\nHost: %s\r\n\r\n' "$ZONE" > /tmp/early.txt
ip netns exec legit sh -c "printf 'GET /s1 HTTP/1.1\r\nHost: $ZONE\r\nConnection: close\r\n\r\n' | openssl s_client -connect $EDGE:443 -servername $ZONE -CAfile /tmp/pebble-root.crt -sess_out /tmp/e.sess -ign_eof" >/tmp/sclient-1.out 2>&1
[ -s /tmp/e.sess ] && echo "  (a session was saved; offering it with early data)" || echo "  (no session saved — tickets are off, as rendered)"
ip netns exec legit openssl s_client -connect $EDGE:443 -servername $ZONE -CAfile /tmp/pebble-root.crt -sess_in /tmp/e.sess -early_data /tmp/early.txt </dev/null >/tmp/sclient-2.out 2>&1
grep -q 'Early data was accepted' /tmp/sclient-2.out && bad "the server ACCEPTED early data" || ok "early data was not accepted ($(grep -oiE 'Early data was [a-z ]+' /tmp/sclient-2.out | head -1 || echo 'none offered: tickets are off'))"
# early_data_capable is omitempty: a false is absent from the JSON, so read it
# with a default (the report itself must be there — the wait above).
[ "$(nodefield edge-1 "n.get('report',{}).get('terminator',{}).get('h3',{}).get('early_data_capable', False)")" = "false" ] && [ "$(nodefield edge-1 "bool(n.get('report',{}).get('terminator',{}).get('h3'))")" = "true" ] && ok "the node reports early_data_capable: false (core $(nodefield edge-1 "n.get('report',{}).get('terminator',{}).get('version')"), OpenSSL 3.5 but nginx < 1.29.1) — recorded, never used" || bad "early_data_capable: $(nodefield edge-1 "n.get('report',{}).get('terminator',{}).get('h3')")"

# ================================================================ ARM F
say "ARM F — the kill lever: drop UDP/443 in the data plane; clients fall back to TCP within a second"
ds0=$(vc drop_static); ds0=${ds0:-0}
brain_yaml false "  static_rules:
    - { name: kill_quic, match: { proto: udp, dst_port: 443 }, action: drop }"; reload_brain
# The drop is immediate; what bounds the observed failure is how long the
# client waits for a QUIC answer that never comes — one second here.
t0=$(date +%s%N); for i in $(seq 1 10); do r=$(h3get legit https://$ZONE/killed -m 1); [ "$r" != "200 3" ] && break; sleep 0.1; done
[ "$r" != "200 3" ] && ok "--http3-only fails within $(( ($(date +%s%N) - t0) / 1000000 )) ms of the rule ('$r'; the client's 1 s wait is the whole delay)" || bad "h3 still served after kill_quic"
[ "$(get legit https://$ZONE/tcp-under-kill)" = "200" ] && ok "TCP serves the zone under the kill" || bad "TCP failed under the kill"
v=$(ip netns exec legit curl -s -o /dev/null -w '%{http_version}' -m8 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" --http3 --alt-svc /tmp/altsvc.cache https://$ZONE/race 2>/dev/null)
[ "$v" = "2" ] && ok "curl --http3 with a warm Alt-Svc cache raced and finished over h2" || bad "curl --http3 under the kill: http_version '$v'"
ds=$(vc drop_static); ds=${ds:-0}; [ $((ds - ds0)) -ge 1 ] && ok "drop_static grew (+$((ds - ds0)))" || bad "drop_static did not move"
grep -qi 'reload' /tmp/brain.log && ok "the brain logged the configuration reload (the lever is audited)" || bad "no reload line in the brain log"
brain_yaml true "  static_rules:
    - { name: kill_quic, match: { proto: udp, dst_port: 443 }, action: drop }"; reload_brain
wd0=$(vc dryrun_would_drop); wd0=${wd0:-0}
for i in $(seq 1 10); do r=$(h3get legit https://$ZONE/preview); [ "$r" = "200 3" ] && break; sleep 0.2; done
[ "$r" = "200 3" ] && ok "brain dry_run: the kill is previewed, h3 serves again" || bad "h3 under a dry-run kill: '$r'"
wd=$(vc dryrun_would_drop); wd=${wd:-0}; [ $((wd - wd0)) -ge 1 ] && ok "dryrun_would_drop counts what the lever would drop (+$((wd - wd0)))" || bad "would_drop did not move under the dry-run kill"
brain_yaml false "$NO_RULES"; reload_brain
for i in $(seq 1 10); do r=$(h3get legit https://$ZONE/back); [ "$r" = "200 3" ] && break; sleep 0.2; done
[ "$r" = "200 3" ] && ok "rule removed: h3 is back" || bad "h3 did not come back: '$r'"

# ================================================================ ARM H
say "ARM H — fail-static: h3 with the brain dead, across a node restart from disk"
GEN=$(sfield generation); INST=$(installs); KEY=$(keysum)
kill_brain && ok "the brain is dead" || bad "the brain is still answering"
r=$(h3get legit https://$ZONE/nobrain); [ "$r" = "200 3" ] && ok "h3 served with the brain dead" || bad "h3 with the brain dead: '$r'"
stop_edge; start_edge
wait_status healthy true 20 && ok "the node restarted from disk with the brain still dead" || bad "restart with the brain dead did not come back"
[ "$(sfield generation)" = "$GEN" ] && ok "the same generation is live ($GEN) — rendered from the cached document" || bad "generation after restart: $(sfield generation)"
r=$(h3get legit https://$ZONE/after-restart); [ "$r" = "200 3" ] && ok "h3 served after the restart" || bad "h3 after restart: '$r'"
[ "$(keysum)" = "$KEY" ] && ok "quic_host.key unchanged across the restart" || bad "host key changed"
BRAIN_SEEN=$(sfield brain_seen); mv /tmp/brain.log /tmp/brain-1.log; start_brain
for i in $(seq 1 100); do [ "$(sfield brain_seen)" != "$BRAIN_SEEN" ] && break; sleep 0.3; done
[ "$(sfield brain_seen)" != "$BRAIN_SEEN" ] && ok "brain back: the node's poll reaches it again" || bad "node did not see the returned brain"
sleep 2
[ "$(sfield generation)" = "$GEN" ] && [ "$(installs)" = "$INST" ] && ok "nothing installed across the brain's death and return (the returned brain answers the poll with the same document)" || bad "an install happened ($INST -> $(installs), gen $GEN -> $(sfield generation))"

# ================================================================ ARM J
say "ARM J — honest degrade: a second node whose build hides the module serves TCP only and says so"
mkdir -p $STATE2/conf $SOCKS2
cat > /tmp/edge2-nginx.conf <<CONF
daemon off;
user www-data;
worker_processes 1;
pid /tmp/edge2-nginx.pid;
error_log /tmp/edge2-nginx-error.log warn;
events { worker_connections 1024; }
http {
  access_log off;
  include $STATE2/conf/live/*.conf;
}
CONF
ip netns exec edge2 nginx -c /tmp/edge2-nginx.conf >/tmp/edge2-nginx.log 2>&1 &
sleep 0.5
cat > /tmp/edge2.yaml <<YAML
dry_run: false
controller: { url: "http://$BRAIN:8080", token_env: KAPKAN_EDGE_TOKEN, name: edge-2, report_interval_seconds: 1 }
state_dir: $STATE2
sockets_dir: $SOCKS2
socket_group: www-data
terminator: { binary: nginx-noh3, main_conf: /tmp/edge2-nginx.conf, reload: exec, pid_file: /tmp/edge2-nginx.pid }
acme: { contact: ["mailto:lab@example.test"] }
status_listen: 127.0.0.1:9103
YAML
"$KAPKAN" edge -config /tmp/edge2.yaml -check 2>&1 | tee /tmp/check2.out | grep -q 'is valid' && ok "edge-2's edge.yaml passes -check" || bad "edge-2 -check failed: $(cat /tmp/check2.out)"
grep -qi 'no_module\|without the HTTP/3 module\|http_v3_module.*no' /tmp/check2.out && ok "-check on edge-2 says the build has no HTTP/3 module" || bad "-check did not report the missing module: $(grep -i h3 /tmp/check2.out)"
: > /tmp/edge2.log
SSL_CERT_FILE=/tmp/pebble.crt ip netns exec edge2 "$KAPKAN" edge -config /tmp/edge2.yaml -log-format text -log-level info >>/tmp/edge2.log 2>&1 &
status2() { ip netns exec edge2 curl -s -m2 http://127.0.0.1:9103/healthz 2>/dev/null; }
s2field() { status2 | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('$1',''); print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }
h3field2() { status2 | python3 -c "
import json,sys
d=json.load(sys.stdin); h=d.get('h3') or {}
try: v=eval(sys.argv[1], {}, {'h': h, 'len': len, 'sorted': sorted})
except Exception: v=''
print(v if not isinstance(v,bool) else str(v).lower())" "$1" 2>/dev/null; }
for i in $(seq 1 150); do [ "$(s2field healthy)" = "true" ] && break; sleep 0.2; done
[ "$(s2field healthy)" = "true" ] && ok "edge-2 is healthy: its TCP-only render passed nginx -t" || { bad "edge-2 never became healthy"; tail -10 /tmp/edge2.log; }
for i in $(seq 1 150); do [ "$(grep -c 'certificate issued' /tmp/edge2.log)" -ge 2 ] && break; sleep 0.2; done
[ "$(grep -c 'certificate issued' /tmp/edge2.log)" -ge 2 ] && ok "edge-2 issued its own certificates (HTTP-01 answered by the fleet's fan-out on edge-1's :80)" || bad "edge-2 certificates not issued: $(grep -i 'acme\|certif' /tmp/edge2.log | tail -3)"
for i in $(seq 1 20); do G1=$(s2field generation); sleep 2; [ "$(s2field generation)" = "$G1" ] && [ "$(s2field converged)" = "true" ] && break; done
[ "$(h3field2 "h.get('state')")" = "no_module" ] && ok "edge-2 /healthz h3.state is no_module" || bad "edge-2 h3.state: $(h3field2 "h.get('state')")"
[ "$(h3field2 "sorted(h.get('unsupported',[]))")" = "['$ZONE']" ] && ok "edge-2 names $ZONE under h3.unsupported" || bad "edge-2 h3.unsupported: $(h3field2 "h.get('unsupported')")"
[ "$(cat $STATE2/conf/live/*.conf | grep -c quic)" = "0" ] && ok "edge-2's render carries no QUIC at all" || bad "QUIC in edge-2's render"
grep -q 'HTTP/3 ASKED FOR, NOT RENDERED' $STATE2/conf/live/kapkan_zone_$ZONE.conf && ok "edge-2's zone file says why (the degradation comment)" || bad "no degradation comment on edge-2"
[ "$(ip netns exec legit curl -s -o /dev/null -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE2" https://$ZONE/tcp-e2 2>/dev/null)" = "200" ] && ok "edge-2 serves the zone over TCP" || bad "edge-2 TCP failed"
r=$(ip netns exec legit curl -s -o /dev/null -w '%{http_code} %{http_version}' -m5 --http3-only --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE2" https://$ZONE/h3-e2 2>/dev/null || echo "000 0"); [ "$r" != "200 3" ] && ok "edge-2 refuses h3 ('$r')" || bad "edge-2 served h3 without the module"
wait_zstatus "sorted(z.get('h3',{}).get('unsupported',[]))" "['edge-2']" 10 && ok "fleet status: h3.unsupported names edge-2" || bad "h3.unsupported: $(zstatus "z.get('h3')")"
[ "$(zstatus "sorted(z.get('h3',{}).get('serving',[]))")" = "['edge-1']" ] && ok "fleet status: h3.serving still names edge-1 beside it — the zone is never held hostage to one node's package (D2)" || bad "h3.serving: $(zstatus "z.get('h3')")"
[ "$(nodefield edge-2 "n.get('report',{}).get('terminator',{}).get('h3',{}).get('state')")" = "no_module" ] && ok "the inventory's report for edge-2 says terminator.h3.state no_module" || bad "inventory edge-2: $(nodefield edge-2 "n.get('report',{}).get('terminator',{}).get('h3')")"
pkill -f "^$KAPKAN edge -config /tmp/edge2.yaml" 2>/dev/null; kill "$(cat /tmp/edge2-nginx.pid 2>/dev/null)" 2>/dev/null; sleep 1

# ================================================================ ARM K
say "ARM K — cost: h3 versus h2, p50, mode:none and decide zones"
# Both zones over h3 for the comparison (static.test gets tls.h3 for this arm
# only), and a ceiling the 240 samples cannot reach — the E4 rig did the same
# before its latency arm.
GEN=$(sfield generation); zones_yaml true true 86400 off true false 1000 true; reload_brain
wait_gen $((GEN+1)) && ok "static.test over h3 too, rate ceiling lifted — one install ($((GEN+1)))" || bad "arm K's document did not install (gen $(sfield generation))"
for i in $(seq 1 30); do [ "$(h3get legit https://$ZONE2/warm)" = "200 3" ] && break; sleep 0.2; done
lat() { ip netns exec legit curl -s -o /dev/null -w '%{http_code} %{time_total}\n' -m5 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" "$@"; }
for i in $(seq 1 60); do lat --http2 "https://$ZONE2/lat"; done > /tmp/lat-none-h2.txt
for i in $(seq 1 60); do lat --http3-only "https://$ZONE2/lat"; done > /tmp/lat-none-h3.txt
for i in $(seq 1 60); do lat --http2 "https://$ZONE/lat"; done > /tmp/lat-decide-h2.txt
for i in $(seq 1 60); do lat --http3-only "https://$ZONE/lat"; done > /tmp/lat-decide-h3.txt
python3 - <<'PY'
import statistics
def load(p):
    rows = [l.split() for l in open(p) if l.strip()]
    return statistics.median(float(r[1]) for r in rows)*1000, sum(1 for r in rows if r[0] != '200')
out = []; bad = 0
for zone, tag in (('static.test (none)', 'none'), ('shop.test (decide)', 'decide')):
    h2, b2 = load(f'/tmp/lat-{tag}-h2.txt'); h3, b3 = load(f'/tmp/lat-{tag}-h3.txt'); bad += b2 + b3
    out.append(f"{zone}: h2 p50 {h2:.2f} ms, h3 p50 {h3:.2f} ms, delta {h3-h2:+.2f} ms")
print("  " + "\n  ".join(out) + f"\n  off-status samples: {bad}")
open('/tmp/lat-h3.txt', 'w').write("\n".join(out) + f"\noff-status {bad}\n")
PY
[ "$(tail -1 /tmp/lat-h3.txt)" = "off-status 0" ] && ok "every latency sample was a 200 (240 requests, h2 and h3, both zones)" || bad "$(tail -1 /tmp/lat-h3.txt) latency samples were not 200"
# static.test back to never asking (the arms below use shop.test; the ceiling
# stays lifted so a burst of checks is never mistaken for a fault).
GEN=$(sfield generation); zones_yaml true true 86400 off true false 1000; reload_brain; wait_gen $((GEN+1)) || true

# ================================================================ ARM L
say "ARM L — MTU below QUIC's floor: h3 fails cleanly and fast, TCP survives"
ip netns exec legit ip link set vlegit mtu 1200
t0=$(date +%s%N); r=$(h3get legit https://$ZONE/mtu -m 3); dt=$(( ($(date +%s%N) - t0) / 1000000 ))
[ "$r" != "200 3" ] && ok "at MTU 1200 --http3-only fails ('$r') in $dt ms" || bad "h3 succeeded at MTU 1200"
[ "$dt" -le 3500 ] && ok "the failure is fast (curl -m 3 bounded it)" || bad "h3 failure took $dt ms"
[ "$(get legit https://$ZONE/mtu-tcp)" = "200" ] && ok "TCP still serves at MTU 1200" || bad "TCP failed at MTU 1200"
ip netns exec legit ip link set vlegit mtu 1500
r=$(h3get legit https://$ZONE/mtu-back); [ "$r" = "200 3" ] && ok "MTU restored: h3 is back" || bad "h3 after MTU restore: '$r'"

# ================================================================ ARM M
say "ARM M — the canary: advertise: false, then a short ma"
GEN=$(sfield generation); INST=$(installs)
zones_yaml true false 86400 off true false 1000; reload_brain
wait_gen $((GEN+1)) && [ "$(installs)" = "$((INST+1))" ] && ok "advertise: false is one install ($((GEN+1)))" || bad "advertise: false: gen $(sfield generation), installs $INST -> $(installs)"
hdrs legit https://$ZONE/canary | grep -qi 'alt-svc' && bad "the canary still announces Alt-Svc" || ok "no Alt-Svc on the TCP answer"
r=$(h3get legit https://$ZONE/canary-h3); [ "$r" = "200 3" ] && ok "an explicit h3 client reaches the canary (200 over HTTP/3)" || bad "canary h3: '$r'"
# The browser path is Alt-Svc-driven: a plain client with an empty alt-svc
# cache makes two requests; with no announcement the second stays on h2 (in
# arm A the same pair upgraded to h3). Not `curl --http3`, which dials QUIC
# directly and merely falls back — that is an explicit client, not a browser.
rm -f /tmp/altsvc-m.cache
v1=$(ip netns exec legit curl -s -o /dev/null -w '%{http_version}' -m8 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" --alt-svc /tmp/altsvc-m.cache https://$ZONE/browser-canary-1 2>/dev/null)
v2=$(ip netns exec legit curl -s -o /dev/null -w '%{http_version}' -m8 --cacert /tmp/pebble-root.crt "${RESOLVE[@]}" --alt-svc /tmp/altsvc-m.cache https://$ZONE/browser-canary-2 2>/dev/null)
[ "$v1" = "2" ] && [ "$v2" = "2" ] && ok "the browser path stays on h2 across two requests (nothing learnt: nobody is told)" || bad "browser path under the canary: http_version $v1 then $v2"
GEN=$(sfield generation); INST=$(installs)
zones_yaml true true 300 off true false 1000; reload_brain
wait_gen $((GEN+1)) && [ "$(installs)" = "$((INST+1))" ] && ok "advertise: true, ma 300 is one install ($((GEN+1)))" || bad "ma 300: gen $(sfield generation), installs $INST -> $(installs)"
hdrs legit https://$ZONE/short-ma | grep -qi 'alt-svc: h3=":443"; ma=300' && ok "Alt-Svc carries ma=300 — a rollback is forgotten in minutes" || bad "Alt-Svc after ma 300: $(hdrs legit https://$ZONE/short-ma2 | grep -i alt-svc)"

echo
echo "== E5 acceptance: $PASS passed, $FAIL failed =="
echo "== latency (arm K): $(head -2 /tmp/lat-h3.txt | tr '\n' ';') =="
[ "$FAIL" -eq 0 ]
