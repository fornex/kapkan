#!/usr/bin/env bash
#
# E6.9 acceptance: one address, many nodes — the anycast/ECMP guide's every
# claim executed on a real kernel with a real router hop, real nginx, real
# HTTP/3 and a real ACME CA (engine/docs/edge-spec.md §8, milestone E6, the
# accepted E6 plan's block E6.9). The guide documents no command this rig has
# not run and no number this rig has not recorded.
#
# The topology is the shape an operator actually builds. A router netns (rtr)
# forwards a VIP /32 to two nodes over two point-to-point legs as an ECMP
# route, and its `fib_multipath_hash_policy` is switched per arm — that sysctl
# IS the subject of half of these arms. Each node holds the VIP on `lo`, runs
# its own stock nginx under `unshare -u` so its `$hostname` is its own name,
# its own `kapkan edge` with its own state_dir/sockets_dir/pid file, and its
# OWN agent token bound with `api.tokens[].node` — the guide tells operators
# one token per node, so the rig models exactly that. The brain sits in its
# own netns, reached by unicast, never on the VIP. The CA resolves the zone
# through /etc/hosts to the VIP, so every HTTP-01 validation crosses the hash.
# There is no XDP anywhere: this rig is about routing and per-node ceilings,
# not the data plane (that is E5's and E6.10's subject).
#
# A request is attributed to the node that served it two ways, and the rig
# uses each where it is honest: per-node `/metrics`
# (`kapkan_edge_requests_total`, `kapkan_edge_decisions_total`) and
# `add_header X-Kapkan-Node $hostname always;` injected through the zone's
# `extra_directives_file` — an operator's debugging trick, never a product
# header. The header rides 200s, 403s and clearance pages but NOT 429s: the
# render's `@kapkan_denied` declares its own `add_header Retry-After`, and
# nginx drops the inherited set wherever a location declares one. So refusals
# are counted at the decider's metric, not at the header (arm C).
#
# Arms:
#
#   A. the fleet and a deterministic fan-out: with the route pinned to edge-2
#      for the whole issuance, edge-1's certificate can only have been
#      validated by the challenge fanned out to edge-2 — both nodes issued,
#      both published, a slot was refused, the two leaves differ, the
#      inventory has two alive nodes on one document, no key bytes in it;
#   B. the two hash forms: L3 (policy 0) pins one client to one node for 40
#      connections; L4 (policy 1) spreads it over both, over TCP and over
#      HTTP/3 alike — the same policy governs the UDP 4-tuple;
#   C. the per-node ceilings under each form: `policy.rate.rps` is enforced
#      per node, so under L4 one source gets up to N× the ceiling. The share
#      is RECORDED — those are the guide's numbers;
#   D. a node dies and nobody withdraws: the route still points at it, so a
#      share of requests fails while the rest are served; keepalive to the
#      dead node breaks and to the live one survives; the inventory says
#      `alive:false` within `stale_after` and the brain touches no route.
#      D2: the link down instead — the nexthop goes `dead` and every request
#      is served without any operator action ("a directly connected router
#      notices link loss, a routed hop does not"), then the withdrawal as
#      what it really is, a RIB effect: `ip route replace`, recovery timed;
#   E. the withdrawal SIGNAL without a BGP daemon: a refused document is not
#      one (`converged:false`, /healthz 200, the VIP serving), a dead
#      terminator is (/healthz 503 within a second, while the brain's
#      inventory still says `alive:true` — the node's signal fires, the
#      inventory's does not);
#   F. the brain dead: both nodes serve TCP and h3 through the VIP, /healthz
#      200, and a restarted brain has them back within `stale_after`;
#   G. the two cross-node facts a shared address exposes: a TLS session is
#      not resumable on the other node (spec §3, sid_ctx), while a clearance
#      cookie IS honoured there (fleet-wide clearance keys);
#   H. MTU: 1200 on ONE leg breaks HTTP/3 for the share of clients hashed to
#      that node while TCP is untouched;
#   I. (stretch, ANYCAST_BGP=1, OUTSIDE the acceptance path) the same
#      withdrawal contract driven by a real speaker: bird2 on each node
#      announcing the VIP /32, enabled and disabled by a once-a-second
#      /healthz probe.
#
# Build the binaries for the container arch first (from engine/), then run
# this inside ONE privileged debian:13-slim container (never two rigs at
# once — check `docker ps`):
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan
#   git clone --depth 1 https://github.com/letsencrypt/pebble /tmp/pebble-src \
#     && (cd /tmp/pebble-src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/pebble ./cmd/pebble)
#   docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:13-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq \
#              iproute2 nginx openssl curl python3 procps iputils-ping ca-certificates tcpdump util-linux >/dev/null \
#            && KAPKAN=/lab/kapkan PEBBLE=/lab/pebble bash engine/scripts/labnet/edge-e6-anycast.sh'
#
set -uo pipefail
export PATH=/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin
KAPKAN=${KAPKAN:-/lab/kapkan}
PEBBLE=${PEBBLE:-/lab/pebble}
ANYCAST_BGP=${ANYCAST_BGP:-0}
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
say() { echo; echo "== $1 =="; }
[ -f /.dockerenv ] || { echo "this rig builds netns, bridges and routes: run it inside the privileged container from the header, not on your host"; exit 2; }
[ -x "$KAPKAN" ] || { echo "kapkan binary not found at $KAPKAN"; exit 2; }
[ -x "$PEBBLE" ] || { echo "pebble binary not found at $PEBBLE"; exit 2; }
# The entry gates. Every one of them is a thing an arm depends on absolutely:
# a box that cannot hash, cannot serve h3, or cannot ask for it must fail here
# rather than pass an arm vacuously over TCP on a single path.
[ -e /proc/sys/net/ipv4/fib_multipath_hash_policy ] || { echo "this kernel has no net.ipv4.fib_multipath_hash_policy: it cannot do ECMP, and arms B/C/H are the point of this rig"; exit 2; }
nginx -V 2>&1 | grep -q -- --with-http_v3_module || { echo "this nginx has no http_v3_module: $(nginx -v 2>&1)"; exit 2; }
curl -V | grep -q HTTP3 || { echo "this curl has no HTTP3: $(curl -V | head -1)"; exit 2; }
command -v unshare >/dev/null || { echo "unshare is required (each node's nginx runs in its own UTS namespace so \$hostname names the node)"; exit 2; }

# Addressing. The VIP is the only address a client ever uses; every leg is a
# /30 so a leg can be taken down or given a small MTU on its own.
VIP=198.51.100.7
E1=10.0.1.2;  R1=10.0.1.1          # edge-1's unicast, rtr's end of its leg
E2=10.0.2.2;  R2=10.0.2.1          # edge-2's unicast, rtr's end of its leg
CLI=10.1.0.2; RC=10.1.0.1          # the client behind the router
BRAIN=203.0.113.20; ORIGIN=203.0.113.30; CA=203.0.113.40; RSVC=203.0.113.1
ZONE=shop.test                     # global: both nodes serve it, through the VIP
ZONEB=nodeb.test                   # placed on pop-b: only edge-2 serves it
STATE1=/var/lib/kapkan-edge1; SOCKS1=/run/kapkan-edge1
STATE2=/var/lib/kapkan-edge2; SOCKS2=/run/kapkan-edge2
STALE=5
EXTRA=/tmp/extra-node.conf         # the node-attribution header
EXTRA_BROKEN=/tmp/extra-broken.conf
export KAPKAN_OP=optok KAPKAN_A1=a1tok KAPKAN_A2=a2tok
tok() { case $1 in op) echo optok;; a1) echo a1tok;; a2) echo a2tok;; *) echo "$1";; esac; }

# hosts_drop NAME removes NAME's lines from /etc/hosts in place — the file is
# a Docker bind mount, so `sed -i` (a rename over it) fails silently.
hosts_drop() { local tmp; tmp=$(grep -v " $1\$" /etc/hosts); printf '%s\n' "$tmp" > /etc/hosts; }
cleanup() {
  if [ -d /lab ]; then
    mkdir -p /lab/logs && cp -f /tmp/*.log /tmp/*.out /tmp/*.txt /lab/logs/ 2>/dev/null
    cp -f /tmp/zones.yaml /tmp/brain.yaml /tmp/edge1.yaml /tmp/edge2.yaml /tmp/extra-node.conf /lab/logs/ 2>/dev/null
  fi
  kill "$(cat /tmp/brain.pid 2>/dev/null)" 2>/dev/null
  pkill -f "^$KAPKAN " 2>/dev/null; pkill -f "^$PEBBLE " 2>/dev/null
  pkill -f '^nginx: master' 2>/dev/null; pkill -f '^python3 /tmp/origin.py' 2>/dev/null
  pkill -f '^python3 /tmp/browser.py' 2>/dev/null; pkill -f '^python3 /tmp/keepalive.py' 2>/dev/null
  pkill -f 'bird -c' 2>/dev/null; pkill -f '^/tmp/announce' 2>/dev/null
  for ns in rtr edge1 edge2 brain origin ca cli; do ip netns del "$ns" 2>/dev/null; done
  ip link del brsvc 2>/dev/null
  for z in $ZONE $ZONEB; do hosts_drop "$z" 2>/dev/null; done
}
trap cleanup EXIT
cleanup

# ---------------------------------------------------------------- topology
say "building the topology: a router with an ECMP VIP, two nodes, the brain by unicast"
add_ns() { ip netns add "$1"; ip netns exec "$1" ip link set lo up; ip netns exec "$1" sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null; }
for ns in rtr edge1 edge2 brain origin ca cli; do add_ns "$ns"; done
ip netns exec rtr sysctl -wq net.ipv4.ip_forward=1
# p2p LEG A/B/CLIENT: one veth per leg, so a leg can go down or shrink alone.
leg() { # NS IFNAME IP/CIDR PEERNAME PEERIP/CIDR  (peer end lands in rtr)
  local ns=$1 ifn=$2 addr=$3 peer=$4 paddr=$5
  ip link add "$ifn" type veth peer name "$peer"
  ip link set "$ifn" netns "$ns"; ip link set "$peer" netns rtr
  ip netns exec "$ns" ip addr add "$addr" dev "$ifn"; ip netns exec "$ns" ip link set "$ifn" up
  ip netns exec rtr ip addr add "$paddr" dev "$peer"; ip netns exec rtr ip link set "$peer" up
}
leg edge1 e1-r  $E1/30  r-e1  $R1/30
leg edge2 e2-r  $E2/30  r-e2  $R2/30
leg cli   cli-r $CLI/24 r-cli $RC/24
# The service network (brain, origin, CA) hangs off the router on a bridge:
# the nodes reach the brain by UNICAST, over the same router, and the CA
# reaches the zone through the VIP — so validation crosses the hash.
ip link add brsvc type bridge; ip link set brsvc up
svc() { # NS IP
  local ns=$1 ip=$2 h="v$1"
  ip link add "$h" type veth peer name "${h}p"
  ip link set "${h}p" master brsvc; ip link set "${h}p" up
  ip link set "$h" netns "$ns"
  ip netns exec "$ns" ip addr add "$ip/24" dev "$h"; ip netns exec "$ns" ip link set "$h" up
  ip netns exec "$ns" ip route add default via $RSVC
}
ip link add r-svc type veth peer name r-svcp
ip link set r-svcp master brsvc; ip link set r-svcp up
ip link set r-svc netns rtr
ip netns exec rtr ip addr add $RSVC/24 dev r-svc; ip netns exec rtr ip link set r-svc up
svc brain  $BRAIN
svc origin $ORIGIN
svc ca     $CA
# Everything but the router routes through the router.
ip netns exec edge1 ip route add default via $R1
ip netns exec edge2 ip route add default via $R2
ip netns exec cli   ip route add default via $RC
# The VIP: on each node's loopback (the guide's shape — address-less listens,
# so kapkan's render is not aware of it at all), and on the router as one
# ECMP route with a nexthop per leg.
ip netns exec edge1 ip addr add $VIP/32 dev lo
ip netns exec edge2 ip addr add $VIP/32 dev lo
route_both() { ip netns exec rtr ip route replace $VIP/32 nexthop via $E1 dev r-e1 weight 1 nexthop via $E2 dev r-e2 weight 1; ip netns exec rtr ip route flush cache; }
route_one()  { ip netns exec rtr ip route replace $VIP/32 via "$1" dev "$2"; ip netns exec rtr ip route flush cache; }
vip_route()  { ip netns exec rtr ip route show $VIP/32 | tr -s ' \n' ' '; }
hashpol()    { ip netns exec rtr sysctl -wq net.ipv4.fib_multipath_hash_policy="$1"; ip netns exec rtr ip route flush cache; }
route_both
hashpol 0
[ -n "$(vip_route)" ] && ok "the router carries the VIP as one ECMP route ($(vip_route))" || bad "no multipath VIP route on the router"
ip netns exec cli ping -c1 -W1 $E1 >/dev/null 2>&1 && ip netns exec cli ping -c1 -W1 $E2 >/dev/null 2>&1 && ok "the client reaches both nodes' unicast addresses through the router" || bad "no path client -> nodes (topology broken; nothing below is meaningful)"
ip netns exec cli ping -c1 -W1 $BRAIN >/dev/null 2>&1 && ip netns exec edge1 ping -c1 -W1 $BRAIN >/dev/null 2>&1 && ok "the brain is reachable by unicast from the client and from a node" || bad "no path to the brain"
ip netns exec ca ping -c1 -W1 $VIP >/dev/null 2>&1 && ok "the CA reaches the VIP (its validation will cross the hash)" || bad "the CA cannot reach the VIP"
printf '%s %s\n' "$VIP" "$ZONE" >> /etc/hosts
printf '%s %s\n' "$E2" "$ZONEB" >> /etc/hosts   # placed on pop-b: its name resolves to the node that serves it

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
for i in $(seq 1 20); do ip netns exec cli curl -s -m1 http://$ORIGIN:8081/ >/dev/null 2>&1 && break; sleep 0.3; done
grep -q '"path"' <<< "$(ip netns exec cli curl -s -m2 http://$ORIGIN:8081/)" && ok "origin answers directly" || bad "origin not answering"

# ---------------------------------------------------------------- Pebble
say "starting Pebble: a real ACME CA that validates HTTP-01 through the VIP"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout /tmp/pebble.key -out /tmp/pebble.crt -subj "/CN=pebble" \
  -addext "subjectAltName=IP:$CA" >/dev/null 2>&1
cat > /tmp/pebble.json <<JSON
{ "pebble": { "listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/tmp/pebble.crt", "privateKey": "/tmp/pebble.key",
  "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false } }
JSON
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 ip netns exec ca "$PEBBLE" -config /tmp/pebble.json -strict=false >/tmp/pebble.log 2>&1 &
for i in $(seq 1 30); do ip netns exec edge1 curl -sk -m1 https://$CA:14000/dir >/dev/null 2>&1 && break; sleep 0.3; done
grep -q newOrder <<< "$(ip netns exec edge1 curl -sk -m2 https://$CA:14000/dir)" && ok "Pebble directory is up" || bad "Pebble not answering (see /tmp/pebble.log)"

# ---------------------------------------------------------------- the brain
say "starting the brain in its own netns: one global zone, one placed zone, one bound token per node"
# The node-attribution header. It is an operator's debugging trick through the
# zone's one escape hatch, not a product header: kapkan renders it verbatim
# and `nginx -t` is its only guard. `$hostname` is what each nginx read from
# its own UTS namespace at start.
cat > $EXTRA <<'CONF'
add_header X-Kapkan-Node $hostname always;
CONF
echo 'this is not nginx;' > $EXTRA_BROKEN
ZONE_RPS=1000; ZONEB_EXTRA=""
zones_yaml() {
  {
    echo "zones:"
    echo "  - name: $ZONE"
    echo "    origins: [\"$ORIGIN:8081\"]"
    echo "    tls: { min_version: \"1.2\", h3: true }"
    echo "    acme: { directory: \"https://$CA:14000/dir\" }"
    echo "    extra_directives_file: \"$EXTRA\""
    echo "    policy:"
    echo "      mode: decide"
    echo "      failure_mode: open"
    echo "      challenge: off"
    echo "      challenge_options: { dry_run: false, difficulty: 12, cookie_ttl_seconds: 300 }"
    echo "      rate: { rps: $ZONE_RPS }"
    echo "  - name: $ZONEB"
    echo "    hostgroup: pop-b"
    echo "    origins: [\"$ORIGIN:8081\"]"
    echo "    acme: { directory: \"https://$CA:14000/dir\" }"
    [ -n "$ZONEB_EXTRA" ] && echo "    extra_directives_file: \"$ZONEB_EXTRA\""
    echo "    policy: { mode: decide, failure_mode: open, challenge: off, rate: { rps: 1000 } }"
  } > /tmp/zones.yaml
}
brain_yaml() {
cat > /tmp/brain.yaml <<YAML
dry_run: false
listen: { netflow: "127.0.0.1:2055" }
sampling: { default_rate: 1000 }
networks: ["203.0.113.0/24", "10.0.0.0/8", "198.51.100.0/24"]
thresholds: { pps: 80000, mbps: 1000, flows_per_sec: 35000 }
ban: { ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50 }
bgp:
  local_asn: 65010
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65010:666"
  neighbors: [{ address: "127.0.0.2", remote_asn: 65000 }]
hostgroups:
  - { name: pop-a, networks: ["$E1/32"] }
  - { name: pop-b, networks: ["$E2/32"] }
api:
  listen: "$BRAIN:8080"
  tokens:
    - { name: op, token_env: KAPKAN_OP, role: operator }
    - { name: a1, token_env: KAPKAN_A1, role: agent, node: edge-1 }
    - { name: a2, token_env: KAPKAN_A2, role: agent, node: edge-2 }
edge:
  zones_file: /tmp/zones.yaml
  state_file: /tmp/edge-state.json
  stale_after_seconds: $STALE
  nodes:
    - { name: edge-1, hostgroups: [pop-a, global] }
    - { name: edge-2, hostgroups: [pop-b, global] }
YAML
}
zones_yaml; brain_yaml
start_brain() {
  ip netns exec brain "$KAPKAN" -config /tmp/brain.yaml -log-format text -log-level info -pid-file /tmp/brain.pid >>/tmp/brain.log 2>&1 &
  for i in $(seq 1 40); do ip netns exec cli curl -s -m1 http://$BRAIN:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done
}
kill_brain() { kill "$(cat /tmp/brain.pid 2>/dev/null)" 2>/dev/null; for i in $(seq 1 30); do ip netns exec cli curl -s -m1 "http://$BRAIN:8080/healthz" >/dev/null 2>&1 || return 0; sleep 0.2; done; return 1; }
reload_brain() { ip netns exec brain "$KAPKAN" -s reload -pid-file /tmp/brain.pid >/dev/null 2>&1; sleep 1; }
check_config() { "$KAPKAN" -check-config /tmp/brain.yaml > /tmp/check.out 2>&1; echo $?; }
api()  { local t=$1 u=$2; shift 2; ip netns exec cli curl -s -m5 -H "Authorization: Bearer $(tok "$t")" "$@" "$u" 2>/dev/null; }
code() { local t=$1 m=$2 u=$3 b=${4:-}; ip netns exec cli curl -s -o /dev/null -w '%{http_code}' -m5 -X "$m" -H "Authorization: Bearer $(tok "$t")" -H 'Content-Type: application/json' ${b:+-d "$b"} "$u" 2>/dev/null; }
B="http://$BRAIN:8080/api/v1"
jx() { python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: d={}
try: v=eval(sys.argv[1], {}, {'d': d, 'len': len, 'sorted': sorted, 'set': set, 'str': str, 'int': int, 'float': float, 'any': any, 'all': all, 'sum': sum})
except Exception: v=''
print(v if not isinstance(v,bool) else str(v).lower())" "$1" 2>/dev/null; }
node_f() { api op "$B/edge/nodes" | jx "(lambda n: $2)(([n for n in d.get('nodes',[]) if n.get('name')=='$1']+[{}])[0])"; }
inv_f()  { api op "$B/edge/nodes" | jx "$1"; }
zst()    { api op "$B/edge/zones/status" | jx "(lambda z: $2)(([z for z in d.get('zones',[]) if z.get('zone')=='$1']+[{}])[0])"; }
lever()  { code op "$1" "$B/edge/zones/$2/challenge" "${3:-}"; }
wait_eq() { local n=$(( $1 * 5 )) want=$2 i; shift 2; for i in $(seq 1 "$n"); do [ "$("$@")" = "$want" ] && return 0; sleep 0.2; done; return 1; }
wait_ne() { local n=$(( $1 * 5 )) not=$2 i; shift 2; for i in $(seq 1 "$n"); do [ "$("$@")" != "$not" ] && return 0; sleep 0.2; done; return 1; }
: > /tmp/brain.log
start_brain
rc=$(check_config); [ "$rc" = "0" ] && ok "-check-config accepts the fleet (two bound agent tokens, two scopes)" || bad "-check-config: rc=$rc $(head -3 /tmp/check.out)"
grep -q 'edge-1 .*scope=\[' /tmp/check.out && ok "-check-config prints the placement matrix ($(grep -oE 'edge-1 .*' /tmp/check.out | head -1 | tr -s ' '))" || bad "no placement matrix in -check-config: $(head -8 /tmp/check.out)"
c=$(code a1 GET "$B/edge/zones?node=edge-1"); [ "$c" = "200" ] && ok "the brain serves edge-1's document to edge-1's own token" || { bad "no zones document (got '$c')"; tail -15 /tmp/brain.log; }
[ "$(code a1 GET "$B/edge/zones?node=edge-2")" = "403" ] && ok "…and refuses it edge-2's name (one token per node, E6.1)" || bad "a1 as edge-2: $(code a1 GET "$B/edge/zones?node=edge-2")"

# ---------------------------------------------------------------- nginx on both nodes
say "starting stock nginx on both nodes, each in its own UTS namespace (\$hostname = the node)"
node_nginx() { # N NS STATE
  mkdir -p "$3/conf"
  cat > /tmp/edge$1-nginx.conf <<CONF
daemon off;
user www-data;
worker_processes 1;
pid /tmp/edge$1-nginx.pid;
error_log /tmp/edge$1-nginx-error.log warn;
events { worker_connections 1024; }
http {
  access_log off;
  include $3/conf/live/*.conf;
}
CONF
  # unshare -u so nginx's $hostname — read once at start, kept across reloads
  # because the master keeps the namespace — names this node and no other.
  ip netns exec "$2" unshare -u sh -c "hostname edge-$1; exec nginx -c /tmp/edge$1-nginx.conf" >/tmp/edge$1-nginx.log 2>&1 &
}
node_nginx 1 edge1 $STATE1
node_nginx 2 edge2 $STATE2
sleep 0.6
[ "$(pgrep -fc 'nginx: master')" = "2" ] && ok "two nginx masters are up ($(nginx -v 2>&1 | grep -oE '[0-9.]+$'))" || bad "nginx masters: $(pgrep -fc 'nginx: master')"

# ---------------------------------------------------------------- kapkan edge on both nodes
edge_yaml() { # N STATE SOCKS
cat > /tmp/edge$1.yaml <<YAML
dry_run: false
controller: { url: "http://$BRAIN:8080", token_env: KAPKAN_EDGE_TOKEN, name: edge-$1, report_interval_seconds: 1 }
state_dir: $2
sockets_dir: $3
socket_group: www-data
terminator: { binary: nginx, main_conf: /tmp/edge$1-nginx.conf, reload: signal, pid_file: /tmp/edge$1-nginx.pid }
acme: { contact: ["mailto:lab@example.test"] }
quic: { h3: auto, retry: true }
status_listen: 127.0.0.1:910$1
YAML
}
edge_yaml 1 $STATE1 $SOCKS1; edge_yaml 2 $STATE2 $SOCKS2
mkdir -p $SOCKS1 $SOCKS2
ns_of()  { [ "$1" = "1" ] && echo edge1 || echo edge2; }
ip_of()  { [ "$1" = "1" ] && echo $E1 || echo $E2; }
tok_of() { [ "$1" = "1" ] && echo a1tok || echo a2tok; }
start_edge() { # N
  KAPKAN_EDGE_TOKEN=$(tok_of "$1") SSL_CERT_FILE=/tmp/pebble.crt \
    ip netns exec "$(ns_of "$1")" "$KAPKAN" edge -config /tmp/edge$1.yaml -log-format text -log-level info >>/tmp/edge$1.log 2>&1 &
}
kill_node() { # N — the whole node at once, as a power cut would (arm D)
  kill -9 "$(cat /tmp/edge$1-nginx.pid 2>/dev/null)" 2>/dev/null
  pkill -9 -f "^$KAPKAN edge -config /tmp/edge$1.yaml" 2>/dev/null
}
sfield()  { ip netns exec "$(ns_of "$1")" curl -s -m2 "http://127.0.0.1:910$1/healthz" 2>/dev/null | jx "d.get('$2','')"; }
hcode()   { ip netns exec "$(ns_of "$1")" curl -s -o /dev/null -w '%{http_code}' -m2 "http://127.0.0.1:910$1/healthz" 2>/dev/null; }
nmetric() { ip netns exec "$(ns_of "$1")" curl -s -m2 "http://127.0.0.1:910$1/metrics" 2>/dev/null | grep -F "$2" | awk '{s+=$NF} END {print s+0}'; }
installs()   { grep -c 'configuration installed' /tmp/edge$1.log; }
certs_seen() { grep -c 'certificate issued' /tmp/edge$1.log; }
wait_healthy() { wait_eq "$2" true sfield "$1" healthy; }
settle() { local i g; for i in $(seq 1 30); do g=$(sfield "$1" generation); sleep 2; [ "$(sfield "$1" generation)" = "$g" ] && [ "$(sfield "$1" converged)" = "true" ] && return 0; done; return 1; }

# Request helpers. Everything a client does goes through the VIP unless an
# assertion is specifically about one node, in which case it resolves the
# name to that node's unicast address.
W_TCP='%{http_code} %header{x-kapkan-node}\n'
W_H3='%{http_code} %{http_version} %header{x-kapkan-node}\n'
H3TMO=5   # arm H shortens it: a QUIC handshake into a small-MTU path can only time out
vget()   { ip netns exec cli curl -s -o /dev/null -w "$W_TCP" -m5 --cacert /tmp/pebble-root.crt "https://$ZONE/${1:-$RANDOM}" 2>/dev/null; }
vh3get() { ip netns exec cli curl -s -o /dev/null -w "$W_H3" -m"$H3TMO" --http3-only --cacert /tmp/pebble-root.crt "https://$ZONE/${1:-$RANDOM}" 2>/dev/null; }
uget()   { local n=$1; shift; ip netns exec cli curl -s -o /dev/null -w "$W_TCP" -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$(ip_of "$n")" "$@" "https://$ZONE/${RANDOM}" 2>/dev/null; }
ubody()  { local n=$1; shift; ip netns exec cli curl -s -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$(ip_of "$n")" "$@" "https://$ZONE/${RANDOM}" 2>/dev/null; }
# batch N tcp|h3 FILE — N fresh connections through the VIP, one "code node"
# line each (h3 lines drop the version column once asserted).
batch() {
  local n=$1 mode=$2 out=$3 i
  : > "$out"
  for i in $(seq 1 "$n"); do
    if [ "$mode" = h3 ]; then vh3get "b$i-$RANDOM" | awk '{print $1, $3}' >> "$out"
    else vget "b$i-$RANDOM" >> "$out"; fi
  done
}
served()  { awk -v n="$1" '$2==n' "$2" 2>/dev/null | wc -l | tr -d ' '; }   # requests attributed to node n
n200()    { awk '$1=="200"' "$1" 2>/dev/null | wc -l | tr -d ' '; }
ncode()   { awk -v c="$1" '$1==c' "$2" 2>/dev/null | wc -l | tr -d ' '; }
nfail()   { awk '$1!="200"' "$1" 2>/dev/null | wc -l | tr -d ' '; }
mix()     { awk '{print $1}' "$1" 2>/dev/null | sort | uniq -c | tr -s ' \n' ' '; }
# batch_until N MODE FILE TRIES WANT200 — repeat a batch until WANT200 of N
# answers are 200, or TRIES are spent (recovery and settling waits)
batch_until() {
  local n=$1 mode=$2 out=$3 tries=$4 want=$5 i
  for i in $(seq 1 "$tries"); do batch "$n" "$mode" "$out"; [ "$(n200 "$out")" = "$want" ] && return 0; sleep 0.2; done
  return 1
}
is_page() { grep -q 'kapkan-puzzle' <<< "$1"; }

# browser.py ZONE IP COUNT COOKIEFILE: solves the clearance puzzle against ONE
# node (the name is the SNI and the Host, the address is where it connects) —
# arm G then offers the cookie it earned to the other node.
cat > /tmp/browser.py <<'PY'
import http.client, ssl, socket, sys, json, re, hashlib, urllib.parse
zone, ip, count, cookiefile = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
class C(http.client.HTTPSConnection):
    def _create_connection(self, address, timeout, source_address):
        return socket.create_connection((ip, 443), timeout, source_address)
def conn(): return C(zone, 443, context=ctx, timeout=6)
def bits(nonce, sol):
    h = hashlib.sha256((nonce + sol).encode()).digest()
    return 256 - int.from_bytes(h, "big").bit_length()
cookie = ""; codes = {}; solved = 0; pages = 0
for n in range(count):
    try:
        c = conn(); h = {"Cookie": "kapkan_clr=" + cookie} if cookie else {}
        c.request("GET", "/browser-%d" % n, headers=h); r = c.getresponse(); b = r.read().decode(errors="replace")
        codes[r.status] = codes.get(r.status, 0) + 1
        if r.status == 403 and "kapkan-puzzle" in b:
            pages += 1
            p = json.loads(re.search(r'id="kapkan-puzzle">(.*?)</script>', b, re.S).group(1))
            i = 0
            while bits(p["nonce"], str(i)) < p["difficulty"]:
                i += 1
            form = urllib.parse.urlencode({"nonce": p["nonce"], "solution": str(i), "return": p["return"]})
            c2 = conn(); c2.request("POST", "/_kapkan/clearance/answer", body=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
            r2 = c2.getresponse(); r2.read()
            m = re.search(r"kapkan_clr=([^;]+)", r2.getheader("Set-Cookie") or "")
            if r2.status == 303 and m:
                cookie = m.group(1); solved += 1; open(cookiefile, "w").write(cookie)
            c2.close()
        c.close()
    except Exception:
        codes["err"] = codes.get("err", 0) + 1
print(json.dumps({"codes": codes, "solved": solved, "pages": pages, "cookie": bool(cookie)}))
PY
# keepalive.py: one connection to each node, a request on each, then it waits
# for /tmp/ka-go before repeating them — so arm D can kill a node BETWEEN the
# two rounds and see which connection survived.
cat > /tmp/keepalive.py <<'PY'
import http.client, ssl, socket, sys, json, os, time
zone, ip1, ip2 = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
def mk(ip):
    class C(http.client.HTTPSConnection):
        def _create_connection(self, address, timeout, source_address):
            return socket.create_connection((ip, 443), timeout, source_address)
    return C(zone, 443, context=ctx, timeout=5)
def once(c, path):
    try:
        c.request("GET", path); r = c.getresponse(); r.read(); return r.status
    except Exception as e:
        return type(e).__name__
c1, c2 = mk(ip1), mk(ip2)
first = [once(c1, "/ka-1a"), once(c2, "/ka-2a")]
open("/tmp/ka-ready", "w").write("1")
for _ in range(600):
    if os.path.exists("/tmp/ka-go"):
        break
    time.sleep(0.1)
second = [once(c1, "/ka-1b"), once(c2, "/ka-2b")]
print(json.dumps({"first": first, "second": second}))
PY

# ================================================================ ARM A
say "ARM A — the fleet and a deterministic fan-out: the route is pinned to edge-2 for the whole issuance"
# With the VIP routed only to edge-2, every HTTP-01 request the CA makes lands
# on edge-2. So edge-1's certificate can ONLY have been validated by the
# challenge it published to the brain and the brain fanned out to edge-2 —
# there is no path by which edge-1 answered for itself.
route_one $E2 r-e2
[ "$(vip_route)" = "$VIP via $E2 dev r-e2 " ] && ok "the VIP is pinned to edge-2 for the issuance ($(vip_route))" || bad "route pin: $(vip_route)"
: > /tmp/edge1.log; : > /tmp/edge2.log
"$KAPKAN" edge -config /tmp/edge1.yaml -check 2>&1 | tee /tmp/check1.out | grep -q 'is valid' && ok "edge-1's edge.yaml passes -check" || bad "edge-1 -check: $(cat /tmp/check1.out)"
"$KAPKAN" edge -config /tmp/edge2.yaml -check 2>&1 | tee /tmp/check2.out | grep -q 'is valid' && ok "edge-2's edge.yaml passes -check (identical but for name, dirs and status_listen — the guide's rule)" || bad "edge-2 -check: $(cat /tmp/check2.out)"
start_edge 1; start_edge 2
wait_healthy 1 40 && ok "edge-1 healthy: a tested generation is live" || { bad "edge-1 never became healthy"; tail -10 /tmp/edge1.log; }
wait_healthy 2 40 && ok "edge-2 healthy" || { bad "edge-2 never became healthy"; tail -10 /tmp/edge2.log; }
for i in $(seq 1 900); do [ "$(certs_seen 1)" -ge 1 ] && [ "$(certs_seen 2)" -ge 2 ] && break; sleep 0.2; done
[ "$(certs_seen 1)" -ge 1 ] && ok "edge-1 has a certificate for $ZONE — validated on edge-2, through the fan-out" || { bad "edge-1 issued nothing in 180 s"; grep -i 'acme\|certif' /tmp/edge1.log | tail -3; }
[ "$(certs_seen 2)" -ge 2 ] && ok "edge-2 has its own certificates ($(certs_seen 2): $ZONE and the placed $ZONEB)" || { bad "edge-2 certificates: $(certs_seen 2)"; grep -i 'acme\|certif' /tmp/edge2.log | tail -3; }
grep -q 'edge acme challenge published.*node=edge-1' /tmp/brain.log && grep -q 'edge acme challenge published.*node=edge-2' /tmp/brain.log && ok "the brain fanned out a challenge published by each node" || bad "challenge publications: $(grep -c 'challenge published' /tmp/brain.log) lines, nodes $(grep -oE 'challenge published.*node=[a-z0-9-]+' /tmp/brain.log | grep -oE 'node=.*' | sort -u | tr '\n' ' ')"
grep -q 'slot requested.*granted=false' /tmp/brain.log && ok "at least one issuance slot was refused: the two nodes serialised on the zone ($(grep -c 'granted=false' /tmp/brain.log) refusals)" || bad "no refused slot in the brain log — the nodes never contended"
ip netns exec cli curl -sk -m3 https://$CA:15000/roots/0 > /tmp/pebble-root.crt 2>/dev/null
grep -q 'BEGIN CERTIFICATE' /tmp/pebble-root.crt && ok "fetched Pebble's root for the clients" || bad "could not fetch Pebble's root"
route_both
settle 1; settle 2
fp() { ip netns exec cli sh -c "openssl s_client -connect $1:443 -servername $ZONE -CAfile /tmp/pebble-root.crt </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" | cut -d= -f2; }
FP1=$(fp $E1); FP2=$(fp $E2)
[ -n "$FP1" ] && [ -n "$FP2" ] && [ "$FP1" != "$FP2" ] && ok "the two nodes serve DIFFERENT leaf certificates for one name (per-node ACME: ${FP1:0:17}… vs ${FP2:0:17}…)" || bad "leaf fingerprints: '$FP1' / '$FP2'"
[ "$(inv_f "d['nodes_total']")" = "2" ] && [ "$(node_f edge-1 "n['alive']")" = "true" ] && [ "$(node_f edge-2 "n['alive']")" = "true" ] && ok "inventory: two nodes, both alive" || bad "inventory: $(inv_f "d['nodes_total']") nodes, alive $(node_f edge-1 "n['alive']")/$(node_f edge-2 "n['alive']")"
[ -n "$(node_f edge-1 "n['report']['zones_etag']")" ] && [ "$(node_f edge-1 "n['report']['zones_etag']")" = "$(node_f edge-2 "n['report']['zones_etag']")" ] && ok "both nodes report the same zones_etag ($(node_f edge-1 "n['report']['zones_etag']")) — one document, one fleet" || bad "zones_etag: $(node_f edge-1 "n['report']['zones_etag']") vs $(node_f edge-2 "n['report']['zones_etag']")"
api op "$B/edge/nodes" > /tmp/inventory.json
grep -qE 'PRIVATE KEY|BEGIN CERTIFICATE|privkey' /tmp/inventory.json && bad "the inventory carries key or certificate bytes" || ok "no key bytes anywhere in the reports ($(wc -c < /tmp/inventory.json) bytes of inventory, certificates named by zone/not_after/issuer only)"
r=$(vget hello); [ "${r%% *}" = "200" ] && ok "the zone is served through the VIP ($(awk '{print $2}' <<< "$r"))" || bad "the VIP does not serve: '$r'"
case "$(awk '{print $2}' <<< "$r")" in
  edge-1|edge-2) ok "the operator's X-Kapkan-Node header names the serving node (\$hostname from its own UTS namespace)";;
  *) bad "no usable X-Kapkan-Node header: '$r'";;
esac
r=$(vh3get h3-hello)
case "$r" in
  "200 3 edge-1"|"200 3 edge-2") ok "…and over HTTP/3 through the VIP ('$r'): nginx answers its wildcard QUIC listener from the address the client used";;
  *) bad "h3 through the VIP: '$r'";;
esac
[ "$(ip netns exec cli curl -s -o /dev/null -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONEB:443:$E2" "https://$ZONEB/x" 2>/dev/null)" = "200" ] && ok "the placed zone $ZONEB is served by edge-2 on its own address (E6.3 placement: only edge-2 lists pop-b)" || bad "$ZONEB on edge-2: $(ip netns exec cli curl -s -o /dev/null -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONEB:443:$E2" "https://$ZONEB/x" 2>/dev/null)"
[ ! -f $STATE1/conf/live/kapkan_zone_$ZONEB.conf ] && ok "edge-1 never renders $ZONEB" || bad "$ZONEB rendered on edge-1"

# ================================================================ ARM B
say "ARM B — the two hash forms: L3 pins a client to one node, L4 spreads it (TCP and HTTP/3 alike)"
hashpol 0
[ "$(ip netns exec rtr cat /proc/sys/net/ipv4/fib_multipath_hash_policy)" = "0" ] && ok "fib_multipath_hash_policy 0 (layer 3: source and destination address)" || bad "hash policy not 0"
batch 40 tcp /tmp/b-l3.txt
[ "$(n200 /tmp/b-l3.txt)" = "40" ] && ok "40 of 40 requests served under L3 ($(mix /tmp/b-l3.txt))" || bad "L3 batch: $(mix /tmp/b-l3.txt)"
L3NODES=$(awk '{print $2}' /tmp/b-l3.txt | sort -u | tr '\n' ' ')
[ "$(awk '{print $2}' /tmp/b-l3.txt | sort -u | wc -l | tr -d ' ')" = "1" ] && ok "every one of the 40 connections carried the SAME X-Kapkan-Node ($L3NODES): flow-consistent by source address" || bad "L3 spread over $L3NODES — the hash is not address-only"
hashpol 1
[ "$(ip netns exec rtr cat /proc/sys/net/ipv4/fib_multipath_hash_policy)" = "1" ] && ok "fib_multipath_hash_policy 1 (layer 4: the 4-tuple)" || bad "hash policy not 1"
batch 40 tcp /tmp/b-l4.txt
B4_1=$(served edge-1 /tmp/b-l4.txt); B4_2=$(served edge-2 /tmp/b-l4.txt)
[ "$(n200 /tmp/b-l4.txt)" = "40" ] && [ "$B4_1" -ge 1 ] && [ "$B4_2" -ge 1 ] && ok "under L4 one client's 40 TCP connections reached BOTH nodes (edge-1 $B4_1, edge-2 $B4_2)" || bad "L4 TCP spread: edge-1 $B4_1, edge-2 $B4_2, codes $(mix /tmp/b-l4.txt)"
H1_0=$(nmetric 1 'kapkan_edge_requests_total{protocol="h3"'); H2_0=$(nmetric 2 'kapkan_edge_requests_total{protocol="h3"')
batch 40 h3 /tmp/b-h3.txt
H4_1=$(served edge-1 /tmp/b-h3.txt); H4_2=$(served edge-2 /tmp/b-h3.txt)
[ "$(n200 /tmp/b-h3.txt)" = "40" ] && [ "$H4_1" -ge 1 ] && [ "$H4_2" -ge 1 ] && ok "…and so did 40 --http3-only requests (edge-1 $H4_1, edge-2 $H4_2): the same policy hashes the UDP 4-tuple" || bad "L4 h3 spread: edge-1 $H4_1, edge-2 $H4_2, codes $(mix /tmp/b-h3.txt)"
sleep 12   # the rollup closes 10 s windows; h3_requests is per window
H1=$(nmetric 1 'kapkan_edge_requests_total{protocol="h3"'); H2=$(nmetric 2 'kapkan_edge_requests_total{protocol="h3"')
[ "$H1" -gt "$H1_0" ] && [ "$H2" -gt "$H2_0" ] && ok "both nodes counted h3 requests of their own (kapkan_edge_requests_total protocol=h3: +$((H1-H1_0)) and +$((H2-H2_0)); the report's h3_requests is the same count per window)" || bad "h3 counted on one node only: edge-1 $H1_0->$H1, edge-2 $H2_0->$H2"
[ "$(zst $ZONE "sorted(z.get('h3',{}).get('serving',[]))")" = "['edge-1', 'edge-2']" ] && ok "the fleet status names both nodes under h3.serving" || bad "h3.serving: $(zst $ZONE "z.get('h3')")"

# ================================================================ ARM C
say "ARM C — the per-node ceilings: what a low policy.rate.rps means under each hash form"
# A 429 does NOT carry the node header (the render's @kapkan_denied declares
# its own add_header, and nginx drops the inherited set wherever a location
# declares one), so refusals are attributed at the decider's own metric.
ZONE_RPS=5; zones_yaml; ET1=$(sfield 1 accepted_etag); reload_brain
wait_ne 15 "$ET1" sfield 1 accepted_etag && ok "the low ceiling (rps 5) reached the nodes on the fast path" || bad "the rate change never reached edge-1"
sleep 1.5
dr() { nmetric "$1" 'kapkan_edge_decisions_total{result="deny_rate"'; }
hashpol 0
D1_0=$(dr 1); D2_0=$(dr 2); batch 40 tcp /tmp/c-l3.txt
C3_429=$(ncode 429 /tmp/c-l3.txt); C3_200=$(ncode 200 /tmp/c-l3.txt); D1_3=$(( $(dr 1) - D1_0 )); D2_3=$(( $(dr 2) - D2_0 ))
[ "$C3_429" -ge 1 ] && ok "under L3 the burst is refused: $C3_429 of 40 answered 429, $C3_200 served" || bad "no 429 under L3 at rps 5: $(mix /tmp/c-l3.txt)"
[ $(( D1_3 * D2_3 )) -eq 0 ] && [ $(( D1_3 + D2_3 )) -ge 1 ] && ok "every rate denial came from ONE node (deny_rate: edge-1 +$D1_3, edge-2 +$D2_3) — one ceiling, as configured" || bad "rate denials on both nodes under L3: edge-1 +$D1_3, edge-2 +$D2_3"
sleep 2
hashpol 1
D1_0=$(dr 1); D2_0=$(dr 2); batch 40 tcp /tmp/c-l4.txt
C4_429=$(ncode 429 /tmp/c-l4.txt); C4_200=$(ncode 200 /tmp/c-l4.txt); D1_4=$(( $(dr 1) - D1_0 )); D2_4=$(( $(dr 2) - D2_0 ))
[ "$C4_429" -ge 1 ] && [ "$D1_4" -ge 1 ] && [ "$D2_4" -ge 1 ] && ok "under L4 BOTH nodes refused ($C4_429 of 40 were 429, deny_rate edge-1 +$D1_4, edge-2 +$D2_4): the ceiling is per node, and the source met two of them" || bad "L4 ceilings: 429s $C4_429, deny_rate edge-1 +$D1_4, edge-2 +$D2_4"
python3 - "$C3_200" "$C4_200" "$C3_429" "$C4_429" "$D1_3" "$D2_3" "$D1_4" "$D2_4" > /tmp/arm-c.txt <<'PY'
import sys
l3_200, l4_200, l3_429, l4_429, d13, d23, d14, d24 = (int(x) for x in sys.argv[1:9])
ratio = (l4_200 / l3_200) if l3_200 else 0.0
print(f"policy.rate.rps 5, 40 connections from one source, two nodes:")
print(f"  L3 (policy 0): served {l3_200}, refused {l3_429} (429 share {l3_429/40*100:.0f}%), deny_rate edge-1 {d13} edge-2 {d23}")
print(f"  L4 (policy 1): served {l4_200}, refused {l4_429} (429 share {l4_429/40*100:.0f}%), deny_rate edge-1 {d14} edge-2 {d24}")
print(f"  the source got {ratio:.1f}x the admitted requests under L4 (the guide's \"up to N x the ceiling\", N = the node count = 2)")
PY
sed 's/^/  /' /tmp/arm-c.txt
grep -q 'x the admitted' /tmp/arm-c.txt && ok "the L3-vs-L4 shares are recorded for the guide (/tmp/arm-c.txt)" || bad "arm C recorded nothing"
# top_sources rides a CLOSED 10 s window, so give the rollup two of them.
srcs() { api op "$B/edge/nodes" | jx "[s['source'] for z in ([n for n in d['nodes'] if n['name']=='edge-$1']+[{}])[0].get('report',{}).get('zones',[]) if z['zone']=='$ZONE' for s in z.get('top_sources',[])]"; }
for i in $(seq 1 60); do
  srcs 1 > /tmp/c-src-1.txt; srcs 2 > /tmp/c-src-2.txt
  grep -q "$CLI" /tmp/c-src-1.txt && grep -q "$CLI" /tmp/c-src-2.txt && break
  sleep 0.5
done
grep -q "$CLI" /tmp/c-src-1.txt && grep -q "$CLI" /tmp/c-src-2.txt && ok "the bursting source appears in BOTH nodes' top_sources — each node saw it, neither saw the whole of it (a rate-refused source is reported \`allow\`: over its ceiling is not a table denial)" || bad "top_sources: edge-1 $(cat /tmp/c-src-1.txt), edge-2 $(cat /tmp/c-src-2.txt)"
ZONE_RPS=1000; zones_yaml; reload_brain; sleep 1.5

# ================================================================ ARM D
say "ARM D — a node dies and nobody withdraws: the route still points at it"
ROUTE0=$(vip_route)
rm -f /tmp/ka-ready /tmp/ka-go
ip netns exec cli python3 /tmp/keepalive.py $ZONE $E1 $E2 > /tmp/keepalive.out 2>&1 &
KA_PID=$!
for i in $(seq 1 60); do [ -f /tmp/ka-ready ] && break; sleep 0.2; done
[ -f /tmp/ka-ready ] && ok "a keepalive connection is open to each node" || bad "keepalive.py never got its first round through: $(cat /tmp/keepalive.out)"
KILL0=$(date +%s%N)
kill_node 2
sleep 0.5; touch /tmp/ka-go
batch 40 tcp /tmp/d-dead.txt
D_FAIL=$(nfail /tmp/d-dead.txt); D_OK=$(n200 /tmp/d-dead.txt)
[ "$D_FAIL" -ge 1 ] && [ "$D_OK" -ge 1 ] && ok "with the route untouched $D_FAIL of 40 requests failed and $D_OK were served — the hash keeps sending a share to a dead node ($(mix /tmp/d-dead.txt))" || bad "dead-node batch: $(mix /tmp/d-dead.txt)"
[ "$(served edge-2 /tmp/d-dead.txt)" = "0" ] && ok "nothing was served BY edge-2 (every success names edge-1)" || bad "edge-2 served after the kill"
wait "$KA_PID" 2>/dev/null
KA=$(cat /tmp/keepalive.out)
[ "$(jx "d['second'][0]" <<< "$KA")" = "200" ] && [ "$(jx "d['second'][1]" <<< "$KA")" != "200" ] && ok "the keepalive connection to edge-1 survived and the one to edge-2 broke ($KA)" || bad "keepalive across the kill: $KA"
wait_eq 20 false node_f edge-2 "n['alive']" && D_LOST_MS=$(( ($(date +%s%N) - KILL0) / 1000000 )) && ok "the inventory marks edge-2 alive:false ${D_LOST_MS} ms after the kill (stale_after_seconds $STALE)" || { D_LOST_MS=0; bad "edge-2 still alive: $(node_f edge-2 "n['alive']")"; }
[ "$(node_f edge-1 "n['alive']")" = "true" ] && ok "edge-1 is untouched by its neighbour's death" || bad "edge-1 alive: $(node_f edge-1 "n['alive']")"
[ "$(vip_route)" = "$ROUTE0" ] && ok "the router's VIP route is byte-identical: the brain never touches routing for a zone address ($ROUTE0)" || bad "the VIP route changed by itself: '$ROUTE0' -> '$(vip_route)'"
grep -qE 'withdraw|announce' /tmp/brain.log && bad "the brain logged an announcement or a withdrawal" || ok "the brain's log has no announce/withdraw line at all (its BGP speaker is about victims, never a zone's VIP)"

say "ARM D2 — the link down instead: a dead nexthop needs no operator, a dead node does"
ip netns exec rtr ip link set r-e2 down
sleep 0.5
ip netns exec rtr ip route show $VIP/32 > /tmp/d2-route.txt
grep -qE 'dead|linkdown' /tmp/d2-route.txt && ok "the nexthop via edge-2 is marked dead ($(tr -s ' \n' ' ' < /tmp/d2-route.txt))" || bad "no dead nexthop after the link went down: $(tr -s ' \n' ' ' < /tmp/d2-route.txt)"
batch 40 tcp /tmp/d2-linkdown.txt
[ "$(n200 /tmp/d2-linkdown.txt)" = "40" ] && ok "40 of 40 served with no operator action: a directly connected router notices link loss, a routed hop does not" || bad "link-down batch: $(mix /tmp/d2-linkdown.txt)"
ip netns exec rtr ip link set r-e2 up
sleep 1
batch 10 tcp /tmp/d2-back.txt
[ "$(n200 /tmp/d2-back.txt)" -lt 10 ] && ok "the link back up and the node still dead: the failures return ($(mix /tmp/d2-back.txt)) — link state is not health" || bad "no failures with the link up and the node dead: $(mix /tmp/d2-back.txt)"
T0=$(date +%s%N); route_one $E1 r-e1
for i in $(seq 1 100); do batch 5 tcp /tmp/d2-probe.txt; [ "$(n200 /tmp/d2-probe.txt)" = "5" ] && break; done
D2_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
batch 40 tcp /tmp/d2-withdrawn.txt; batch 20 h3 /tmp/d2-withdrawn-h3.txt
[ "$(n200 /tmp/d2-withdrawn.txt)" = "40" ] && [ "$(n200 /tmp/d2-withdrawn-h3.txt)" = "20" ] && ok "after the operator's withdrawal (one \`ip route replace … via edge-1\`) 40 of 40 TCP and 20 of 20 HTTP/3 requests are served, in ${D2_MS} ms from the RIB change" || bad "after the withdrawal: TCP $(mix /tmp/d2-withdrawn.txt), h3 $(mix /tmp/d2-withdrawn-h3.txt)"
C2_0=$(certs_seen 2)
node_nginx 2 edge2 $STATE2; sleep 0.6; start_edge 2
wait_healthy 2 30 && ok "edge-2 restarted (its render came back from disk)" || bad "edge-2 did not come back"
wait_eq 15 true node_f edge-2 "n['alive']" && ok "the inventory has it alive again at its first poll" || bad "edge-2 not alive after the restart"
sleep 3
[ "$(certs_seen 2)" = "$C2_0" ] && ok "the restarted node ordered nothing new: its certificates came back from disk (\`certificate issued\` still $C2_0)" || bad "edge-2 re-issued after a restart: $C2_0 -> $(certs_seen 2) lines"
route_both

# ================================================================ ARM E
say "ARM E — the withdrawal signal: a refused document is not one, a dead terminator is"
# (i) A broken extra_directives_file on the zone only edge-2 serves: only
# edge-2 renders it, so only edge-2's `nginx -t` fails. Its previous
# generation keeps serving (§2.4) — and that is exactly why converged:false
# must never drive a withdrawal.
G2=$(sfield 2 generation); I2=$(installs 2)
ZONEB_EXTRA=$EXTRA_BROKEN; zones_yaml; reload_brain
wait_eq 40 false sfield 2 converged && ok "edge-2 reports converged:false — it refused the broken document" || bad "edge-2 converged: $(sfield 2 converged)"
[ "$(hcode 2)" = "200" ] && ok "…and /healthz still answers 200: the tested generation it already had is live" || bad "/healthz on a refused document: $(hcode 2)"
[ "$(sfield 2 generation)" = "$G2" ] && [ "$(installs 2)" = "$I2" ] && ok "no new generation went live on edge-2 (still $G2)" || bad "the broken document installed: gen $G2 -> $(sfield 2 generation)"
[ "$(sfield 1 converged)" = "true" ] && ok "edge-1 is converged throughout: it never renders that zone" || bad "edge-1 converged: $(sfield 1 converged)"
batch 20 tcp /tmp/e-refused.txt
[ "$(n200 /tmp/e-refused.txt)" = "20" ] && [ "$(served edge-2 /tmp/e-refused.txt)" -ge 1 ] && ok "20 of 20 requests served through the VIP, edge-2 among them ($(served edge-1 /tmp/e-refused.txt)/$(served edge-2 /tmp/e-refused.txt)) — NOT a reason to withdraw" || bad "VIP under a refused document: $(mix /tmp/e-refused.txt), edge-2 served $(served edge-2 /tmp/e-refused.txt)"
ZONEB_EXTRA=""; zones_yaml; reload_brain
wait_eq 40 true sfield 2 converged && ok "the file fixed: edge-2 converges again" || bad "edge-2 did not converge after the fix"
# (ii) The terminator itself gone, with terminator.pid_file set: THAT is the
# signal — and the brain's inventory does not have it, because the node is
# still polling perfectly well.
kill "$(cat /tmp/edge2-nginx.pid 2>/dev/null)" 2>/dev/null
T0=$(date +%s%N)
for i in $(seq 1 50); do [ "$(hcode 2)" = "503" ] && break; sleep 0.1; done
E_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
[ "$(hcode 2)" = "503" ] && ok "/healthz on edge-2 turned 503 in ${E_MS} ms of nginx dying (terminator.pid_file is what makes this observable)" || bad "/healthz after killing nginx: $(hcode 2)"
[ "$(node_f edge-2 "n['alive']")" = "true" ] && ok "…while the brain's inventory still says alive:true — the node's own signal fired, the inventory's did not (never withdraw on \`alive\`)" || bad "inventory alive after the nginx kill: $(node_f edge-2 "n['alive']")"
[ "$(node_f edge-2 "n['report']['terminator']['alive']")" = "false" ] && ok "the node's report does say terminator.alive:false (the honest field, one poll behind)" || bad "report terminator.alive: $(node_f edge-2 "n['report']['terminator']['alive']")"
node_nginx 2 edge2 $STATE2; sleep 0.8
wait_eq 20 200 hcode 2 && ok "nginx restarted on its live configuration: /healthz 200 again" || bad "/healthz after the nginx restart: $(hcode 2)"
batch_until 10 tcp /tmp/e-back.txt 50 10
[ "$(n200 /tmp/e-back.txt)" = "10" ] && [ "$(served edge-2 /tmp/e-back.txt)" -ge 1 ] && ok "the VIP serves from both nodes again ($(served edge-1 /tmp/e-back.txt)/$(served edge-2 /tmp/e-back.txt))" || bad "after the nginx restart: $(mix /tmp/e-back.txt), edge-2 $(served edge-2 /tmp/e-back.txt)"

# ================================================================ ARM F
say "ARM F — the brain dead: the fleet is fail-static behind one address"
kill_brain && ok "the brain is dead" || bad "the brain is still answering"
batch 20 tcp /tmp/f-nobrain.txt; batch 20 h3 /tmp/f-nobrain-h3.txt
[ "$(n200 /tmp/f-nobrain.txt)" = "20" ] && [ "$(served edge-1 /tmp/f-nobrain.txt)" -ge 1 ] && [ "$(served edge-2 /tmp/f-nobrain.txt)" -ge 1 ] && ok "20 of 20 TCP requests served by both nodes with the brain dead" || bad "TCP with the brain dead: $(mix /tmp/f-nobrain.txt), $(served edge-1 /tmp/f-nobrain.txt)/$(served edge-2 /tmp/f-nobrain.txt)"
[ "$(n200 /tmp/f-nobrain-h3.txt)" = "20" ] && ok "…and 20 of 20 over HTTP/3" || bad "h3 with the brain dead: $(mix /tmp/f-nobrain-h3.txt)"
[ "$(hcode 1)" = "200" ] && [ "$(hcode 2)" = "200" ] && ok "both /healthz stay 200: the brain is not in the health predicate" || bad "healthz with the brain dead: $(hcode 1)/$(hcode 2)"
mv /tmp/brain.log /tmp/brain-1.log; T0=$(date +%s%N); start_brain
wait_eq 15 true node_f edge-1 "n['alive']" && wait_eq 15 true node_f edge-2 "n['alive']" && ok "the brain came back and both nodes are alive again in $(( ($(date +%s%N) - T0) / 1000000 )) ms" || bad "nodes after the brain's return: $(node_f edge-1 "n['alive']")/$(node_f edge-2 "n['alive']")"

# ================================================================ ARM G
say "ARM G — the two cross-node facts a shared address exposes"
# A TLS session is bound to the node's own certificate through the session id
# context (spec §3), so it is not resumable on the other node. TLS 1.3 has no
# session ids and kapkan renders `ssl_session_tickets off`, so there is nothing
# to resume there at all (E5 asserts that); 1.2 with the shared cache is the
# form where a resumption CAN be offered — and is refused across nodes.
ip netns exec cli sh -c "printf 'GET /g HTTP/1.1\r\nHost: $ZONE\r\nConnection: close\r\n\r\n' | openssl s_client -connect $E1:443 -servername $ZONE -CAfile /tmp/pebble-root.crt -tls1_2 -sess_out /tmp/g.sess -ign_eof" >/tmp/g-out1.txt 2>&1
[ -s /tmp/g.sess ] && ok "a TLS 1.2 session was saved from edge-1" || bad "no session saved from edge-1: $(grep -iE 'session|error' /tmp/g-out1.txt | head -2 | tr '\n' ' ')"
ip netns exec cli openssl s_client -connect $E1:443 -servername $ZONE -CAfile /tmp/pebble-root.crt -tls1_2 -sess_in /tmp/g.sess </dev/null >/tmp/g-same.txt 2>&1
ip netns exec cli openssl s_client -connect $E2:443 -servername $ZONE -CAfile /tmp/pebble-root.crt -tls1_2 -sess_in /tmp/g.sess </dev/null >/tmp/g-other.txt 2>&1
grep -q 'Reused, TLSv1.2' /tmp/g-same.txt && ok "offered back to edge-1 it is Reused" || bad "resumption on the same node: $(grep -oE 'New|Reused, TLS[^,]*' /tmp/g-same.txt | head -1)"
grep -q 'Reused' /tmp/g-other.txt && bad "edge-2 RESUMED a session from edge-1 — the sid_ctx binding is not holding" || ok "offered to edge-2 it is New ($(grep -oE 'New, TLS[^,]*' /tmp/g-other.txt | head -1)): one full handshake is the whole price of changing node"
# The clearance cookie is the opposite case, and deliberately so: the keys are
# the fleet's, so a visitor cleared on one node is cleared on all of them.
ET1=$(sfield 1 accepted_etag); ET2=$(sfield 2 accepted_etag)
[ "$(lever POST $ZONE '{"mode":"manual","ttl_seconds":300,"reason":"rig arm G"}')" = "200" ] && ok "the challenge rung is on for the zone (the lever, no reload)" || bad "lever: $(lever POST $ZONE '{"mode":"manual","ttl_seconds":300,"reason":"rig arm G"}')"
wait_ne 15 "$ET1" sfield 1 accepted_etag && wait_ne 15 "$ET2" sfield 2 accepted_etag && ok "both nodes took the lever in one poll" || bad "the lever did not reach both nodes"
sleep 0.5
b=$(ubody 1); is_page "$b" && ok "a plain client gets the clearance page from edge-1" || bad "no page on edge-1: $(cut -c1-100 <<< "$b")"
rm -f /tmp/cookie-g
ip netns exec cli python3 /tmp/browser.py $ZONE $E1 2 /tmp/cookie-g > /tmp/browser-g.out 2>&1
[ "$(jx "d['solved']" < /tmp/browser-g.out)" = "1" ] && ok "a browser solved the puzzle on edge-1 and earned its cookie" || bad "browser on edge-1: $(cat /tmp/browser-g.out)"
COOKIE=$(cat /tmp/cookie-g 2>/dev/null); : > /tmp/origin.log
r=$(uget 2 -H "Cookie: kapkan_clr=$COOKIE")
[ "${r%% *}" = "200" ] && ok "the same cookie is honoured on edge-2 ('$r'): clearance keys are the fleet's, not the node's" || bad "the cookie on edge-2: '$r'"
grep -q '"mark": "cleared"' /tmp/origin.log && ok "…and the origin sees X-Kapkan-Mark: cleared on the request edge-2 forwarded" || bad "no cleared mark at the origin: $(tail -1 /tmp/origin.log)"
lever DELETE $ZONE >/dev/null; sleep 1.5
batch_until 10 tcp /tmp/g-off.txt 50 10
[ "$(n200 /tmp/g-off.txt)" = "10" ] && ok "the rung off again: 10 of 10 served through the VIP" || bad "after clearing the lever: $(mix /tmp/g-off.txt)"

# ================================================================ ARM H
say "ARM H — MTU 1200 on ONE leg: HTTP/3 breaks for that node's share, TCP does not"
ip netns exec rtr ip link set r-e2 mtu 1200; ip netns exec edge2 ip link set e2-r mtu 1200
sleep 0.5
H3TMO=2   # a QUIC handshake into a 1200-byte path cannot complete; it can only time out
batch 40 h3 /tmp/h-h3.txt; H3TMO=5
batch 40 tcp /tmp/h-tcp.txt
H_FAIL=$(nfail /tmp/h-h3.txt)
[ "$H_FAIL" -ge 1 ] && [ "$H_FAIL" -lt 40 ] && ok "$H_FAIL of 40 --http3-only requests failed — the share hashed to the small-MTU leg (QUIC's floor is 1280 and no client goes below it) ($(mix /tmp/h-h3.txt))" || bad "h3 under a 1200-byte leg: $(mix /tmp/h-h3.txt)"
[ "$(awk '$1=="200" && $2=="edge-2"' /tmp/h-h3.txt | wc -l | tr -d ' ')" = "0" ] && ok "every h3 success came from the untouched node" || bad "edge-2 served h3 over a 1200-byte path"
[ "$(n200 /tmp/h-tcp.txt)" = "40" ] && [ "$(served edge-2 /tmp/h-tcp.txt)" -ge 1 ] && ok "40 of 40 TCP requests served, edge-2 among them ($(served edge-1 /tmp/h-tcp.txt)/$(served edge-2 /tmp/h-tcp.txt)): TCP clamps its MSS, QUIC has a floor" || bad "TCP under a 1200-byte leg: $(mix /tmp/h-tcp.txt), edge-2 $(served edge-2 /tmp/h-tcp.txt)"
ip netns exec rtr ip link set r-e2 mtu 1500; ip netns exec edge2 ip link set e2-r mtu 1500
sleep 0.5
batch 20 h3 /tmp/h-back.txt
[ "$(n200 /tmp/h-back.txt)" = "20" ] && [ "$(served edge-2 /tmp/h-back.txt)" -ge 1 ] && ok "the MTU restored: 20 of 20 over HTTP/3, both nodes serving again" || bad "h3 after the MTU restore: $(mix /tmp/h-back.txt), edge-2 $(served edge-2 /tmp/h-back.txt)"

# ================================================================ ARM I (stretch)
say "ARM I — the withdrawal contract driven by a real speaker (stretch, ANYCAST_BGP=$ANYCAST_BGP, outside the acceptance path)"
if [ "$ANYCAST_BGP" != "1" ]; then
  echo "  (skipped: set ANYCAST_BGP=1 to install bird2 and run it — the guide's example, never a Kapkan component)"
else
  apt-get install -y -qq bird2 >/tmp/bird-install.log 2>&1
  if ! command -v bird >/dev/null; then
    echo "  (skipped: bird2 is not installable in this container — $(tail -1 /tmp/bird-install.log))"
  else
    ok "bird2 installed ($(bird --version 2>&1 | head -1))"
    # The router accepts both announcements and merges them into one ECMP
    # route; each node announces the VIP /32 with itself as the next hop.
    cat > /tmp/bird-rtr.conf <<CONF
router id 10.0.0.254;
log stderr all;
protocol device { }
protocol kernel { ipv4 { export all; }; merge paths on; learn off; }
protocol bgp e1 { local as 65100; neighbor $E1 as 65001; ipv4 { import all; export none; }; multihop 2; }
protocol bgp e2 { local as 65100; neighbor $E2 as 65002; ipv4 { import all; export none; }; multihop 2; }
CONF
    node_bird() { # N ASN OWNIP PEERIP
      cat > /tmp/bird-e$1.conf <<CONF
router id $3;
log stderr all;
protocol device { }
protocol static announce {
  ipv4;
  route $VIP/32 via "lo";
  disabled;
}
protocol bgp rtr { local as $2; neighbor $4 as 65100; ipv4 { import none; export all; }; multihop 2; }
CONF
      mkdir -p /run/bird-e$1
      ip netns exec "$(ns_of "$1")" bird -c /tmp/bird-e$1.conf -s /run/bird-e$1/ctl -P /run/bird-e$1/pid -f >>/tmp/bird-e$1.log 2>&1 &
    }
    # The router's own static route must go: BGP owns the VIP for this arm.
    ip netns exec rtr ip route del $VIP/32 2>/dev/null
    mkdir -p /run/bird-rtr
    ip netns exec rtr bird -c /tmp/bird-rtr.conf -s /run/bird-rtr/ctl -P /run/bird-rtr/pid -f >>/tmp/bird-rtr.log 2>&1 &
    node_bird 1 65001 $E1 $R1; node_bird 2 65002 $E2 $R2
    sleep 2
    # The health loop the guide prescribes: announce while /healthz answers
    # 200 on the node's OWN address, withdraw the moment it does not.
    for n in 1 2; do
      cat > /tmp/announce-$n.sh <<SH
#!/bin/sh
while :; do
  if curl -sf -m1 -o /dev/null http://127.0.0.1:910$n/healthz; then
    birdc -s /run/bird-e$n/ctl enable announce >/dev/null 2>&1
  else
    birdc -s /run/bird-e$n/ctl disable announce >/dev/null 2>&1
  fi
  sleep 1
done
SH
      chmod 755 /tmp/announce-$n.sh
      ip netns exec "$(ns_of "$n")" /tmp/announce-$n.sh >>/tmp/announce-$n.log 2>&1 &
    done
    for i in $(seq 1 60); do [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && break; sleep 0.5; done
    [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && ok "both announcements are in the router's FIB as one multipath route ($(vip_route))" || bad "bird did not produce a multipath route: $(vip_route)"
    batch 20 tcp /tmp/i-both.txt
    [ "$(n200 /tmp/i-both.txt)" = "20" ] && [ "$(served edge-2 /tmp/i-both.txt)" -ge 1 ] && ok "20 of 20 served over the announced route, both nodes" || bad "over the announced route: $(mix /tmp/i-both.txt)"
    T0=$(date +%s%N)
    kill "$(cat /tmp/edge2-nginx.pid 2>/dev/null)" 2>/dev/null
    for i in $(seq 1 200); do batch 5 tcp /tmp/i-probe.txt; [ "$(n200 /tmp/i-probe.txt)" = "5" ] && [ "$(served edge-1 /tmp/i-probe.txt)" = "5" ] && break; sleep 0.2; done
    I_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
    batch 40 tcp /tmp/i-withdrawn.txt
    [ "$(n200 /tmp/i-withdrawn.txt)" = "40" ] && [ "$(served edge-1 /tmp/i-withdrawn.txt)" = "40" ] && ok "nginx killed on edge-2: /healthz 503 -> the protocol disabled -> the nexthop left the FIB -> 40 of 40 on edge-1, ${I_MS} ms from kill to all-edge-1" || bad "after the speaker's withdrawal: $(mix /tmp/i-withdrawn.txt), edge-1 $(served edge-1 /tmp/i-withdrawn.txt)"
    echo "  bird2: kill -> all-edge-1 in ${I_MS} ms" >> /tmp/arm-i.txt
    node_nginx 2 edge2 $STATE2; sleep 1
    for i in $(seq 1 60); do [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && break; sleep 0.5; done
    [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && ok "nginx back: the announcement returns and the route is multipath again" || bad "the route did not come back: $(vip_route)"
    G2=$(sfield 2 generation); ZONEB_EXTRA=$EXTRA_BROKEN; zones_yaml; reload_brain
    wait_eq 40 false sfield 2 converged || bad "edge-2 did not refuse the broken document (arm I)"
    sleep 3
    [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && ok "a refused document did NOT withdraw the route: /healthz stayed 200, so the speaker stayed enabled" || bad "a refused document withdrew the route: $(vip_route)"
    ZONEB_EXTRA=""; zones_yaml; reload_brain
    pkill -f '^/tmp/announce' 2>/dev/null; pkill -f 'bird -c' 2>/dev/null
    route_both
  fi
fi

# ================================================================ summary
{
  echo "E6.9 anycast rig — recorded numbers"
  echo
  cat /tmp/arm-c.txt
  echo
  echo "arm D  (a node dies, nobody withdraws): $D_FAIL of 40 requests failed, $D_OK served;"
  echo "       the inventory said alive:false ${D_LOST_MS} ms after the kill (stale_after_seconds $STALE)"
  echo "arm D2 (the operator's withdrawal): 40/40 TCP and 20/20 h3 within ${D2_MS} ms of \`ip route replace\`"
  echo "arm E  (the node's own signal): /healthz turned 503 ${E_MS} ms after nginx died"
  echo "arm H  (MTU 1200 on one leg): $H_FAIL of 40 h3 requests failed, 40/40 TCP served"
  [ -f /tmp/arm-i.txt ] && cat /tmp/arm-i.txt
} > /tmp/numbers.txt
echo
sed 's/^/  /' /tmp/numbers.txt
echo
echo "== E6.9 anycast acceptance: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
