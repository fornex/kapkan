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
#      inventory has two alive nodes each on its OWN document (they differ
#      under placement, so a shared zones_etag is not a fleet-health signal;
#      the zone they share is byte-identical in both), no key bytes in it;
#   B. the two hash forms: L3 (policy 0) pins one client to one node for 40
#      connections; L4 (policy 1) spreads it over both, over TCP and over
#      HTTP/3 alike — the same policy governs the UDP 4-tuple;
#   C. the per-node ceilings under each form: `policy.rate.rps` is enforced
#      per node, so under L4 one source gets up to N× the ceiling. The share
#      is RECORDED with the batch's duration beside it — those are the guide's
#      numbers. Under L3 the same burst concentrates on ONE node, crosses the
#      rollup's flood rule there and is promoted to a table denial for
#      DenyTTL: the arm asserts that too, because an operator picking a low
#      per-node rps under L3 must know it;
#   D. a node dies and nobody withdraws: the route still points at it, so a
#      share of requests fails while the rest are served; keepalive to the
#      dead node breaks and to the live one survives; the inventory says
#      `alive:false` `stale_after` after its last sighting and the brain
#      touches no route.
#      D2: the link down instead — the nexthop goes `dead` and every request
#      is served without any operator action ("a directly connected router
#      notices link loss, a routed hop does not"), then the withdrawal as
#      what it really is, a RIB effect: `ip route replace`, recovery timed;
#   E. the withdrawal SIGNAL without a BGP daemon: a refused document is not
#      one (`converged:false`, /healthz 200, the VIP serving), a dead
#      terminator is (/healthz 503 within one `controller.report_interval_
#      seconds` — the liveness check rides that ticker, 1 s here, 10 s by
#      default — while the brain's inventory still says `alive:true`: the
#      node's signal fires, the inventory's does not);
#   F. the brain dead: both nodes serve TCP and h3 through the VIP, /healthz
#      200, and a restarted brain has them back at the nodes' next poll —
#      what bounds that is the poll's own backoff after a failed poll (1 s
#      doubling to 30 s), never `stale_after`;
#   G. the two cross-node facts a shared address exposes: a TLS session is
#      not resumable on the other node (spec §3, sid_ctx), while a clearance
#      cookie IS honoured there (fleet-wide clearance keys). This arm found
#      the one PRODUCT DEFECT of the E6 runs, since fixed: as rendered, a TLS
#      session resumed on NO node, its own included, because OpenSSL looks a
#      session up through the SSL context of the address's default server and
#      kapkan's catch-all carried no `ssl_session_cache` — the same family as
#      the `ssl_protocols` behaviour the shared file already documents. The
#      arm asserts the fix (Reused on its own node, on BOTH nodes, with the
#      catch-all in place) before the cross-node claim, so that claim is not
#      vacuous, and still exercises the supported `omit_catch_all` knob;
#   H. MTU: 1200 on ONE leg takes HTTP/3 away from a client for the WHOLE
#      shared address — a path MTU is cached per destination and the
#      destination is the VIP — and it stays broken after the leg is repaired
#      until `ip route flush cache`, while TCP is untouched;
#   I. (stretch, ANYCAST_BGP=1, OUTSIDE the acceptance path) the same
#      withdrawal contract driven by a real speaker: bird2 on each node
#      announcing the VIP /32, enabled and disabled by a once-a-second
#      /healthz probe.
#
# Build the binaries for the container arch first (every command below runs
# from the REPO ROOT), then run this inside ONE privileged debian:13-slim
# container (never two rigs at once — check `docker ps`):
#
#   mkdir -p /tmp/lab
#   (cd engine && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan)
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
BURST3=10.1.0.50                   # arm C's L3 source: it gets laddered, the client must not
BURST4=10.1.0.51                   # arm C's L4 source: and the L3 one's ladder must not reach it
BRAIN=203.0.113.20; ORIGIN=203.0.113.30; CA=203.0.113.40; RSVC=203.0.113.1
ZONE=shop.test                     # global: both nodes serve it, through the VIP
ZONEB=nodeb.test                   # placed on pop-b: only edge-2 serves it
STATE1=/var/lib/kapkan-edge1; SOCKS1=/run/kapkan-edge1
STATE2=/var/lib/kapkan-edge2; SOCKS2=/run/kapkan-edge2
STALE=5
EXTRA=/tmp/extra-node.conf         # the node-attribution header
EXTRA_BROKEN=/tmp/extra-broken.conf
# The figures the guide quotes. Pre-set so the summary is printed even when an
# arm fell over before recording its own.
D_FAIL=0; D_OK=0; D_LOST_MS=0; D2_MS=0; E_MS=0; F_MS=0; H_FAIL=0
ANN_PIDS=""                        # arm I's /healthz->birdc loops, killed by pid
export KAPKAN_OP=optok KAPKAN_A1=a1tok KAPKAN_A2=a2tok
tok() { case $1 in op) echo optok;; a1) echo a1tok;; a2) echo a2tok;; *) echo "$1";; esac; }

# hosts_drop NAME removes NAME's lines from /etc/hosts in place — the file is
# a Docker bind mount, so `sed -i` (a rename over it) fails silently.
hosts_drop() { local tmp; tmp=$(grep -v " $1\$" /etc/hosts); printf '%s\n' "$tmp" > /etc/hosts; }
cleanup() {
  if [ -d /lab ]; then
    mkdir -p /lab/logs && cp -f /tmp/*.log /tmp/*.out /tmp/*.txt /lab/logs/ 2>/dev/null
    cp -f /tmp/zones.yaml /tmp/brain.yaml /tmp/edge1.yaml /tmp/edge2.yaml /tmp/extra-node.conf /lab/logs/ 2>/dev/null
    # The rendered configurations too: half of a diagnosis is what nginx was
    # actually given.
    for n in 1 2; do
      d=/lab/logs/render-edge$n; mkdir -p "$d"
      cp -f /var/lib/kapkan-edge$n/conf/live/*.conf "$d/" 2>/dev/null
    done
  fi
  kill "$(cat /tmp/brain.pid 2>/dev/null)" 2>/dev/null
  pkill -f "^$KAPKAN " 2>/dev/null; pkill -f "^$PEBBLE " 2>/dev/null
  pkill -f '^nginx: master' 2>/dev/null; pkill -f '^python3 /tmp/origin.py' 2>/dev/null
  pkill -f '^python3 /tmp/browser.py' 2>/dev/null; pkill -f '^python3 /tmp/keepalive.py' 2>/dev/null
  pkill -f 'bird -c' 2>/dev/null
  # The announce loops are shell scripts started by path, so their cmdline is
  # `/bin/sh /tmp/announce-N.sh` — an anchored `^/tmp/announce` pattern matches
  # nothing and the loops outlive the rig. Kill the recorded pids, and then
  # everything still living in a namespace: membership is the exact list, and
  # it catches whatever a pattern would miss.
  # shellcheck disable=SC2086
  [ -n "$ANN_PIDS" ] && kill -9 $ANN_PIDS 2>/dev/null
  pkill -f 'announce-[12]\.sh' 2>/dev/null
  for ns in rtr edge1 edge2 brain origin ca cli; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del "$ns" 2>/dev/null
  done
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
# Two more addresses on the client, one per half of arm C. Neither may be the
# address every other arm uses: a source that spends a window over its ceiling
# is promoted by the rollup's flood rule to a table denial for a minute or
# more, and a 403 from that ladder is indistinguishable, at the client, from
# the node being gone (run 1 spent four arms on exactly that confusion). The
# two halves need one address EACH for the same reason: the L3 half hands one
# node 34 refusals of 40, which is over FloodMinDenied (20) at well over
# FloodDeniedShare (0.3), so that source is table-denied on that node when the
# window closes — two seconds later, in the middle of the L4 half.
ip netns exec cli ip addr add $BURST3/24 dev cli-r
ip netns exec cli ip addr add $BURST4/24 dev cli-r
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
[ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" = "2" ] && ok "the router carries the VIP as ONE route with two nexthops ($(vip_route))" || bad "the VIP route is not multipath: $(vip_route)"
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
# etag TOKEN NODE -> the ETag of that node's document, unquoted; doc -> its body
etag()   { ip netns exec cli curl -s -o /dev/null -D - -m5 -H "Authorization: Bearer $(tok "$1")" "$B/edge/zones?node=$2" 2>/dev/null | grep -i '^etag:' | awk '{print $2}' | tr -d '\r"'; }
doc()    { api "$1" "$B/edge/zones?node=$2"; }
wait_eq() { local n=$(( $1 * 5 )) want=$2 i; shift 2; for i in $(seq 1 "$n"); do [ "$("$@")" = "$want" ] && return 0; sleep 0.2; done; return 1; }
wait_ne() { local n=$(( $1 * 5 )) not=$2 i; shift 2; for i in $(seq 1 "$n"); do [ "$("$@")" != "$not" ] && return 0; sleep 0.2; done; return 1; }
# A node's report carries the LAST CLOSED window of a zone, so everything
# per-window (top_sources, h3_requests) has to be waited for by CONDITION, not
# by a sleep: the aggregator's 10 s window is phased by its own clock, not by
# when a batch ran. zfield reads a field of that window, zat its close time as
# epoch seconds, and wait_window waits until the window a batch fell into has
# closed AND been reported — at most window + report_interval. Both stamps are
# whole seconds, so the window is accepted when its close is AT or after the
# batch's end: a strict "later" would skip the very window that holds the batch
# whenever it closes in the same second the batch ended, and wait for the next
# one — which holds nothing of it.
#
# align_window phases a batch: it waits (≤ 15 s) until BOTH nodes closed a
# window within the last 5 s. The nodes' 10 s windows are not aligned with each
# other, but their phases differ by at most 5 s one way round, so the moment
# recurs every ten seconds — and a batch of ≤ 4 s started then falls inside ONE
# open window on each node. Without it a boundary lands inside the burst on
# some runs, splitting its records over two windows: a per-window assertion
# (h3_requests, top_sources, the flood rule's threshold) then reads half a
# burst and fails on a green product.
zfield() { node_f "edge-$1" "([z for z in n.get('report',{}).get('zones',[]) if z['zone']=='$ZONE']+[{}])[0].get('$2',0)"; }
zat() { local a; a=$(node_f "edge-$1" "([z for z in n.get('report',{}).get('zones',[]) if z['zone']=='$ZONE']+[{}])[0].get('at','')"); date -u -d "$a" +%s 2>/dev/null || echo 0; }
wait_window() { local n=$1 after=$2 i; for i in $(seq 1 $(( $3 * 2 )) ); do [ "$(zat "$n")" -ge "$after" ] 2>/dev/null && return 0; sleep 0.5; done; return 1; }
align_window() { local i now a1 a2; for i in $(seq 1 30); do now=$(date -u +%s); a1=$(zat 1); a2=$(zat 2); [ $(( now - a1 )) -le 5 ] && [ $(( now - a2 )) -le 5 ] && return 0; sleep 0.5; done; echo "  WARN  align_window: the nodes' windows did not line up within 15 s (edge-1 at $a1, edge-2 at $a2, now $now)"; return 1; }
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
# wait_nginx N — nginx up WITH its pid file written. This is a precondition of
# `kapkan edge`, not a nicety: the node's first apply SIGHUPs the pid in
# `terminator.pid_file`, and an unwritten pid file makes that reload an error
# the node then retries only after RetryMin — a minute, with no knob set in
# this rig's edge.yaml, which is longer than every wait below. A hard sleep
# guarded that on the author's box and nothing on a slower one. There is
# nothing to wait for on :443: until kapkan renders, this nginx has no server
# block at all, so a live pid IS the condition.
wait_nginx() { local n=$1 i p; for i in $(seq 1 100); do p=$(cat "/tmp/edge$n-nginx.pid" 2>/dev/null); [ -n "$p" ] && kill -0 "$p" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
node_nginx 1 edge1 $STATE1
node_nginx 2 edge2 $STATE2
wait_nginx 1 && wait_nginx 2 && [ "$(pgrep -fc 'nginx: master')" = "2" ] && ok "two nginx masters are up, each with its pid file written ($(nginx -v 2>&1 | grep -oE '[0-9.]+$'))" || bad "nginx masters: $(pgrep -fc 'nginx: master'), pid files '$(cat /tmp/edge1-nginx.pid 2>/dev/null)'/'$(cat /tmp/edge2-nginx.pid 2>/dev/null)'"

# ---------------------------------------------------------------- kapkan edge on both nodes
edge_yaml() { # N STATE SOCKS [OMIT_CATCH_ALL]
cat > /tmp/edge$1.yaml <<YAML
dry_run: false
controller: { url: "http://$BRAIN:8080", token_env: KAPKAN_EDGE_TOKEN, name: edge-$1, report_interval_seconds: 1 }
state_dir: $2
sockets_dir: $3
socket_group: www-data
terminator: { binary: nginx, main_conf: /tmp/edge$1-nginx.conf, reload: signal, pid_file: /tmp/edge$1-nginx.pid }
acme: { contact: ["mailto:lab@example.test"] }
quic: { h3: auto, retry: true }
omit_catch_all: ${4:-false}
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
  # Everything in the node's netns, not just the nginx master: SIGKILL on the
  # master leaves its WORKERS holding the listening sockets and serving
  # happily (run 1 believed a node was dead while it answered 200s, and the
  # replacement master could then never bind). `ip netns pids` is the exact
  # membership list.
  ip netns pids "$(ns_of "$1")" 2>/dev/null | xargs -r kill -9 2>/dev/null
  for i in $(seq 1 50); do [ -z "$(ip netns pids "$(ns_of "$1")" 2>/dev/null)" ] && return 0; sleep 0.1; done
  bad "edge-$1 still has processes in its netns after SIGKILL: $(ip netns pids "$(ns_of "$1")" | tr '\n' ' ')"
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
vget()   { local p=$1; shift; ip netns exec cli curl -s -o /dev/null -w "$W_TCP" -m5 --cacert /tmp/pebble-root.crt "$@" "https://$ZONE/$p" 2>/dev/null; }
vh3get() { local p=$1; shift; ip netns exec cli curl -s -o /dev/null -w "$W_H3" -m"$H3TMO" --http3-only --cacert /tmp/pebble-root.crt "$@" "https://$ZONE/$p" 2>/dev/null; }
uget()   { local n=$1; shift; ip netns exec cli curl -s -o /dev/null -w "$W_TCP" -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$(ip_of "$n")" "$@" "https://$ZONE/${RANDOM}" 2>/dev/null; }
ubody()  { local n=$1; shift; ip netns exec cli curl -s -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$(ip_of "$n")" "$@" "https://$ZONE/${RANDOM}" 2>/dev/null; }
# batch N tcp|h3 FILE — N fresh connections through the VIP, one "code node"
# line each (h3 lines drop the version column once asserted).
batch() {
  local n=$1 mode=$2 out=$3 i; shift 3
  : > "$out"
  for i in $(seq 1 "$n"); do
    if [ "$mode" = h3 ]; then vh3get "b$i-$RANDOM" "$@" | awk '{print $1, $3}' >> "$out"
    else vget "b$i-$RANDOM" "$@" >> "$out"; fi
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
# connect() is overridden whole, not _create_connection: which internal
# http.client uses to open the socket varies by version, and when the hook
# misses, the connection silently goes to the name — which on this rig is the
# VIP, i.e. whichever node the hash picks. An arm about one named node would
# then be testing the hash.
class C(http.client.HTTPSConnection):
    def connect(self):
        raw = socket.create_connection((ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
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
# keepalive.py: one connection to each node, a request on each, then a second
# request on each the moment the rig says the node has been killed. The gap is
# the kill itself — a few hundred milliseconds — so no idle timeout can be
# mistaken for it, and nothing needs to keep the connections warm (an earlier
# version warmed them every half second and its rounds raced the kill). It
# counts its own TCP opens, so a silent reconnect can never pass for a
# surviving connection.
cat > /tmp/keepalive.py <<'PY'
import http.client, ssl, socket, sys, json, os, time
zone, ip1, ip2 = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
class Conn:
    def __init__(self, ip):
        self.ip, self.opens, self.closed_by_server = ip, 0, 0
        outer = self
        # connect() overridden whole: see browser.py. `opens` counts real TCP
        # opens, so a silent reconnect can never pass for a survivor.
        class C(http.client.HTTPSConnection):
            def connect(self):
                outer.opens += 1
                raw = socket.create_connection((outer.ip, 443), self.timeout)
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        self.c = C(zone, 443, context=ctx, timeout=5)
    def get(self, path):
        try:
            self.c.request("GET", path)
            r = self.c.getresponse(); r.read()
            if (r.getheader("Connection") or "").lower() == "close" or self.c.sock is None:
                self.closed_by_server += 1
            return r.status
        except Exception as e:
            return type(e).__name__
a, b = Conn(ip1), Conn(ip2)
first = [a.get("/ka-1a"), b.get("/ka-2a")]
opens_before = [a.opens, b.opens]
open("/tmp/ka-ready", "w").write("1")
for _ in range(1200):
    if os.path.exists("/tmp/ka-go"):
        break
    time.sleep(0.05)
second = [a.get("/ka-1b"), b.get("/ka-2b")]
print(json.dumps({"first": first, "second": second, "opens_before": opens_before,
                  "opens": [a.opens, b.opens], "server_closed": [a.closed_by_server, b.closed_by_server]}))
PY

# ================================================================ ARM A
say "ARM A — the fleet and a deterministic fan-out: the route is pinned to edge-2 for the whole issuance"
# With the VIP routed only to edge-2, every HTTP-01 request the CA makes lands
# on edge-2. So edge-1's certificate can ONLY have been validated by the
# challenge it published to the brain and the brain fanned out to edge-2 —
# there is no path by which edge-1 answered for itself.
route_one $E2 r-e2
{ vip_route | grep -q "via $E2 dev r-e2"; } && [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" = "0" ] && ok "the VIP is pinned to edge-2 alone for the issuance ($(vip_route))" || bad "route pin: $(vip_route)"
: > /tmp/edge1.log; : > /tmp/edge2.log
"$KAPKAN" edge -config /tmp/edge1.yaml -check 2>&1 | tee /tmp/check1.out | grep -q 'is valid' && ok "edge-1's edge.yaml passes -check" || bad "edge-1 -check: $(cat /tmp/check1.out)"
"$KAPKAN" edge -config /tmp/edge2.yaml -check 2>&1 | tee /tmp/check2.out | grep -q 'is valid' && ok "edge-2's edge.yaml passes -check (identical but for name, dirs and status_listen — the guide's rule)" || bad "edge-2 -check: $(cat /tmp/check2.out)"
# wait_certs N WANT SECONDS — wait for N's `certificate issued` count, failing
# FAST on an order the CA refused: a failed order is retried an hour later
# (acme's backoffMin), so a wait that sits out the clock only hides the error.
wait_certs() {
  local n=$1 want=$2 i
  for i in $(seq 1 $(( $3 * 5 ))); do
    [ "$(certs_seen "$n")" -ge "$want" ] && return 0
    grep -q 'certificate order failed' "/tmp/edge$n.log" && return 1
    sleep 0.2
  done
  return 1
}
# The starts are STAGGERED, and not for tidiness. The fan-out is not
# acknowledged: a node publishes its HTTP-01 token to the brain and accepts the
# challenge at once, while the brain only WAKES the other node's parked poll —
# nothing confirms the token is installed there. Pebble validates in one pass
# (PEBBLE_VA_NOSLEEP=1, no retry) and a lost order costs an hour, which no wait
# in this rig can sit out. So edge-2 issues first, alone; by the time edge-1
# asks for a certificate, the node that must answer for it is idle.
start_edge 2
wait_healthy 2 40 && ok "edge-2 healthy: a tested generation is live" || { bad "edge-2 never became healthy"; tail -10 /tmp/edge2.log; }
wait_certs 2 2 180 && ok "edge-2 has its own certificates ($(certs_seen 2): $ZONE and the placed $ZONEB), validated on itself — the route points here" || { bad "edge-2 certificates: $(certs_seen 2)"; grep -i 'acme\|certif' /tmp/edge2.log | tail -3; }
start_edge 1
wait_healthy 1 40 && ok "edge-1 healthy" || { bad "edge-1 never became healthy"; tail -10 /tmp/edge1.log; }
wait_certs 1 1 180 && ok "edge-1 has a certificate for $ZONE — validated on edge-2, through the fan-out" || { bad "edge-1 issued nothing in 180 s"; grep -i 'acme\|certif' /tmp/edge1.log | tail -3; }
grep -q 'edge acme challenge published.*node=edge-1' /tmp/brain.log && grep -q 'edge acme challenge published.*node=edge-2' /tmp/brain.log && ok "the brain fanned out a challenge published by each node" || bad "challenge publications: $(grep -c 'challenge published' /tmp/brain.log) lines, nodes $(grep -oE 'challenge published.*node=[a-z0-9-]+' /tmp/brain.log | grep -oE 'node=.*' | sort -u | tr '\n' ' ')"
# Whether the two nodes happen to collide on one zone at startup is a race —
# and with the starts staggered above there is normally nothing to collide
# with. The serialisation itself is not a race, so it is asserted directly on
# the route both nodes use: hold the zone's slot as edge-1, then ask for it as
# edge-2.
echo "  (startup contention seen so far: $(grep -c 'granted=false' /tmp/brain.log) refused slot request(s) — incidental, the assertion below does not depend on it)"
api a1 "$B/edge/nodes/edge-1/acme/slot" -X POST -H 'Content-Type: application/json' -d "{\"zone\":\"$ZONE\"}" > /tmp/slot-hold.json
[ "$(jx "d['granted']" < /tmp/slot-hold.json)" = "true" ] && ok "edge-1 takes $ZONE's issuance slot on demand" || bad "slot for edge-1: $(cat /tmp/slot-hold.json)"
api a2 "$B/edge/nodes/edge-2/acme/slot" -X POST -H 'Content-Type: application/json' -d "{\"zone\":\"$ZONE\"}" > /tmp/slot-refused.json
[ "$(jx "d['granted']" < /tmp/slot-refused.json)" = "false" ] && [ "$(jx "d['holder']" < /tmp/slot-refused.json)" = "edge-1" ] && ok "edge-2 asking for the same zone is refused, and told who holds it (granted:false, holder edge-1, retry_after_seconds $(jx "d.get('retry_after_seconds')" < /tmp/slot-refused.json)) — N nodes on one name are N duplicate orders, so the brain serialises them" || bad "second slot request: $(cat /tmp/slot-refused.json)"
grep -q 'slot requested.*node=edge-2.*granted=false' /tmp/brain.log && ok "…and the refusal is in the brain's log with the node, the zone and the holder" || bad "no granted=false line naming edge-2: $(grep 'slot requested' /tmp/brain.log | tail -2)"
api a1 "$B/edge/nodes/edge-1/acme/slot" -X POST -H 'Content-Type: application/json' -d "{\"zone\":\"$ZONE\",\"release\":true}" >/dev/null
ip netns exec cli curl -sk -m3 https://$CA:15000/roots/0 > /tmp/pebble-root.crt 2>/dev/null
grep -q 'BEGIN CERTIFICATE' /tmp/pebble-root.crt && ok "fetched Pebble's root for the clients" || bad "could not fetch Pebble's root"
route_both
settle 1; settle 2
fp() { ip netns exec cli sh -c "openssl s_client -connect $1:443 -servername $ZONE -CAfile /tmp/pebble-root.crt </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256" | cut -d= -f2; }
FP1=$(fp $E1); FP2=$(fp $E2)
[ -n "$FP1" ] && [ -n "$FP2" ] && [ "$FP1" != "$FP2" ] && ok "the two nodes serve DIFFERENT leaf certificates for one name (per-node ACME: ${FP1:0:17}… vs ${FP2:0:17}…)" || bad "leaf fingerprints: '$FP1' / '$FP2'"
[ "$(inv_f "d['nodes_total']")" = "2" ] && [ "$(node_f edge-1 "n['alive']")" = "true" ] && [ "$(node_f edge-2 "n['alive']")" = "true" ] && ok "inventory: two nodes, both alive" || bad "inventory: $(inv_f "d['nodes_total']") nodes, alive $(node_f edge-1 "n['alive']")/$(node_f edge-2 "n['alive']")"
# Each node reports the ETag of the document it was actually handed. Under
# placement those documents differ (edge-2 also serves the placed zone), so a
# shared zones_etag is NOT the fleet-health signal an operator might expect —
# what must hold is that each node's reported ETag is its own document's, and
# that the zone they share is identical in both.
# A report carries the ETag verbatim, quotes included, so both sides are
# compared unquoted.
ET1R=$(node_f edge-1 "n['report']['zones_etag']" | tr -d '"'); ET2R=$(node_f edge-2 "n['report']['zones_etag']" | tr -d '"')
[ -n "$ET1R" ] && [ -n "$ET2R" ] && [ "$ET1R" = "$(etag op edge-1)" ] && [ "$ET2R" = "$(etag op edge-2)" ] && ok "each node reports the ETag of its OWN document ($ET1R, $ET2R)" || bad "reported vs served ETag: edge-1 $ET1R/$(etag op edge-1), edge-2 $ET2R/$(etag op edge-2)"
[ "$ET1R" != "$ET2R" ] && ok "…and the two differ, because edge-2 also serves the placed zone: on a fleet with placement a shared zones_etag is not a health signal" || bad "the two documents have the same ETag despite placement"
doc op edge-1 | jx "[z for z in d['zones'] if z['name']=='$ZONE']" > /tmp/zone-e1.json
doc op edge-2 | jx "[z for z in d['zones'] if z['name']=='$ZONE']" > /tmp/zone-e2.json
cmp -s /tmp/zone-e1.json /tmp/zone-e2.json && [ -s /tmp/zone-e1.json ] && ok "the shared zone's entry is byte-identical in both documents ($(wc -c < /tmp/zone-e1.json) bytes): one name, one policy, whichever node the hash picks" || bad "the shared zone differs between documents: $(cat /tmp/zone-e1.json | cut -c1-120) / $(cat /tmp/zone-e2.json | cut -c1-120)"
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
align_window; B_START_MS=$(date -u +%s%3N); T0=$(date +%s%N); batch 40 h3 /tmp/b-h3.txt; B_END_MS=$(date -u +%s%3N); TB_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
H4_1=$(served edge-1 /tmp/b-h3.txt); H4_2=$(served edge-2 /tmp/b-h3.txt)
[ "$(n200 /tmp/b-h3.txt)" = "40" ] && [ "$H4_1" -ge 1 ] && [ "$H4_2" -ge 1 ] && ok "…and so did 40 --http3-only requests (edge-1 $H4_1, edge-2 $H4_2): the same policy hashes the UDP 4-tuple" || bad "L4 h3 spread: edge-1 $H4_1, edge-2 $H4_2, codes $(mix /tmp/b-h3.txt)"
# The metric is a per-RECORD counter — it moves as each access-log line
# arrives, so it is waited for on itself, not on a window's clock.
wait_ne 5 "$H1_0" nmetric 1 'kapkan_edge_requests_total{protocol="h3"'
wait_ne 5 "$H2_0" nmetric 2 'kapkan_edge_requests_total{protocol="h3"'
H1=$(nmetric 1 'kapkan_edge_requests_total{protocol="h3"'); H2=$(nmetric 2 'kapkan_edge_requests_total{protocol="h3"')
[ "$H1" -gt "$H1_0" ] && [ "$H2" -gt "$H2_0" ] && ok "both nodes counted h3 requests of their own (kapkan_edge_requests_total protocol=h3: +$((H1-H1_0)) and +$((H2-H2_0)))" || bad "h3 counted on one node only: edge-1 $H1_0->$H1, edge-2 $H2_0->$H2"
# And the report's own per-window field, which is what the guide quotes and
# what a fleet-wide consumer reads — a different number from a different code
# path. Forty --http3-only requests are forty QUIC handshakes from forty curl
# processes: the batch takes seconds, so even phased by align_window it can
# straddle a window boundary on one node (a run of this rig read 1 of 26 in
# the window that closed after the batch — the tail of a burst a boundary
# had cut). So the field is SUMMED over the windows the batch fell into: every
# closed window with `at` from the batch's start until the one that closed at
# or after its end, each read once from a single report (at and the count
# together, so a report arriving between two reads cannot pair one window's
# stamp with the next one's count). The sum must equal the node's share of
# the batch exactly: not "some h3", the batch itself, counted by a code path
# that never saw /tmp/b-h3.txt. Nothing else sends h3 to this zone here. The
# stamps are MILLISECONDS: a 40-request batch runs in well under a second, so
# with whole seconds a window that closed in the same second just BEFORE the
# batch's first request would both be counted (it holds arm A's one request)
# and end the collection before the batch's own window had closed.
h3win() { node_f "edge-$1" "(lambda z: str(z.get('at',''))+' '+str(z.get('h3_requests',0)))(([z for z in n.get('report',{}).get('zones',[]) if z['zone']=='$ZONE']+[{}])[0])"; }
h3sum() { local n=$1 i pair at v last="" sum=0; for i in $(seq 1 30); do pair=$(h3win "$n"); at=$(date -u -d "${pair% *}" +%s%3N 2>/dev/null || echo 0); v=${pair##* }; if [ "$at" -gt "$B_START_MS" ] && [ "$at" != "$last" ]; then sum=$(( sum + ${v:-0} )); last=$at; fi; [ "$at" -ge "$B_END_MS" ] && break; sleep 0.5; done; echo "$sum"; }
H3R1=$(h3sum 1); H3R2=$(h3sum 2)
[ "$H3R1" = "$H4_1" ] && [ "$H3R2" = "$H4_2" ] && ok "…and each node's report counts exactly its share of the batch (h3_requests summed over the window(s) the batch fell into: $H3R1 and $H3R2 for $ZONE = the $H4_1 and $H4_2 the two nodes served; the 40 QUIC handshakes took $TB_MS ms)" || bad "report h3_requests over the batch's window(s): edge-1 $H3R1 (served $H4_1), edge-2 $H3R2 (served $H4_2); batch $TB_MS ms"
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
# The decider's counters move as each access-log record reaches the node, so a
# delta read the instant curl returns is short — and the shortfall would land
# in the NEXT half's delta. Each half's counts are therefore read once the
# node has stopped counting, by condition.
dr_settled() { local n=$1 a b i; a=$(dr "$n"); for i in $(seq 1 20); do sleep 0.3; b=$(dr "$n"); [ "$b" = "$a" ] && { echo "$b"; return 0; }; a=$b; done; echo "$a"; }
# Each half rides its OWN source, and that is load-bearing, not tidiness: the
# L3 half hands one node ~34 refusals of 40 decided, over the flood rule's
# FloodMinDenied (20) at far over its FloodDeniedShare (0.3), so when that
# window closes the source is promoted to a TABLE denial there for DenyTTL.
# On a shared address that close falls wherever the aggregator's clock puts
# it — including inside the L4 half two seconds later, which would answer 403
# instead of 429, leave deny_rate still, and skew the recorded table without
# failing anything. Hence BURST3 and BURST4, and hence the 200+429 = 40
# assertions below: a 403 in either half is now a FAIL, not a silent skew.
hashpol 0
# align_window: the flood rule counts a source's refusals PER WINDOW, so the
# promotion asserted below needs the whole burst inside one window on the node
# it lands on — a boundary inside the burst would split its ~34 refusals so
# that neither half crosses FloodMinDenied, and the 403 would never come.
align_window
D1_0=$(dr 1); D2_0=$(dr 2); T0=$(date +%s%N); batch 40 tcp /tmp/c-l3.txt --interface $BURST3; T3_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
C3_429=$(ncode 429 /tmp/c-l3.txt); C3_200=$(ncode 200 /tmp/c-l3.txt); D1_3=$(( $(dr_settled 1) - D1_0 )); D2_3=$(( $(dr_settled 2) - D2_0 ))
[ "$C3_429" -ge 1 ] && [ $((C3_200 + C3_429)) -eq 40 ] && ok "under L3 the burst is refused: $C3_429 of 40 answered 429, $C3_200 served, and nothing else ($(mix /tmp/c-l3.txt)) — every answer is the rate ceiling's, none a table verdict" || bad "L3 batch: $(mix /tmp/c-l3.txt) (429 + 200 must be all 40; a 403 would be the flood rule's ladder, not the ceiling)"
[ $(( D1_3 * D2_3 )) -eq 0 ] && [ $(( D1_3 + D2_3 )) -ge 1 ] && ok "every rate denial came from ONE node (deny_rate: edge-1 +$D1_3, edge-2 +$D2_3) — one ceiling, as configured" || bad "rate denials on both nodes under L3: edge-1 +$D1_3, edge-2 +$D2_3"
hashpol 1
align_window
D1_0=$(dr 1); D2_0=$(dr 2); T0=$(date +%s%N); batch 40 tcp /tmp/c-l4.txt --interface $BURST4; T4_MS=$(( ($(date +%s%N) - T0) / 1000000 )); C4_END=$(date -u +%s)
C4_429=$(ncode 429 /tmp/c-l4.txt); C4_200=$(ncode 200 /tmp/c-l4.txt); D1_4=$(( $(dr_settled 1) - D1_0 )); D2_4=$(( $(dr_settled 2) - D2_0 ))
[ "$C4_429" -ge 1 ] && [ $((C4_200 + C4_429)) -eq 40 ] && [ "$D1_4" -ge 1 ] && [ "$D2_4" -ge 1 ] && ok "under L4 BOTH nodes refused ($C4_429 of 40 were 429, $C4_200 served, nothing else; deny_rate edge-1 +$D1_4, edge-2 +$D2_4): the ceiling is per node, and the source met two of them" || bad "L4 ceilings: $(mix /tmp/c-l4.txt) (429 + 200 must be all 40), deny_rate edge-1 +$D1_4, edge-2 +$D2_4"
# The ratio is a range, not a constant: a node's bucket holds rps tokens and
# refills rps per second, so a batch lasting T seconds is admitted 5 + 5·T per
# node. T is recorded beside the counts and asserted, because on a slow box
# the same 40 connections mean a different table.
CV=$(python3 - "$C3_200" "$C4_200" "$C3_429" "$C4_429" "$D1_3" "$D2_3" "$D1_4" "$D2_4" "$T3_MS" "$T4_MS" <<'PY'
import sys
l3_200, l4_200, l3_429, l4_429, d13, d23, d14, d24, t3, t4 = (int(x) for x in sys.argv[1:11])
ratio = (l4_200 / l3_200) if l3_200 else 0.0
T3, T4 = t3 / 1000.0, t4 / 1000.0
lines = [
    "policy.rate.rps 5, 40 connections from one source, two nodes:",
    f"  L3 (policy 0): served {l3_200}, refused {l3_429} (429 share {l3_429/40*100:.0f}%), deny_rate edge-1 {d13} edge-2 {d23}, batch {T3:.1f}s",
    f"  L4 (policy 1): served {l4_200}, refused {l4_429} (429 share {l4_429/40*100:.0f}%), deny_rate edge-1 {d14} edge-2 {d24}, batch {T4:.1f}s",
    f"  the source got {ratio:.1f}x the admitted requests under L4 (the guide's \"up to N x the ceiling\", N = the node count = 2)",
    "  that figure is a RANGE, not a constant: a node's bucket admits rps + rps*T over a batch of T",
    f"  seconds, so it holds while each node's share of the batch exceeds its own allowance (5 + 5*T <= 20,",
    f"  i.e. T <= 3 s for 40 connections over two nodes; here T was {T3:.1f}s and {T4:.1f}s). Asserted as 1.5x-2.5x.",
    f"  the other side of the same coin: under L3 all {l3_429} refusals land on ONE node, over the rollup's",
    "  flood rule (>= 20 refusals in a window, >= 30% of that source's decided requests), so the source is",
    "  promoted there to a TABLE denial for DenyTTL (a minute, escalating) — asserted. Under L4 the split",
    "  keeps each node under the threshold and the source stays `allow`. A low per-node rps under an L3",
    "  hash therefore blocks a busy client; under L4 it only slows it.",
]
open("/tmp/arm-c.txt", "w").write("\n".join(lines) + "\n")
print("ok" if 1.5 <= ratio <= 2.5 and T3 <= 3.0 and T4 <= 3.0 else f"out-of-range ratio={ratio:.2f} T3={T3:.1f}s T4={T4:.1f}s")
PY
)
sed 's/^/  /' /tmp/arm-c.txt
[ "$CV" = "ok" ] && ok "the L3-vs-L4 shares are recorded for the guide with the batch durations beside them, and the ratio is in the 1.5x-2.5x the bucket allows (/tmp/arm-c.txt)" || bad "arm C's recorded share: $CV"
# top_sources rides a CLOSED 10 s window, so it is waited for by CONDITION:
# the window the L4 batch fell into must have closed (its `at` at or after the
# batch's end — whole seconds, so "later" would skip a window closing in the
# batch's last second) and been reported — at most 10 s plus one report
# interval; align_window put the whole batch inside that one window. The
# L4 source is the one to look for: under L4 both nodes saw it, while the L3
# source, by design, only ever reached one.
srcs() { api op "$B/edge/nodes" | jx "'\n'.join(s['source']+' '+s['state'] for z in ([n for n in d['nodes'] if n['name']=='edge-$1']+[{}])[0].get('report',{}).get('zones',[]) if z['zone']=='$ZONE' for s in z.get('top_sources',[]))"; }
bsrc() { awk -v s="$BURST4" '$1==s {print $2}' "$1" 2>/dev/null | head -1; }
for i in $(seq 1 60); do
  srcs 1 > /tmp/c-src-1.txt; srcs 2 > /tmp/c-src-2.txt
  if [ "$(zat 1)" -ge "$C4_END" ] 2>/dev/null && [ "$(zat 2)" -ge "$C4_END" ] 2>/dev/null; then
    [ -n "$(bsrc /tmp/c-src-1.txt)" ] && [ -n "$(bsrc /tmp/c-src-2.txt)" ] && break
  fi
  sleep 0.5
done
S1=$(bsrc /tmp/c-src-1.txt); S2=$(bsrc /tmp/c-src-2.txt)
[ -n "$S1" ] && [ -n "$S2" ] && ok "the bursting source $BURST4 appears in BOTH nodes' top_sources for the window it burst in — each node saw it, neither saw the whole of it" || bad "top_sources: edge-1 '$(tr '\n' ' ' < /tmp/c-src-1.txt)', edge-2 '$(tr '\n' ' ' < /tmp/c-src-2.txt)'"
[ "$S1" = "allow" ] && [ "$S2" = "allow" ] && ok "…and in that window each node still reports it \`allow\`: a rate denial is not a table verdict. What promotes a source to one is the flood rule, when its refusals in a single window cross FloodMinDenied (20) — which, diluted over two nodes, neither node's share does" || bad "state of $BURST4: edge-1 '$S1', edge-2 '$S2' ('denied' means one node took >= 20 of the 40 refusals in one window and the flood rule promoted it)"
# The other half of that rule, and the half an operator picking a low per-node
# rps under the guide's recommended L3 hash must know: there the whole burst
# lands on ONE node, so its ~34 refusals in one window ARE over the threshold
# and the source is promoted to a table denial for DenyTTL (a minute to start,
# escalating). The L3 hash is deterministic, so this probe reaches the node the
# burst did; a 403 is the promotion, a 200 or a 429 would mean it never
# happened.
hashpol 0
C3P=""
for i in $(seq 1 60); do
  C3P=$(vget "promoted-$RANDOM" --interface $BURST3); C3P=${C3P%% *}
  [ "$C3P" = "403" ] && break
  sleep 0.5
done
[ "$C3P" = "403" ] && ok "under L3 the concentrated burst IS promoted: $BURST3 now gets a 403 table denial from the node that refused it — a low per-node rps under an L3 hash turns a busy source into a blocked one for DenyTTL, where the same 40 connections diluted over L4 stayed \`allow\`" || bad "no table denial for $BURST3 under L3 within 30 s: last answer '$C3P'"
ZONE_RPS=1000; zones_yaml; reload_brain; sleep 1.5

# ================================================================ ARM D
say "ARM D — a node dies and nobody withdraws: the route still points at it"
# Every arm from here on needs ONE client spread over BOTH nodes — "a share
# fails", "edge-2 served it too" — so each states the hash form it assumes
# rather than inheriting arm C's last `hashpol` call.
hashpol 1
ROUTE0=$(vip_route)
# A clean-client pre-check, so that a client the ladder has promoted (arm C's
# two burst sources are separate addresses for exactly this reason) can never
# be mistaken for a node that is gone.
batch_until 20 tcp /tmp/d-pre.txt 40 20
[ "$(n200 /tmp/d-pre.txt)" = "20" ] && [ "$(served edge-1 /tmp/d-pre.txt)" -ge 1 ] && [ "$(served edge-2 /tmp/d-pre.txt)" -ge 1 ] && ok "before the kill: 20 of 20 served, both nodes ($(served edge-1 /tmp/d-pre.txt)/$(served edge-2 /tmp/d-pre.txt)) — the client is clean, arm C's bursts rode their own addresses" || bad "the client is not clean before arm D: $(mix /tmp/d-pre.txt)"
rm -f /tmp/ka-ready /tmp/ka-go
ip netns exec cli python3 /tmp/keepalive.py $ZONE $E1 $E2 > /tmp/keepalive.out 2>&1 &
KA_PID=$!
for i in $(seq 1 60); do [ -f /tmp/ka-ready ] && break; sleep 0.2; done
[ -f /tmp/ka-ready ] && ok "a keepalive connection is open to each node" || bad "keepalive.py never got its first round through: $(cat /tmp/keepalive.out)"
KILL0=$(date +%s%N)
kill_node 2
touch /tmp/ka-go
batch 40 tcp /tmp/d-dead.txt
D_FAIL=$(ncode 000 /tmp/d-dead.txt); D_OK=$(n200 /tmp/d-dead.txt)
# The failures must be CONNECTION failures (curl's 000), not a refusal: a 403
# or a 429 would mean a live node decided something, which is a different
# story altogether.
[ "$D_FAIL" -ge 1 ] && [ "$D_OK" -ge 1 ] && [ $((D_FAIL + D_OK)) -eq 40 ] && ok "with the route untouched $D_FAIL of 40 requests failed to connect at all and $D_OK were served — the hash keeps sending a share to a dead node ($(mix /tmp/d-dead.txt))" || bad "dead-node batch: $(mix /tmp/d-dead.txt) (failures must be 000, a connection failure, not a refusal)"
[ "$(served edge-2 /tmp/d-dead.txt)" = "0" ] && ok "nothing was served BY edge-2 (every success names edge-1)" || bad "edge-2 served after the kill"
wait "$KA_PID" 2>/dev/null
KA=$(cat /tmp/keepalive.out)
# One TCP connection each before the kill, and no server-side close: without
# this the assertion below could pass on a silent reconnect. After the kill
# edge-1 must still be on its ORIGINAL connection (opens still 1); edge-2's
# count is not asserted, since a client that finds its node gone may well try
# to reopen — and be refused.
[ "$(jx "d['opens_before']" <<< "$KA")" = "[1, 1]" ] && [ "$(jx "d['first']" <<< "$KA")" = "[200, 200]" ] && [ "$(jx "sum(d['server_closed'])" <<< "$KA")" = "0" ] && ok "one TCP connection to each node, both answering 200, neither closed by the server: genuinely established connections" || bad "keepalive bookkeeping: $KA"
[ "$(jx "d['second'][0]" <<< "$KA")" = "200" ] && [ "$(jx "d['opens'][0]" <<< "$KA")" = "1" ] && [ "$(jx "d['second'][1]" <<< "$KA")" != "200" ] && ok "across the kill the connection to edge-1 answers 200 on that same connection and the one to edge-2 is gone ($(jx "d['second']" <<< "$KA")) — a shared address gives an established connection no protection whatever" || bad "keepalive across the kill: $KA"
if wait_eq 20 false node_f edge-2 "n['alive']"; then
  D_LOST_MS=$(( ($(date +%s%N) - KILL0) / 1000000 ))
  # The bound is the product's, not the wait's: `alive` is the brain's judgment
  # at read time — a parked poll, or a sighting within stale_after — so the
  # flip is due stale_after after the dead node's parked poll closed with its
  # socket. Asserted with 2 s for that close and the observer's 200 ms step.
  [ "$D_LOST_MS" -le $(( (STALE + 2) * 1000 )) ] && ok "the inventory marks edge-2 alive:false ${D_LOST_MS} ms after the kill — stale_after_seconds $STALE after its last sighting, within the asserted $(( (STALE + 2) * 1000 )) ms" || bad "alive:false took ${D_LOST_MS} ms, over stale_after ($STALE s) plus 2 s of slack"
else
  D_LOST_MS=0; bad "edge-2 still alive: $(node_f edge-2 "n['alive']")"
fi
[ "$(node_f edge-1 "n['alive']")" = "true" ] && ok "edge-1 is untouched by its neighbour's death" || bad "edge-1 alive: $(node_f edge-1 "n['alive']")"
# The two checks below are STRUCTURAL: in this topology no Kapkan code path
# can touch the router's table or name the VIP, so they cannot fail by any
# product action — they record the ABSENCE of a zone-address path, not a
# decision. The one product-facing check of the claim is the third: the brain's
# ban list, the thing its speaker announces, must not carry the VIP either.
[ "$(vip_route)" = "$ROUTE0" ] && ok "the router's VIP route is byte-identical: the brain never touches routing for a zone address ($ROUTE0) — structural" || bad "the VIP route changed by itself: '$ROUTE0' -> '$(vip_route)'"
# The brain HAS a BGP speaker configured here (positive control), and it still
# never says a word about the zone's address: its speaker is for victims under
# attack, never for service routing. Nothing listens at 127.0.0.2, so what the
# log shows is the speaker's own FSM, not an established session.
grep -q 'bgp peer state' /tmp/brain.log && ok "the brain's own BGP speaker is configured and running (peer state transitions logged): there IS a speaker to keep quiet" || bad "no bgp peer line in the brain log — the next assertion would be vacuous"
grep -q "$VIP" /tmp/brain.log && bad "the brain's log mentions the VIP $VIP" || ok "the brain never mentions $VIP: nothing in Kapkan announces or withdraws a zone's address — structural"
api op "$B/bans" > /tmp/d-bans.json
grep -q "$VIP" /tmp/d-bans.json && bad "the brain's ban list carries the VIP $VIP: $(cut -c1-200 /tmp/d-bans.json)" || ok "and its ban list — the set its speaker announces — carries no $VIP either, with a node of that address dead ($(wc -c < /tmp/d-bans.json) bytes)"

say "ARM D2 — the link down instead: a dead nexthop needs no operator, a dead node does"
ip netns exec rtr ip link set r-e2 down
sleep 0.5
ip netns exec rtr ip route show $VIP/32 > /tmp/d2-route.txt
grep -qE 'dead|linkdown' /tmp/d2-route.txt && ok "the nexthop via edge-2 is marked dead ($(tr -s ' \n' ' ' < /tmp/d2-route.txt))" || bad "no dead nexthop after the link went down: $(tr -s ' \n' ' ' < /tmp/d2-route.txt)"
batch 40 tcp /tmp/d2-linkdown.txt
[ "$(n200 /tmp/d2-linkdown.txt)" = "40" ] && ok "40 of 40 served with no operator action: a directly connected router notices link loss, a routed hop does not" || bad "link-down batch: $(mix /tmp/d2-linkdown.txt)"
ip netns exec rtr ip link set r-e2 up
sleep 1
batch 20 tcp /tmp/d2-back.txt
[ "$(ncode 000 /tmp/d2-back.txt)" -ge 1 ] && ok "the link back up and the node still dead: the connection failures return ($(mix /tmp/d2-back.txt)) — link state is not health" || bad "no failures with the link up and the node dead: $(mix /tmp/d2-back.txt)"
T0=$(date +%s%N); route_one $E1 r-e1
for i in $(seq 1 100); do batch 5 tcp /tmp/d2-probe.txt; [ "$(n200 /tmp/d2-probe.txt)" = "5" ] && break; done
D2_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
batch 40 tcp /tmp/d2-withdrawn.txt; batch 20 h3 /tmp/d2-withdrawn-h3.txt
[ "$(n200 /tmp/d2-withdrawn.txt)" = "40" ] && [ "$(n200 /tmp/d2-withdrawn-h3.txt)" = "20" ] && ok "after the operator's withdrawal (one \`ip route replace … via edge-1\`) 40 of 40 TCP and 20 of 20 HTTP/3 requests are served, in ${D2_MS} ms from the RIB change" || bad "after the withdrawal: TCP $(mix /tmp/d2-withdrawn.txt), h3 $(mix /tmp/d2-withdrawn-h3.txt)"
C2_0=$(certs_seen 2); SLOT2_0=$(grep -c 'slot requested.*node=edge-2' /tmp/brain.log)
A2_0=$(node_f edge-2 "n['alive']"); R0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
node_nginx 2 edge2 $STATE2; wait_nginx 2; start_edge 2
wait_healthy 2 30 && ok "edge-2 restarted (its render came back from disk)" || bad "edge-2 did not come back"
# "Alive again at its first poll" pinned rather than waited out: it was alive
# FALSE before the restart, and the sighting the brain now holds was made
# AFTER it — a leftover sighting would be at least stale_after older, which is
# what an eventual 15 s wait alone would not have told apart.
wait_eq 15 true node_f edge-2 "n['alive']"
LS2=$(node_f edge-2 "n['last_seen']")
LS2_E=$(date -u -d "$LS2" +%s 2>/dev/null || echo 0); R0_E=$(date -u -d "$R0" +%s 2>/dev/null || echo 0)
[ "$A2_0" = "false" ] && [ "$(node_f edge-2 "n['alive']")" = "true" ] && [ "$LS2_E" -ge "$R0_E" ] && ok "the inventory has it alive again from a poll made after the restart (alive false -> true, last_seen $LS2 >= restart $R0)" || bad "edge-2 after the restart: alive $A2_0 -> $(node_f edge-2 "n['alive']"), last_seen '$LS2' vs restart '$R0'"
# "Ordered nothing new" read off the FRESH process instead of a sleep: its own
# ACME counter is zero, and the brain logged no slot request from it — a slot
# is taken before every order, at its start, so this is not a race with a
# completion the way a `certificate issued` grep after a fixed sleep is.
A2M=$(nmetric 2 'kapkan_edge_acme_attempts_total')
SLOT2=$(grep -c 'slot requested.*node=edge-2' /tmp/brain.log)
[ "$A2M" = "0" ] && [ "$SLOT2" = "$SLOT2_0" ] && [ "$(certs_seen 2)" = "$C2_0" ] && ok "the restarted node ordered nothing: its certificates came back from disk (its own kapkan_edge_acme_attempts_total is 0, it asked the brain for no issuance slot, \`certificate issued\` still $C2_0)" || bad "edge-2 after a restart: acme_attempts $A2M, slot requests $SLOT2_0 -> $SLOT2, certificate issued $C2_0 -> $(certs_seen 2)"
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
# What bounds the 503 is `controller.report_interval_seconds`, not a health
# timer: the pid check is sampled on the report ticker (one second here, TEN
# by default), so an operator who withdraws on /healthz must set that interval
# to the probe period they want. Asserted at one interval plus 300 ms.
kill "$(cat /tmp/edge2-nginx.pid 2>/dev/null)" 2>/dev/null
T0=$(date +%s%N)
for i in $(seq 1 50); do [ "$(hcode 2)" = "503" ] && break; sleep 0.1; done
E_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
[ "$(hcode 2)" = "503" ] && [ "$E_MS" -le 1300 ] && ok "/healthz on edge-2 turned 503 ${E_MS} ms after nginx died — within one controller.report_interval_seconds (1 s in this rig; the product default is 10), the tick the liveness check rides; terminator.pid_file is what makes it observable at all" || bad "/healthz after killing nginx: $(hcode 2) after ${E_MS} ms (bound: one report interval + 300 ms)"
[ "$(node_f edge-2 "n['alive']")" = "true" ] && ok "…while the brain's inventory still says alive:true — the node's own signal fired, the inventory's did not (never withdraw on \`alive\`)" || bad "inventory alive after the nginx kill: $(node_f edge-2 "n['alive']")"
[ "$(node_f edge-2 "n['report']['terminator']['alive']")" = "false" ] && ok "the node's report does say terminator.alive:false (the honest field, one poll behind)" || bad "report terminator.alive: $(node_f edge-2 "n['report']['terminator']['alive']")"
node_nginx 2 edge2 $STATE2; wait_nginx 2
wait_eq 20 200 hcode 2 && ok "nginx restarted on its live configuration: /healthz 200 again" || bad "/healthz after the nginx restart: $(hcode 2)"
batch_until 10 tcp /tmp/e-back.txt 50 10
[ "$(n200 /tmp/e-back.txt)" = "10" ] && [ "$(served edge-2 /tmp/e-back.txt)" -ge 1 ] && ok "the VIP serves from both nodes again ($(served edge-1 /tmp/e-back.txt)/$(served edge-2 /tmp/e-back.txt))" || bad "after the nginx restart: $(mix /tmp/e-back.txt), edge-2 $(served edge-2 /tmp/e-back.txt)"

# ================================================================ ARM F
say "ARM F — the brain dead: the fleet is fail-static behind one address"
kill_brain && ok "the brain is dead" || bad "the brain is still answering"
batch 20 tcp /tmp/f-nobrain.txt; batch 20 h3 /tmp/f-nobrain-h3.txt
[ "$(n200 /tmp/f-nobrain.txt)" = "20" ] && [ "$(served edge-1 /tmp/f-nobrain.txt)" -ge 1 ] && [ "$(served edge-2 /tmp/f-nobrain.txt)" -ge 1 ] && ok "20 of 20 TCP requests served by both nodes with the brain dead" || bad "TCP with the brain dead: $(mix /tmp/f-nobrain.txt), $(served edge-1 /tmp/f-nobrain.txt)/$(served edge-2 /tmp/f-nobrain.txt)"
[ "$(n200 /tmp/f-nobrain-h3.txt)" = "20" ] && [ "$(served edge-1 /tmp/f-nobrain-h3.txt)" -ge 1 ] && [ "$(served edge-2 /tmp/f-nobrain-h3.txt)" -ge 1 ] && ok "…and 20 of 20 over HTTP/3, from both nodes too ($(served edge-1 /tmp/f-nobrain-h3.txt)/$(served edge-2 /tmp/f-nobrain-h3.txt))" || bad "h3 with the brain dead: $(mix /tmp/f-nobrain-h3.txt), edge-1 $(served edge-1 /tmp/f-nobrain-h3.txt)/edge-2 $(served edge-2 /tmp/f-nobrain-h3.txt)"
[ "$(hcode 1)" = "200" ] && [ "$(hcode 2)" = "200" ] && ok "both /healthz stay 200: the brain is not in the health predicate" || bad "healthz with the brain dead: $(hcode 1)/$(hcode 2)"
mv /tmp/brain.log /tmp/brain-1.log; T0=$(date +%s%N); start_brain
# What bounds this is the node's own poll backoff after a failed poll — 1 s
# doubling to 30 s — and NOTHING the brain does, `stale_after` included: the
# nodes never stopped being alive to themselves, they simply had nowhere to
# poll. So the assertion is the backoff's own ceiling, and the figure, which
# depends only on how long the outage was, is recorded beside it.
if wait_eq 45 true node_f edge-1 "n['alive']" && wait_eq 45 true node_f edge-2 "n['alive']"; then
  F_MS=$(( ($(date +%s%N) - T0) / 1000000 ))
  [ "$F_MS" -le 31000 ] && ok "the brain came back and both nodes are alive again ${F_MS} ms later, inside the poll backoff's 30 s ceiling — the backoff, reached by an outage of this length, is the whole delay" || bad "the nodes took ${F_MS} ms to come back, over the poll backoff's 30 s ceiling"
else
  F_MS=0; bad "nodes after the brain's return: $(node_f edge-1 "n['alive']")/$(node_f edge-2 "n['alive']")"
fi

# ================================================================ ARM G
say "ARM G — the two cross-node facts a shared address exposes"
# A TLS session must not resume on the other node: nginx binds it to the
# node's own certificate through the session id context (spec §3). TLS 1.3 is
# in the SAME position as 1.2 here, not a different one: `ssl_session_tickets
# off` sets SSL_OP_NO_TICKET, and nginx then issues stateful 1.3 tickets whose
# sessions it looks up in `ssl_session_cache` — so both resume on their own
# node only. TLS 1.2 is the form this arm drives because `openssl s_client
# -sess_out/-sess_in` makes the offer and its answer visible in one word.
sess() { # SRCNODE DSTNODE FILE — save a session from SRC, offer it to DST
  local s=$1 d=$2 f=$3
  ip netns exec cli sh -c "printf 'GET /g HTTP/1.1\r\nHost: $ZONE\r\nConnection: close\r\n\r\n' | openssl s_client -connect $(ip_of "$s"):443 -servername $ZONE -CAfile /tmp/pebble-root.crt -tls1_2 -sess_out /tmp/g-$s.sess -ign_eof" >/tmp/g-save-$s.txt 2>&1
  ip netns exec cli openssl s_client -connect "$(ip_of "$d")":443 -servername $ZONE -CAfile /tmp/pebble-root.crt -tls1_2 -sess_in "/tmp/g-$s.sess" </dev/null >"$f" 2>&1
  grep -oE '^(New|Reused)' "$f" | head -1
}
r=$(sess 1 1 /tmp/g-default.txt)
[ -s /tmp/g-1.sess ] && ok "a TLS 1.2 session is issued and saved from edge-1 (the render does carry ssl_session_cache and a session id)" || bad "no session saved from edge-1: $(grep -iE 'session|error' /tmp/g-save-1.txt | head -2 | tr '\n' ' ')"
# THE FIX THIS ARM FOUND (product, not rig): as first rendered, that session
# resumed NOWHERE — not even on the node that issued it. OpenSSL looks a
# session up through the SSL context of the server the connection STARTED on
# — the address's DEFAULT server, SSL_set_SSL_CTX leaves session_ctx alone —
# and kapkan's catch-all default server carried no ssl_session_cache, so the
# per-zone cache was never consulted. The catch-all now declares the zones'
# shared cache; a session must therefore be Reused on its own node with the
# catch-all in place, and on BOTH nodes (the positive control the cross-node
# claim rests on: without it a New from the other node is equally what a
# broken cache there would produce).
[ "$(grep -c 'ssl_session_cache shared:kapkan_ssl' $STATE1/conf/live/kapkan_00_common.conf)" = "1" ] && [ "$(grep -c 'ssl_session_cache shared:kapkan_ssl' $STATE2/conf/live/kapkan_00_common.conf)" = "1" ] && ok "both shared files declare the zones' session cache on the catch-all default server (the fix the first runs of this arm asked for)" || bad "catch-all without ssl_session_cache: edge-1 $(grep -c ssl_session_cache $STATE1/conf/live/kapkan_00_common.conf), edge-2 $(grep -c ssl_session_cache $STATE2/conf/live/kapkan_00_common.conf)"
[ "$r" = "Reused" ] && ok "as rendered the session IS Reused on edge-1, the node that issued it, with the catch-all in place ('$r')" || bad "expected Reused on the same node with the catch-all in place, got '$r' — the catch-all's session cache is not being consulted"
r=$(sess 2 2 /tmp/g-same2-default.txt)
[ "$r" = "Reused" ] && ok "and edge-2 resumes its own session too, as rendered ('$r')" || bad "resumption on edge-2's own node with the catch-all in place: '$r'"
r=$(sess 1 2 /tmp/g-other-default.txt)
[ "$r" = "New" ] && ok "offered edge-1's session, edge-2 answers New: a session does not cross nodes (spec §3 — the session id context is the node's own certificate)" || bad "edge-2 resumed a session from edge-1 with the catch-all in place: '$r'"
r=$(sess 2 1 /tmp/g-other2-default.txt)
[ "$r" = "New" ] && ok "…and symmetrically, edge-2's session is New on edge-1: neither direction crosses" || bad "edge-1 resumed a session from edge-2: '$r'"
# The supported omit_catch_all knob (an nginx.conf with default servers of its
# own) makes the zone's own server the address's default: the same two facts
# must hold there — it was the knob that proved the cause before the fix.
edge_yaml 1 $STATE1 $SOCKS1 true; edge_yaml 2 $STATE2 $SOCKS2 true
kill_node 1; kill_node 2
node_nginx 1 edge1 $STATE1; node_nginx 2 edge2 $STATE2; wait_nginx 1; wait_nginx 2; start_edge 1; start_edge 2
wait_healthy 1 40 && wait_healthy 2 40 && ok "both nodes restarted with omit_catch_all: their own servers are now the address's default (the QUIC anchor still carries the one reuseport listener)" || bad "a node did not come back under omit_catch_all: $(sfield 1 healthy)/$(sfield 2 healthy)"
[ "$(grep -c ssl_reject_handshake $STATE1/conf/live/kapkan_00_common.conf)" = "1" ] && [ "$(grep -c ssl_reject_handshake $STATE2/conf/live/kapkan_00_common.conf)" = "1" ] && ok "both shared files now hold only the QUIC anchor, no TCP catch-all — the change is on the node being offered the session as much as on the one issuing it" || bad "catch-all servers in the shared files: edge-1 $(grep -c ssl_reject_handshake $STATE1/conf/live/kapkan_00_common.conf), edge-2 $(grep -c ssl_reject_handshake $STATE2/conf/live/kapkan_00_common.conf)"
r=$(sess 1 1 /tmp/g-same.txt)
[ "$r" = "Reused" ] && ok "with the catch-all omitted the session is Reused on edge-1 as well — the zone's own server is the address's default there" || bad "resumption on its own node under omit_catch_all: '$r'"
r=$(sess 2 2 /tmp/g-same2.txt)
[ "$r" = "Reused" ] && ok "and on edge-2's own node under omit_catch_all" || bad "resumption on edge-2's own node under omit_catch_all: '$r'"
r=$(sess 1 2 /tmp/g-other.txt)
[ "$r" = "New" ] && ok "offered edge-1's session under omit_catch_all, edge-2 still answers New: the knob changes the default server, not the session id context" || bad "edge-2 resumed a session from edge-1 under omit_catch_all: '$r'"
edge_yaml 1 $STATE1 $SOCKS1; edge_yaml 2 $STATE2 $SOCKS2
kill_node 1; kill_node 2
node_nginx 1 edge1 $STATE1; node_nginx 2 edge2 $STATE2; wait_nginx 1; wait_nginx 2; start_edge 1; start_edge 2
wait_healthy 1 40 && wait_healthy 2 40 && ok "the catch-all restored on both nodes" || bad "a node did not come back with the catch-all: $(sfield 1 healthy)/$(sfield 2 healthy)"
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
say "ARM H — MTU 1200 on ONE leg: HTTP/3 breaks for the whole VIP (a cached PMTU), TCP does not"
ip netns exec rtr ip link set r-e2 mtu 1200; ip netns exec edge2 ip link set e2-r mtu 1200
sleep 0.5
H3TMO=2   # a QUIC handshake into a 1200-byte path cannot complete; it can only time out
batch 40 h3 /tmp/h-h3.txt; H3TMO=5
batch 40 tcp /tmp/h-tcp.txt
H_FAIL=$(nfail /tmp/h-h3.txt)
# It is not a share. Whichever of the first requests reaches the small-MTU
# node teaches this client a 1200-byte path MTU for the VIP, and from then on
# every HTTP/3 request fails — to either node. So a handful may get through
# before the lesson lands (how many is the hash's coin toss), and then nothing
# does; the categorical statement is the poisoned batch below.
[ "$H_FAIL" -ge 30 ] && ok "$H_FAIL of 40 --http3-only requests failed ($(mix /tmp/h-h3.txt)): QUIC's floor is 1280, and one node below it takes HTTP/3 away for the whole shared address, not for its share of it" || bad "h3 under a 1200-byte leg: $(mix /tmp/h-h3.txt) (expected the great majority to fail)"
[ "$(awk '$1=="200" && $2=="edge-2"' /tmp/h-h3.txt | wc -l | tr -d ' ')" = "0" ] && ok "no h3 answer ever came from the node behind the small MTU" || bad "edge-2 served h3 over a 1200-byte path"
[ "$(n200 /tmp/h-tcp.txt)" = "40" ] && [ "$(served edge-2 /tmp/h-tcp.txt)" -ge 1 ] && ok "40 of 40 TCP requests served, edge-2 among them ($(served edge-1 /tmp/h-tcp.txt)/$(served edge-2 /tmp/h-tcp.txt)): TCP clamps its MSS, QUIC has a floor" || bad "TCP under a 1200-byte leg: $(mix /tmp/h-tcp.txt), edge-2 $(served edge-2 /tmp/h-tcp.txt)"
# The failure does not stay on the bad leg. A path MTU is cached per
# DESTINATION address, and the destination is the address every node shares —
# so once the router's ICMP has taught this client that 198.51.100.7 is a
# 1200-byte path, its HTTP/3 breaks toward the HEALTHY node too. One node's
# small MTU takes HTTP/3 away from a client for the whole VIP; TCP, which
# clamps per connection, never notices. Recorded here because it belongs in
# the guide's failure table.
ip netns exec cli ip route get $VIP > /tmp/h-pmtu.txt 2>&1
grep -qE 'mtu 12[0-9][0-9]' /tmp/h-pmtu.txt && ok "the client has cached a 1200-byte path MTU for the VIP itself ($(grep -oE 'mtu [0-9]+' /tmp/h-pmtu.txt | head -1))" || bad "no cached PMTU exception for the VIP: $(tr -s ' \n' ' ' < /tmp/h-pmtu.txt)"
H3TMO=2; batch 20 h3 /tmp/h-poisoned.txt; H3TMO=5
[ "$(n200 /tmp/h-poisoned.txt)" = "0" ] && ok "with that cache in place NO HTTP/3 request succeeds, not even to the untouched node ($(mix /tmp/h-poisoned.txt)) — a shared address shares its path MTU" || bad "h3 with a poisoned PMTU cache: $(mix /tmp/h-poisoned.txt)"
ip netns exec rtr ip link set r-e2 mtu 1500; ip netns exec edge2 ip link set e2-r mtu 1500
# Restoring the link does not undo the client's cache: the exception has to
# expire or be flushed. An operator watching only the link will call this a
# ghost.
H3TMO=2; batch 10 h3 /tmp/h-stale.txt; H3TMO=5
[ "$(n200 /tmp/h-stale.txt)" = "0" ] && ok "the link is 1500 again and HTTP/3 is STILL broken ($(mix /tmp/h-stale.txt)): the cached exception outlives the fault that caused it" || bad "h3 recovered without a cache flush: $(mix /tmp/h-stale.txt)"
ip netns exec cli ip route flush cache
sleep 0.5
batch 20 h3 /tmp/h-back.txt
[ "$(n200 /tmp/h-back.txt)" = "20" ] && [ "$(served edge-2 /tmp/h-back.txt)" -ge 1 ] && ok "after \`ip route flush cache\` on the client: 20 of 20 over HTTP/3, both nodes serving again" || bad "h3 after the MTU restore and flush: $(mix /tmp/h-back.txt), edge-2 $(served edge-2 /tmp/h-back.txt)"

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
      # Recorded, because these loops cannot be found by name later: a script
      # started by path runs as `/bin/sh /tmp/announce-N.sh`.
      ANN_PIDS="$ANN_PIDS $!"
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
    node_nginx 2 edge2 $STATE2; wait_nginx 2
    for i in $(seq 1 60); do [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && break; sleep 0.5; done
    [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && ok "nginx back: the announcement returns and the route is multipath again" || bad "the route did not come back: $(vip_route)"
    ZONEB_EXTRA=$EXTRA_BROKEN; zones_yaml; reload_brain
    wait_eq 40 false sfield 2 converged || bad "edge-2 did not refuse the broken document (arm I)"
    sleep 3
    [ "$(ip netns exec rtr ip route show $VIP/32 | grep -c nexthop)" -ge 2 ] && ok "a refused document did NOT withdraw the route: /healthz stayed 200, so the speaker stayed enabled" || bad "a refused document withdrew the route: $(vip_route)"
    ZONEB_EXTRA=""; zones_yaml; reload_brain
    # shellcheck disable=SC2086
    kill $ANN_PIDS 2>/dev/null; ANN_PIDS=""
    pkill -f 'announce-[12]\.sh' 2>/dev/null; pkill -f 'bird -c' 2>/dev/null
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
  echo "       the inventory said alive:false ${D_LOST_MS} ms after the kill — stale_after_seconds $STALE"
  echo "       after the dead node's last sighting, which is the whole of that delay"
  echo "arm D2 (the operator's withdrawal): the first all-200 batch of five completed ${D2_MS} ms after"
  echo "       the \`ip route replace\`, then 40/40 TCP and 20/20 h3 — a withdrawal is a RIB change,"
  echo "       so what bounds recovery is the client's next request, not any Kapkan timer"
  echo "arm E  (the node's own signal): /healthz turned 503 ${E_MS} ms after nginx died — the bound is one"
  echo "       controller.report_interval_seconds (1 s in this rig; the product default is 10), the tick the"
  echo "       terminator-liveness check rides, so an operator withdrawing on /healthz sets it to their probe period"
  echo "arm F  (the brain's return): both nodes alive again ${F_MS} ms after it came back — what bounds this is"
  echo "       the node's own poll backoff (1 s doubling to 30 s) and never stale_after: the nodes were alive"
  echo "       throughout, they simply had nowhere to poll"
  echo "arm H  (MTU 1200 on one leg): $H_FAIL of 40 h3 requests failed while TCP was 40/40 — not a share:"
  echo "       the client caches that path MTU for the VIP itself, so HTTP/3 fails toward the healthy"
  echo "       node too, and stays broken after the link is repaired until the cache is flushed"
  [ -f /tmp/arm-i.txt ] && cat /tmp/arm-i.txt
} > /tmp/numbers.txt
echo
sed 's/^/  /' /tmp/numbers.txt
echo
echo "== E6.9 anycast acceptance: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
