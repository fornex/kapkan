#!/usr/bin/env bash
#
# E6 acceptance: the fleet as a product — tenancy, token↔node binding, placement
# and the edge history — on a real kernel with a real nginx, a real ACME CA and
# a real ClickHouse (engine/docs/edge-spec.md §8, milestone E6; the E6 plan's
# §5 acceptance map). The E5 rig's topology on Debian 13 (stock nginx 1.26.3
# with the HTTP/3 module, curl with HTTP3), the brain inside the edge netns,
# two nodes (edge-1, edge-2), Pebble, and ClickHouse beside the brain — the
# binary extracted from the SAME pinned image CI's storage-clickhouse job uses
# (the rig prints the version it ran against). Five zones under four
# hostgroups (edge-eu, edge-us, edge-asia — the group nobody lists — and the
# tenant group acme) and two tenants; seven token names, six configured at a
# time (the shared t0 gives way to t1 → edge-1 and t2 → edge-2). The data
# plane is E5's subject and stays out of this rig.
#
# Arms, in the order they run, each a row of the plan's acceptance table:
#
#   K.  a fleet without scopes: one document, byte for byte, for every node;
#   B.  grace and migration without downtime — both nodes on a shared agent
#       token (WARNING, unbound_agent_tokens, last_token), one bound per node,
#       binding never moves a document (installs and ETags still), the shared
#       token removed under a live node (LOST; fail-static: TLS, h3 and the
#       node's own 429s), bound, alive again;
#   A.  binding refuses another node's name on every route of both channels,
#       saving nothing;
#   C.  the operator previews a stopped node's document without presence;
#   T1. tenancy is not an event for a node (labels → ETags, generations,
#       nginx workers all still);
#   T2. default-deny: a tenant sees exactly its zones, no foreign hostname,
#       no tenant field; scoped tokens get no topology;
#   T3. the tenant's lever: the same policy in the same document, no reload,
#       audited under the tenant;
#   T4. no existence oracle on the lever;
#   T5. a relabel follows the file (a tenant is made by its zones — ETag
#       still); a zone/hostgroup tenant mismatch and a zone removed under a
#       live token are refused, -check-config repeats both;
#   T6. certificate expiry for a tenant without the inventory;
#   S1–S4. rows land once, an idle deciding zone writes no decided window
#       (only the CA's undecided probe windows), only the telling sources,
#       the read API equals SQL and is default-deny;
#   S5. the node's chronology as events;
#   D.  placement: one document per node, rendered only where placed;
#   E.  fan-out only to the serving nodes; a slot outside the scope is 404;
#   F.  unserved and the lever by placement;
#   G.  an impossible or broken configuration never goes live;
#   H.  fail-static under a wrong rebind, ended by the reload itself;
#   I.  moving a zone;  J. the brain dead and restarted under placement;
#   S6. the report is not trusted;  S7. never blocks — ClickHouse dead under
#       a report burst;  S9. retention;
#   S8. storage off is byte-identical;  S10. nothing to steal, fail-static.
#
# Three rows are met differently from the plan's wording, for product reasons
# the arms state: T5 — a relabel to an unused tenant is ACCEPTED (E6.2: a
# tenant is made by its zones); S6 — the per-window source cap is proved with
# 150 sources (1 000 exceed the 64 KiB report body and are 413); E — a node
# outside a zone's placement closes the connection on :80 (nginx return 444)
# rather than answering 404.
#
# Build the binaries for the container arch first (from engine/), extract the
# ClickHouse binary from the pinned image, then run this inside one privileged
# debian:13-slim container (never two rigs at once; the script refuses to run
# outside a container — it rewrites /etc/hosts and kills every nginx):
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan
#   git clone --depth 1 https://github.com/letsencrypt/pebble /tmp/pebble-src \
#     && (cd /tmp/pebble-src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/pebble ./cmd/pebble)
#   c=$(docker create clickhouse/clickhouse-server:25.8) && docker cp "$c:/usr/bin/clickhouse" /tmp/lab/clickhouse && docker rm "$c"
#   docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:13-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq \
#              iproute2 iptables nginx openssl curl python3 procps iputils-ping ca-certificates tcpdump >/dev/null \
#            && KAPKAN=/lab/kapkan PEBBLE=/lab/pebble CLICKHOUSE=/lab/clickhouse bash engine/scripts/labnet/edge-e6.sh'
#
set -uo pipefail
export PATH=/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin
KAPKAN=${KAPKAN:-/lab/kapkan}
PEBBLE=${PEBBLE:-/lab/pebble}
CLICKHOUSE=${CLICKHOUSE:-/lab/clickhouse}
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
say() { echo; echo "== $1 =="; }
[ -x "$KAPKAN" ] || { echo "kapkan binary not found at $KAPKAN"; exit 2; }
[ -x "$PEBBLE" ] || { echo "pebble binary not found at $PEBBLE"; exit 2; }
[ -x "$CLICKHOUSE" ] || { echo "clickhouse binary not found at $CLICKHOUSE"; exit 2; }
nginx -V 2>&1 | grep -q -- --with-http_v3_module || { echo "this nginx has no http_v3_module: $(nginx -v 2>&1)"; exit 2; }
curl -V | grep -q HTTP3 || { echo "this curl has no HTTP3: $(curl -V | head -1)"; exit 2; }
command -v tcpdump >/dev/null || { echo "tcpdump is required (arm S8)"; exit 2; }
command -v iptables >/dev/null || { echo "iptables is required (arm S7)"; exit 2; }
command -v timeout >/dev/null || { echo "coreutils timeout is required (arm S8)"; exit 2; }
# The rig rewrites /etc/hosts, deletes a bridge named br0 and kills every nginx
# master it finds: a container's, never a host's.
[ -f /.dockerenv ] || [ "${KAPKAN_RIG_ALLOW_HOST:-}" = 1 ] || { echo "refusing to run outside a container (set KAPKAN_RIG_ALLOW_HOST=1 to override)"; exit 2; }

EDGE=203.0.113.10; EDGE2=203.0.113.11; BRAIN=203.0.113.20; ORIGIN=203.0.113.30; CA=203.0.113.40
SHOP=shop.test; API=api.test; US=us.test; STATIC=static.test; HOUSE=house.test
STATE1=/var/lib/kapkan-edge1; SOCKS1=/run/kapkan-edge1
STATE2=/var/lib/kapkan-edge2; SOCKS2=/run/kapkan-edge2
STALE=5
export KAPKAN_OP=optok KAPKAN_ACME_VIEW=acmeviewtok KAPKAN_ACME_OP=acmeoptok KAPKAN_GLOBEX_OP=globexoptok
export KAPKAN_T0=t0tok KAPKAN_T1=t1tok KAPKAN_T2=t2tok
tok() { case $1 in op) echo optok;; acme-view) echo acmeviewtok;; acme-op) echo acmeoptok;; globex-op) echo globexoptok;; t0) echo t0tok;; t1) echo t1tok;; t2) echo t2tok;; *) echo "$1";; esac; }

# hosts_drop NAME removes NAME's lines from /etc/hosts in place — the file is
# a Docker bind mount, so `sed -i` (rename over it) fails silently.
hosts_drop() { local tmp; tmp=$(grep -v " $1\$" /etc/hosts); printf '%s\n' "$tmp" > /etc/hosts; }
cleanup() {
  rm -f /tmp/s10-keys # the clearance keys S10 harvested never leave the box
  if [ -d /lab ]; then
    mkdir -p /lab/logs && cp -f /tmp/*.log /tmp/*.out /tmp/*.txt /tmp/*.tsv /tmp/*.json /tmp/*.conf /lab/logs/ 2>/dev/null
    cp -f /tmp/zones.yaml /tmp/edge1.yaml /tmp/edge2.yaml /tmp/brain.yaml /lab/logs/ 2>/dev/null
    for n in 1 2; do d=/var/lib/kapkan-edge$n/conf/live; [ -d "$d" ] && mkdir -p /lab/logs/edge$n-live && cp -f "$d"/*.conf /lab/logs/edge$n-live/ 2>/dev/null; done
  fi
  kill "$(cat /tmp/brain.pid 2>/dev/null)" "$(cat /tmp/edge1-nginx.pid 2>/dev/null)" "$(cat /tmp/edge2-nginx.pid 2>/dev/null)" 2>/dev/null
  pkill -f "^$KAPKAN " 2>/dev/null; pkill -f "^$PEBBLE " 2>/dev/null; pkill -f "^$CLICKHOUSE " 2>/dev/null
  pkill -f '^nginx: master' 2>/dev/null; pkill -f '^python3 /tmp/origin.py' 2>/dev/null; pkill -f '^tcpdump' 2>/dev/null
  for ns in edge edge2 origin ca legit attacker; do ip netns del "$ns" 2>/dev/null; done
  ip link del br0 2>/dev/null
  for z in $SHOP $API $US $STATIC $HOUSE; do hosts_drop "$z" 2>/dev/null; done
}
trap cleanup EXIT
cleanup

# ---------------------------------------------------------------- topology
say "building the netns topology (brain and ClickHouse inside the edge netns)"
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
ip netns exec edge ip addr add $BRAIN/24 dev vedge
add_ns edge2    $EDGE2       24 203.0.113.1
add_ns origin   $ORIGIN      24 203.0.113.1
add_ns ca       $CA          24 203.0.113.1
add_ns legit    203.0.113.2  24 203.0.113.1
add_ns attacker 198.51.100.3 24 198.51.100.1
ip netns exec attacker ip addr add 198.51.100.4/24 dev vattacker # a second source for arm H's burst
# The CA resolves a zone the way the world does: the global zones' "DNS" is
# edge-1 (whose :80 answers both nodes' challenges through the fan-out),
# us.test's is the node it is placed on — and follows the zone when it moves
# (arm I). A node outside a zone's placement has no server for the Host and
# closes the connection (nginx return 444): HTTP-01 fails there.
for z in $SHOP $API $STATIC $HOUSE; do printf '%s %s\n' "$EDGE" "$z" >> /etc/hosts; done
printf '%s %s\n' "$EDGE2" "$US" >> /etc/hosts
ip netns exec legit ping -c1 -W1 $EDGE >/dev/null 2>&1 && ok "legit reaches the edge" || bad "no path legit -> edge (topology broken; nothing below is meaningful)"
ip netns exec legit ping -c1 -W1 $BRAIN >/dev/null 2>&1 && ok "the brain's alias on vedge is reachable" || bad "no path to the brain alias"

# ---------------------------------------------------------------- origin
say "starting the origin (echoes the headers kapkan sets), on :8081 and :8082"
cat > /tmp/origin.py <<'PY'
import http.server, json, sys
port = int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        body = json.dumps({"path": self.path, "zone": self.headers.get("X-Kapkan-Zone", ""), "mark": self.headers.get("X-Kapkan-Mark", ""), "port": port}).encode()
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
http.server.ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
PY
: > /tmp/origin.log
ip netns exec origin python3 /tmp/origin.py 8081 &
ip netns exec origin python3 /tmp/origin.py 8082 &
for i in $(seq 1 20); do ip netns exec legit curl -s -m1 http://$ORIGIN:8081/ >/dev/null 2>&1 && break; sleep 0.3; done
grep -q '"path"' <<< "$(ip netns exec legit curl -s -m2 http://$ORIGIN:8081/)" && ok "origin answers directly" || bad "origin not answering"

# ---------------------------------------------------------------- Pebble (ACME CA)
say "starting Pebble: a real ACME CA validating HTTP-01 on the nodes' :80"
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

# ---------------------------------------------------------------- ClickHouse
say "starting ClickHouse beside the brain (loopback of the edge netns, :8123)"
mkdir -p /tmp/ch
cat > /tmp/ch.xml <<'XML'
<clickhouse>
  <logger><level>warning</level><console>true</console></logger>
  <listen_host>127.0.0.1</listen_host>
  <http_port>8123</http_port>
  <tcp_port>9000</tcp_port>
  <path>/tmp/ch/</path>
  <tmp_path>/tmp/ch/tmp/</tmp_path>
  <user_files_path>/tmp/ch/user_files/</user_files_path>
  <format_schema_path>/tmp/ch/format_schemas/</format_schema_path>
  <mark_cache_size>134217728</mark_cache_size>
  <max_server_memory_usage_to_ram_ratio>0.5</max_server_memory_usage_to_ram_ratio>
  <users>
    <default>
      <password></password>
      <networks><ip>::1</ip><ip>127.0.0.1</ip></networks>
      <profile>default</profile>
      <quota>default</quota>
      <access_management>1</access_management>
    </default>
  </users>
  <profiles><default></default></profiles>
  <quotas><default></default></quotas>
</clickhouse>
XML
start_ch() { ip netns exec edge "$CLICKHOUSE" server --config-file=/tmp/ch.xml >>/tmp/clickhouse.log 2>&1 & }
stop_ch() { pkill -f "^$CLICKHOUSE server" 2>/dev/null; for i in $(seq 1 50); do pgrep -f "^$CLICKHOUSE server" >/dev/null || return 0; sleep 0.2; done; pkill -9 -f "^$CLICKHOUSE server" 2>/dev/null; }
# chq QUERY -> the query's answer (TSV), through ClickHouse's HTTP port;
# chq_code QUERY -> the HTTP code of the statement (an INSERT that failed is
# not silence).
chq() { ip netns exec edge curl -s -m10 'http://127.0.0.1:8123/' --data-binary "$1" 2>/dev/null; }
chq_code() { ip netns exec edge curl -s -o /dev/null -w '%{http_code}' -m10 'http://127.0.0.1:8123/' --data-binary "$1" 2>/dev/null; }
wait_ch() { local i; for i in $(seq 1 100); do [ "$(chq 'SELECT 1')" = "1" ] && return 0; sleep 0.3; done; return 1; }
: > /tmp/clickhouse.log
start_ch
wait_ch && ok "ClickHouse answers SELECT 1 ($("$CLICKHOUSE" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9.]+' | head -1))" || { bad "ClickHouse did not start (see /tmp/clickhouse.log)"; tail -5 /tmp/clickhouse.log; }

# ---------------------------------------------------------------- the brain
say "starting the brain: five zones, four hostgroups, humans + one shared agent token, storage on"
# zones_yaml renders /tmp/zones.yaml from the globals below; every arm sets
# what it changes and re-renders. Every zone says challenge: off — in the
# FILE, `manual` means the clearance page for every request; the lever (T3)
# is what turns the rung on, over the document, without a reload.
SHOP_TENANT=""; API_TENANT=""; STATIC_TENANT=""; STATIC_HG=""; US_HG="edge-us"; HOUSE_HG=""
SHOP_RPS=1000; SHOP_DRY=false; SHOP_EXTRA=""; SHOP_ORIGIN_PORT=8081
zones_yaml() {
  {
    echo "zones:"
    echo "  - name: $SHOP"
    [ -n "$SHOP_TENANT" ] && echo "    tenant: \"$SHOP_TENANT\""
    echo "    origins: [\"$ORIGIN:$SHOP_ORIGIN_PORT\"]"
    echo "    tls: { min_version: \"1.2\", h3: true }"
    echo "    acme: { directory: \"https://$CA:14000/dir\" }"
    echo "    policy:"
    echo "      mode: decide"
    echo "      failure_mode: open"
    echo "      dry_run: $SHOP_DRY"
    echo "      challenge: off"
    echo "      challenge_options: { dry_run: false, difficulty: 12, cookie_ttl_seconds: 120 }"
    echo "      rate: { rps: $SHOP_RPS }"
    [ -n "$SHOP_EXTRA" ] && echo "    extra_directives_file: \"$SHOP_EXTRA\""
    echo "  - name: $API"
    [ -n "$API_TENANT" ] && echo "    tenant: \"$API_TENANT\""
    echo "    origins: [\"$ORIGIN:8081\"]"
    echo "    acme: { directory: \"https://$CA:14000/dir\" }"
    echo "    policy: { mode: none }"
    echo "  - name: $US"
    [ -n "$US_HG" ] && echo "    hostgroup: $US_HG"
    echo "    origins: [\"$ORIGIN:8081\"]"
    echo "    acme: { directory: \"https://$CA:14000/dir\" }"
    echo "    policy: { mode: decide, failure_mode: open, challenge: off, rate: { rps: 1000 } }"
    echo "  - name: $STATIC"
    [ -n "$STATIC_TENANT" ] && echo "    tenant: \"$STATIC_TENANT\""
    [ -n "$STATIC_HG" ] && echo "    hostgroup: $STATIC_HG"
    echo "    origins: [\"$ORIGIN:8081\"]"
    echo "    acme: { directory: \"https://$CA:14000/dir\" }"
    echo "    policy: { mode: decide, failure_mode: open, challenge: off, rate: { rps: 1000 } }"
    echo "  - name: $HOUSE"
    [ -n "$HOUSE_HG" ] && echo "    hostgroup: $HOUSE_HG"
    echo "    origins: [\"$ORIGIN:8081\"]"
    echo "    acme: { directory: \"https://$CA:14000/dir\" }"
    echo "    policy: { mode: decide, failure_mode: open, challenge: off, rate: { rps: 1000 } }"
  } > /tmp/zones.yaml
}
# brain_yaml renders /tmp/brain.yaml: AGENTS is the agent-token block, NODES
# the edge.nodes block, STORAGE "on" or "off".
HUMANS='    - { name: op, token_env: KAPKAN_OP, role: operator }
    - { name: acme-view, token_env: KAPKAN_ACME_VIEW, role: viewer, tenant: acme }
    - { name: acme-op, token_env: KAPKAN_ACME_OP, role: operator, tenant: acme }'
GLOBEX_OP='    - { name: globex-op, token_env: KAPKAN_GLOBEX_OP, role: operator, tenant: globex }'
AG_T0='    - { name: t0, token_env: KAPKAN_T0, role: agent }'
AG_T2='    - { name: t2, token_env: KAPKAN_T2, role: agent, node: edge-2 }'
AG_T1='    - { name: t1, token_env: KAPKAN_T1, role: agent, node: edge-1 }'
AG_T1_WRONG='    - { name: t1, token_env: KAPKAN_T1, role: agent, node: edge-2 }'
NODES_PLAIN='    - name: edge-1
    - name: edge-2'
NODES_SCOPED='    - { name: edge-1, hostgroups: [edge-eu, global] }
    - { name: edge-2, hostgroups: [edge-us, global] }'
HUMANS_NOW="$HUMANS"
brain_yaml() { # AGENTS NODES STORAGE(on|off)
  local storage=""
  [ "$3" = "on" ] && storage='storage:
  clickhouse: { url: "http://127.0.0.1:8123", database: kapkan, ttl_days: 1, flush_interval_seconds: 1, batch_size: 50, queue_size: 50, traffic_interval_seconds: 10 }'
cat > /tmp/brain.yaml <<YAML
dry_run: false
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
hostgroups:
  - { name: edge-eu, networks: ["$EDGE/32"] }
  - { name: edge-us, networks: ["$EDGE2/32"] }
  - { name: edge-asia, networks: ["203.0.113.12/32"] }
  - { name: acme, networks: ["203.0.113.64/32"], tenant: acme }
$storage
api:
  listen: "$BRAIN:8080"
  tokens:
$HUMANS_NOW
$1
edge:
  zones_file: /tmp/zones.yaml
  state_file: /tmp/edge-state.json
  stale_after_seconds: $STALE
  nodes:
$2
YAML
}
zones_yaml
brain_yaml "$AG_T0" "$NODES_PLAIN" on
start_brain() {
  ip netns exec edge "$KAPKAN" -config /tmp/brain.yaml -log-format text -log-level info -pid-file /tmp/brain.pid >>/tmp/brain.log 2>&1 &
  for i in $(seq 1 40); do ip netns exec edge curl -s -m1 http://$BRAIN:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done
}
kill_brain() { kill "$(cat /tmp/brain.pid 2>/dev/null)" 2>/dev/null; for i in $(seq 1 30); do ip netns exec edge curl -s -m1 "http://$BRAIN:8080/healthz" >/dev/null 2>&1 || return 0; sleep 0.2; done; return 1; }
reloads() { grep -c 'config reloaded' /tmp/brain.log; }
reload_failures() { grep -c 'config reload failed' /tmp/brain.log; }
# reload_brain sends SIGHUP and waits for the brain to say what it made of it
# (one more "config reloaded" or "config reload failed" line), up to ten
# seconds — the reload is asynchronous, the log is the outcome.
reload_brain() {
  local r f i; r=$(reloads); f=$(reload_failures)
  ip netns exec edge "$KAPKAN" -s reload -pid-file /tmp/brain.pid >/dev/null 2>&1
  for i in $(seq 1 50); do { [ "$(reloads)" -gt "$r" ] || [ "$(reload_failures)" -gt "$f" ]; } 2>/dev/null && return 0; sleep 0.2; done
  echo "  (reload_brain: no outcome line within 10 s)"; return 1
}
check_config() { "$KAPKAN" -check-config /tmp/brain.yaml > /tmp/check.out 2>&1; echo $?; }
# api TOKENNAME URL [curl args] -> body ; code TOKENNAME METHOD URL [BODY] -> http code
api()  { local t=$1 u=$2; shift 2; ip netns exec edge curl -s -m5 -H "Authorization: Bearer $(tok "$t")" "$@" "$u" 2>/dev/null; }
code() { local t=$1 m=$2 u=$3 b=${4:-}; if [ -n "$b" ]; then ip netns exec edge curl -s -o /dev/null -w '%{http_code}' -m5 -X "$m" -H "Authorization: Bearer $(tok "$t")" -H 'Content-Type: application/json' -d "$b" "$u" 2>/dev/null; else ip netns exec edge curl -s -o /dev/null -w '%{http_code}' -m5 -X "$m" -H "Authorization: Bearer $(tok "$t")" -H 'Content-Type: application/json' "$u" 2>/dev/null; fi; }
cbody() { local t=$1 m=$2 u=$3 b=${4:-}; ip netns exec edge curl -s -m5 -X "$m" -H "Authorization: Bearer $(tok "$t")" -H 'Content-Type: application/json' ${b:+-d "$b"} "$u" 2>/dev/null; }
B="http://$BRAIN:8080/api/v1"
# jx EXPR <json -> python expression over d (the parsed document)
jx() { python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: d={}
try: v=eval(sys.argv[1], {}, {'d': d, 'len': len, 'sorted': sorted, 'set': set, 'str': str, 'int': int, 'float': float, 'any': any, 'all': all, 'sum': sum, 'max': max, 'min': min})
except Exception as e: v=''
print(v if not isinstance(v,bool) else str(v).lower())" "$1" 2>/dev/null; }
# etag TOKEN NODE -> the ETag of GET /edge/zones?node=NODE ; doc TOKEN NODE -> its body
etag() { ip netns exec edge curl -s -o /dev/null -D - -m5 -H "Authorization: Bearer $(tok "$1")" "$B/edge/zones?node=$2" 2>/dev/null | grep -i '^etag:' | awk '{print $2}' | tr -d '\r'; }
doc()  { api "$1" "$B/edge/zones?node=$2"; }
# node_f NODE EXPR (python over n, the node's inventory entry); inv_f EXPR
# (over d, the inventory document); zst TOKEN ZONE EXPR (over z, the zone's
# status row — {} when absent).
node_f() { api op "$B/edge/nodes" | jx "(lambda n: $2)(([n for n in d.get('nodes',[]) if n.get('name')=='$1']+[{}])[0])"; }
inv_f()  { api op "$B/edge/nodes" | jx "$1"; }
zst()    { api "$1" "$B/edge/zones/status" | jx "(lambda z: $3)(([z for z in d.get('zones',[]) if z.get('zone')=='$2']+[{}])[0])"; }
zlist()  { api "$1" "$B/edge/zones/status" | jx "' '.join(sorted(z.get('zone') for z in d.get('zones',[])))"; }
lever()  { code "$1" "$2" "$B/edge/zones/$3/challenge" "${4:-}"; }
hist()   { api "$1" "$B/edge/history?$2"; }
events() { api "$1" "$B/edge/events?$2"; }
brain_metric() { ip netns exec edge curl -s -m3 http://$BRAIN:8080/metrics 2>/dev/null | grep "^$1" | awk '{s+=$NF} END {print s+0}'; }
wait_eq() { # SECS WANT CMD... -> until $(CMD) == WANT
  local n=$(( $1 * 5 )) want=$2 i; shift 2
  for i in $(seq 1 $n); do [ "$("$@")" = "$want" ] && return 0; sleep 0.2; done; return 1
}
wait_ne() { # SECS NOTWANT CMD... -> until $(CMD) != NOTWANT
  local n=$(( $1 * 5 )) not=$2 i; shift 2
  for i in $(seq 1 $n); do [ "$("$@")" != "$not" ] && return 0; sleep 0.2; done; return 1
}
wait_sql() { # SECS WANT QUERY -> until chq QUERY == WANT
  local n=$(( $1 * 2 )) i; for i in $(seq 1 $n); do [ "$(chq "$3")" = "$2" ] && return 0; sleep 0.5; done; return 1
}
# settle_etag TOKEN NODE -> the node's document ETag once two reads a second
# apart agree (grants expire and levers lapse on their own clock).
settle_etag() { local a b i; for i in $(seq 1 15); do a=$(etag "$1" "$2"); sleep 1; b=$(etag "$1" "$2"); [ "$a" = "$b" ] && { echo "$a"; return 0; }; done; echo "$b"; }
# ev_count KIND [NODE] -> how many events of the kind (for the node);
# ev_more KIND N [NODE] -> true once the count exceeds N; ev_newest KIND NODE
# FIELD -> the newest event's field (the read is newest first).
ev_count() { events op "kind=$1${2:+&node=$2}" | jx "len(d.get('events') or [])"; }
ev_more()  { [ "$(ev_count "$1" "${3:-}")" -gt "$2" ] 2>/dev/null && echo true || echo false; }
ev_newest() { events op "kind=$1&node=$2" | jx "(d.get('events') or [{}])[0].get('$3','')"; }
node_etag() { sfield "$1" accepted_etag; }
audit_n() { api "$1" "$B/audit?action=edge_challenge" | jx "len([r for r in (d.get('events') or []) if r.get('action')=='edge_challenge'])"; }
audit_ge() { [ "$(audit_n "$1")" -ge "$2" ] 2>/dev/null && echo true || echo false; }
: > /tmp/brain.log
start_brain
c=$(code t0 GET "$B/edge/zones?node=edge-1"); [ "$c" = "200" ] && ok "brain serves the zones document to the shared agent token" || { bad "no zones document (got '$c')"; tail -15 /tmp/brain.log; }
for i in $(seq 1 50); do chq "SHOW DATABASES" | grep -qx kapkan && break; sleep 0.2; done
chq "SHOW DATABASES" | grep -qx kapkan && ok "the brain runs with storage on: it created the kapkan database" || bad "no kapkan database in ClickHouse: $(chq 'SHOW DATABASES' | tr '\n' ' ')"

# ---------------------------------------------------------------- nginx + kapkan edge, two nodes
say "starting stock nginx and kapkan edge on both nodes (both on the shared token t0)"
node_nginx() { # N STATE PIDFILE NS
  mkdir -p "$2/conf"
  cat > /tmp/edge$1-nginx.conf <<CONF
daemon off;
user www-data;
worker_processes 1;
pid /tmp/edge$1-nginx.pid;
error_log /tmp/edge$1-nginx-error.log warn;
events { worker_connections 1024; }
http {
  access_log off;
  include $2/conf/live/*.conf;
}
CONF
  ip netns exec "$4" nginx -c /tmp/edge$1-nginx.conf >/tmp/edge$1-nginx.log 2>&1 &
}
node_nginx 1 $STATE1 /tmp/edge1-nginx.pid edge
node_nginx 2 $STATE2 /tmp/edge2-nginx.pid edge2
sleep 0.5
[ "$(pgrep -fc 'nginx: master')" = "2" ] && ok "two nginx masters are up ($(nginx -v 2>&1 | grep -oE '[0-9.]+$'))" || bad "nginx masters: $(pgrep -fc 'nginx: master')"
edge_yaml() { # N STATE SOCKS PORT
cat > /tmp/edge$1.yaml <<YAML
dry_run: false
controller: { url: "http://$BRAIN:8080", token_env: KAPKAN_EDGE_TOKEN, name: edge-$1, report_interval_seconds: 1 }
state_dir: $2
sockets_dir: $3
socket_group: www-data
terminator: { binary: nginx, main_conf: /tmp/edge$1-nginx.conf, reload: exec, pid_file: /tmp/edge$1-nginx.pid }
acme: { contact: ["mailto:lab@example.test"] }
quic: { h3: auto, retry: true }
status_listen: 127.0.0.1:910$1
YAML
}
edge_yaml 1 $STATE1 $SOCKS1; edge_yaml 2 $STATE2 $SOCKS2
mkdir -p $SOCKS1 $SOCKS2
ns_of() { [ "$1" = "1" ] && echo edge || echo edge2; }
start_edge() { # N TOKENNAME
  KAPKAN_EDGE_TOKEN=$(tok "$2") SSL_CERT_FILE=/tmp/pebble.crt ip netns exec "$(ns_of "$1")" "$KAPKAN" edge -config /tmp/edge$1.yaml -log-format text -log-level info >>/tmp/edge$1.log 2>&1 &
}
stop_edge() { # N
  pkill -f "^$KAPKAN edge -config /tmp/edge$1.yaml" 2>/dev/null
  for i in $(seq 1 100); do pgrep -f "^$KAPKAN edge -config /tmp/edge$1.yaml" >/dev/null || return 0; sleep 0.1; done
  bad "edge-$1 did not stop within 10 s of SIGTERM"
}
sfield() { ip netns exec "$(ns_of "$1")" curl -s -m2 http://127.0.0.1:910$1/healthz 2>/dev/null | jx "d.get('$2','')"; }
installs() { grep -c 'configuration installed' /tmp/edge$1.log; }
# refusals N -> how many times the brain refused edge-N's credentials (the
# node logs the status it got; the bare digits would also match timestamps).
refusals() { grep -cE 'status=40[13]' /tmp/edge$1.log; }
wait_healthy() { wait_eq "$2" true sfield "$1" healthy; }
wait_gen() { local i; for i in $(seq 1 $(( $3 * 5 ))); do [ "$(sfield "$1" generation)" = "$2" ] && [ "$(sfield "$1" converged)" = "true" ] && return 0; sleep 0.2; done; return 1; }
settle() { # N — wait until the generation stops moving and is converged
  local i g; for i in $(seq 1 30); do g=$(sfield "$1" generation); sleep 2; [ "$(sfield "$1" generation)" = "$g" ] && [ "$(sfield "$1" converged)" = "true" ] && return 0; done; return 1
}
# get NS ZONE IP [curl args] -> http code over TCP; h3get -> "code version" over --http3-only
get()   { local ns=$1 z=$2 ip=$3; shift 3; ip netns exec "$ns" curl -s -o /dev/null -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$z:443:$ip" "$@" "https://$z/${RANDOM}" 2>/dev/null; }
h3get() { local ns=$1 z=$2 ip=$3; shift 3; ip netns exec "$ns" curl -s -o /dev/null -w '%{http_code} %{http_version}' -m5 --http3-only --cacert /tmp/pebble-root.crt --resolve "$z:443:$ip" "$@" "https://$z/${RANDOM}" 2>/dev/null; }
body()  { local ns=$1 z=$2 ip=$3; shift 3; ip netns exec "$ns" curl -s -m5 --cacert /tmp/pebble-root.crt --resolve "$z:443:$ip" "$@" "https://$z/${RANDOM}" 2>/dev/null; }
is_page() { grep -q 'kapkan-puzzle' <<< "$1"; }
# burst_refused NS ZONE IP N [SRC] -> "refused/N codes…": how many of N quick
# requests the node itself refused — 429 (its ceiling) or 403 (the rollup's
# flood rule promoting a source over its ceiling to a table denial) — from
# source address SRC when given. Decided locally either way.
burst_refused() {
  local ns=$1 z=$2 ip=$3 n=$4 src=${5:-} i c=0 code codes=""
  for i in $(seq 1 "$n"); do
    code=$(get "$ns" "$z" "$ip" ${src:+--interface "$src"}); codes="$codes $code"
    case $code in 429|403) c=$((c+1));; esac
  done
  echo "$c/$n $(tr -s ' ' '\n' <<< "$codes" | sort | uniq -c | tr -s ' \n' ' ')"
}
: > /tmp/edge1.log; : > /tmp/edge2.log
start_edge 1 t0; start_edge 2 t0
wait_healthy 1 40 && ok "edge-1 healthy: a tested generation is live" || { bad "edge-1 never became healthy"; tail -10 /tmp/edge1.log; }
wait_healthy 2 40 && ok "edge-2 healthy" || { bad "edge-2 never became healthy"; tail -10 /tmp/edge2.log; }
# Four zones served by both nodes (us.test is placed on edge-us, which no node
# lists yet): eight certificates from Pebble, each node issuing its own — the
# global zones' hosts entries point at edge-1, so edge-2's four validations
# could only pass through the fan-out to edge-1's :80.
for i in $(seq 1 900); do [ "$(grep -c 'certificate issued' /tmp/edge1.log)" -ge 4 ] && [ "$(grep -c 'certificate issued' /tmp/edge2.log)" -ge 4 ] && break; sleep 0.2; done
[ "$(grep -c 'certificate issued' /tmp/edge1.log)" -ge 4 ] && [ "$(grep -c 'certificate issued' /tmp/edge2.log)" -ge 4 ] && ok "eight certificates issued by Pebble (four zones on each node; edge-2's validated through the fan-out on edge-1's :80)" || { bad "certificates not issued in 180 s (edge-1 $(grep -c 'certificate issued' /tmp/edge1.log), edge-2 $(grep -c 'certificate issued' /tmp/edge2.log))"; grep -i 'acme\|certif' /tmp/edge1.log | tail -3; }
ip netns exec legit curl -sk -m3 https://$CA:15000/roots/0 > /tmp/pebble-root.crt 2>/dev/null
grep -q 'BEGIN CERTIFICATE' /tmp/pebble-root.crt && ok "fetched Pebble's root for the clients" || bad "could not fetch Pebble's root"
settle 1; settle 2
for i in $(seq 1 50); do [ "$(get legit $SHOP $EDGE)" = "200" ] && [ "$(get legit $SHOP $EDGE2)" = "200" ] && break; sleep 0.2; done
[ "$(get legit $SHOP $EDGE)" = "200" ] && [ "$(get legit $SHOP $EDGE2)" = "200" ] && ok "$SHOP is served by both nodes over TLS" || bad "$SHOP: edge-1 $(get legit $SHOP $EDGE), edge-2 $(get legit $SHOP $EDGE2)"
[ "$(h3get legit $SHOP $EDGE)" = "200 3" ] && ok "…and over HTTP/3 on edge-1" || bad "h3 on edge-1: $(h3get legit $SHOP $EDGE)"
[ "$(get legit $API $EDGE)" = "200" ] && [ "$(get legit $STATIC $EDGE2)" = "200" ] && ok "$API and $STATIC served ($HOUSE is left untouched: the quiet zone of arm S2)" || bad "the other zones: api $(get legit $API $EDGE) static $(get legit $STATIC $EDGE2)"
[ "$(get legit $US $EDGE)" != "200" ] && [ "$(get legit $US $EDGE2)" != "200" ] && ok "$US (placed on edge-us, which no node lists) is served nowhere" || bad "$US served before any node listed edge-us"
[ "$(zst op $US "z['placement']['nodes']")" = "[]" ] && ok "status: $US placement.nodes is [] (a group without nodes)" || bad "$US placement: $(zst op $US "z['placement']")"
G1_0=$(sfield 1 generation); G2_0=$(sfield 2 generation); I1_0=$(installs 1); I2_0=$(installs 2)
echo "  (edge-1 generation $G1_0, $I1_0 installs; edge-2 generation $G2_0, $I2_0 installs)"

# ================================================================ ARM K
say "ARM K — a fleet without scopes: one document, byte for byte, for every node"
doc op edge-1 > /tmp/doc-e1.json; doc op edge-2 > /tmp/doc-e2.json; api op "$B/edge/zones" > /tmp/doc-bare.json
cmp -s /tmp/doc-e1.json /tmp/doc-e2.json && ok "?node=edge-1 and ?node=edge-2 are byte-identical ($(wc -c < /tmp/doc-e1.json) bytes)" || bad "documents differ across nodes without scopes"
[ -n "$(etag op edge-1)" ] && [ "$(etag op edge-1)" = "$(etag op edge-2)" ] && ok "one ETag for the fleet ($(etag op edge-1))" || bad "ETags differ: $(etag op edge-1) vs $(etag op edge-2)"
[ "$(jx "len(d.get('zones',[]))" < /tmp/doc-e1.json)" = "4" ] && ok "each node's document carries the four global zones ($US, placed on a group nobody lists, is in no node's document)" || bad "zones in the document: $(jx "sorted(z['name'] for z in d.get('zones',[]))" < /tmp/doc-e1.json)"
[ "$(jx "len(d.get('zones',[]))" < /tmp/doc-bare.json)" = "5" ] && ok "the bare GET (no node) is the whole file: five zones (the pre-E6 golden is the unit test TestEdgePlacementGoldenWithoutScopes; the rig proves identity across nodes)" || bad "bare GET zones: $(jx "len(d.get('zones',[]))" < /tmp/doc-bare.json)"

# ================================================================ ARM B
say "ARM B — grace and migration: from one shared agent token to one bound token per node, no downtime"
rc=$(check_config); grep -q 'WARNING.*agent token' /tmp/check.out && [ "$rc" = "0" ] && ok "-check-config: OK with a WARNING about the unbound agent token" || bad "-check-config on the shared token: rc=$rc $(grep -i warning /tmp/check.out | head -1)"
grep -qi 'not bound to a node' /tmp/brain.log && ok "the brain's log warned about the unbound agent token at start" || bad "no unbound-token warning in the brain log"
[ "$(inv_f "d['unbound_agent_tokens']")" = "['t0']" ] && ok "inventory: unbound_agent_tokens [t0]" || bad "unbound_agent_tokens: $(inv_f "d['unbound_agent_tokens']")"
[ "$(node_f edge-1 "n['last_token']")" = "t0" ] && [ "$(node_f edge-2 "n['last_token']")" = "t0" ] && ok "both nodes last polled with t0 (last_token)" || bad "last_token: $(node_f edge-1 "n['last_token']") / $(node_f edge-2 "n['last_token']")"
ET1=$(sfield 1 accepted_etag); ET2=$(sfield 2 accepted_etag)
brain_yaml "$AG_T0
$AG_T2" "$NODES_PLAIN" on; reload_brain
sleep 2
[ "$(sfield 1 accepted_etag)" = "$ET1" ] && [ "$(sfield 2 accepted_etag)" = "$ET2" ] && [ "$(installs 1)" = "$I1_0" ] && [ "$(installs 2)" = "$I2_0" ] && ok "binding t2 to edge-2 moved neither ETag nor an install: binding is not a document change" || bad "a token change moved something: etags $ET1/$(sfield 1 accepted_etag) $ET2/$(sfield 2 accepted_etag), installs $I1_0/$(installs 1) $I2_0/$(installs 2)"
stop_edge 2; start_edge 2 t2
wait_eq 15 t2 node_f edge-2 "n['last_token']" && ok "edge-2 restarted on its bound token: last_token t2" || bad "edge-2 last_token: $(node_f edge-2 "n['last_token']")"
[ "$(node_f edge-2 "n['tokens']")" = "['t2']" ] && ok "inventory: edge-2 tokens [t2]" || bad "edge-2 tokens: $(node_f edge-2 "n['tokens']")"
[ "$(sfield 2 generation)" = "$G2_0" ] && [ "$(installs 2)" = "$I2_0" ] && ok "the restart on the bound token installed nothing (generation $G2_0)" || bad "edge-2 after the token switch: gen $(sfield 2 generation), installs $(installs 2)"
# A low ceiling on shop.test (the fast path: no install), so the node's OWN
# decisions are visible while the brain refuses it.
SHOP_RPS=2; zones_yaml; E1=$(sfield 1 accepted_etag); reload_brain; wait_ne 10 "$E1" node_etag 1 || bad "the low ceiling never reached edge-1"
# The shared token removed while edge-1 still uses it: the brain refuses its
# polls (401: the token is gone), presence marks it lost, the box keeps
# serving AND deciding from disk.
R1=$(refusals 1)
brain_yaml "$AG_T2" "$NODES_PLAIN" on; reload_brain
wait_eq 20 false node_f edge-1 "n['alive']" && ok "edge-1 on the removed token is LOST after stale_after" || bad "edge-1 alive: $(node_f edge-1 "n['alive']")"
[ "$(refusals 1)" -gt "$R1" ] && ok "edge-1's log shows the brain's refusal (status=401/403 lines: $R1 -> $(refusals 1))" || bad "no refusal in edge-1's log: $(tail -2 /tmp/edge1.log | cut -c1-120)"
[ "$(get legit $SHOP $EDGE)" = "200" ] && ok "fail-static: edge-1 serves TLS while refused by the brain" || bad "edge-1 refused by the brain does not serve TLS: $(get legit $SHOP $EDGE)"
sleep 1 # the ceiling is 2 rps: give the h3 request its own second
h=$(h3get legit $SHOP $EDGE); [ "$h" = "200 3" ] && ok "…and h3" || bad "edge-1 refused by the brain does not serve h3: '$h'"
r=$(burst_refused attacker $SHOP $EDGE 30); [ "${r%%/*}" -ge 1 ] && ok "…and still decides: $r — the node's own 429 (fail-static is serve AND decide)" || bad "no refusal from a refused node under a burst ($r): the node fell open"
SHOP_RPS=1000; zones_yaml
brain_yaml "$AG_T1
$AG_T2" "$NODES_PLAIN" on; reload_brain
stop_edge 1; start_edge 1 t1
wait_eq 15 true node_f edge-1 "n['alive']" && ok "edge-1 restarted on t1 is alive again" || bad "edge-1 alive after t1: $(node_f edge-1 "n['alive']")"
sleep 2
[ "$(sfield 1 generation)" = "$G1_0" ] && [ "$(installs 1)" = "$I1_0" ] && ok "…with the same generation and no install (the document never changed; a 304 is asserted through its consequence — the node logs nothing on 304)" || bad "edge-1 after rebinding: gen $(sfield 1 generation), installs $(installs 1)"
[ "$(inv_f "d.get('unbound_agent_tokens')")" = "None" ] && ok "inventory: no unbound agent tokens left" || bad "unbound_agent_tokens: $(inv_f "d['unbound_agent_tokens']")"
rc=$(check_config); [ "$rc" = "0" ] && ! grep -q 'WARNING.*agent token' /tmp/check.out && ok "-check-config: OK, the unbound-token WARNING is gone" || bad "-check-config after binding: rc=$rc $(grep -i 'warning' /tmp/check.out | head -1)"

# ================================================================ ARM A
say "ARM A — binding refuses another node's name on every route of both channels, saving nothing"
# edge-2's poll is parked (a hold of up to 25 s): its last_seen — the START
# of that poll — must not move for another token's forgeries in its name.
LS2=$(node_f edge-2 "n['last_seen']"); REF0=$(brain_metric 'kapkan_api_node_binding_refused_total')
[ "$(code t1 GET "$B/edge/zones?node=edge-2")" = "403" ] && ok "t1 polling as edge-2: 403" || bad "t1 as edge-2: $(code t1 GET "$B/edge/zones?node=edge-2")"
[ "$(code t1 GET "$B/edge/zones")" = "403" ] && ok "t1 without a node name: 403 (a bound token must identify as its node)" || bad "t1 bare GET: $(code t1 GET "$B/edge/zones")"
[ "$(code t1 POST "$B/edge/nodes/edge-2/report" '{"version":"rig","zones":[]}')" = "403" ] && ok "t1 reporting as edge-2: 403" || bad "report as edge-2: $(code t1 POST "$B/edge/nodes/edge-2/report" '{"version":"rig"}')"
[ "$(code t1 POST "$B/edge/nodes/edge-2/acme/slot" "{\"zone\":\"$SHOP\"}")" = "403" ] && ok "t1 asking edge-2's issuance slot: 403" || bad "slot as edge-2: $(code t1 POST "$B/edge/nodes/edge-2/acme/slot" "{\"zone\":\"$SHOP\"}")"
[ "$(code t1 POST "$B/edge/nodes/edge-2/acme/challenges" "{\"zone\":\"$SHOP\",\"token\":\"rig\",\"key_authorization\":\"rig.rig\"}")" = "403" ] && ok "t1 publishing a challenge as edge-2: 403" || bad "publish as edge-2: $(code t1 POST "$B/edge/nodes/edge-2/acme/challenges" "{\"zone\":\"$SHOP\",\"token\":\"rig\",\"key_authorization\":\"rig.rig\"}")"
# The scrub channel's two node-identified routes refuse the same way — the
# binding is checked before any node lookup, so no scrub node has to exist.
[ "$(code t1 GET "$B/dataplane/rules?node=edge-2")" = "403" ] && ok "t1 polling the scrub rules as edge-2: 403" || bad "scrub rules as edge-2: $(code t1 GET "$B/dataplane/rules?node=edge-2")"
[ "$(code t1 POST "$B/dataplane/nodes/edge-2/report" '{"version":"rig"}')" = "403" ] && ok "t1 reporting on the scrub channel as edge-2: 403" || bad "scrub report as edge-2: $(code t1 POST "$B/dataplane/nodes/edge-2/report" '{"version":"rig"}')"
[ "$(node_f edge-2 "n['last_seen']")" = "$LS2" ] && [ "$(node_f edge-2 "n['alive']")" = "true" ] && [ "$(node_f edge-2 "n['tokens']")" = "['t2']" ] && ok "edge-2's last_seen did not move ($LS2), it stays alive on its own token, t1 never enters its token list" || bad "edge-2 after the forgeries: last_seen $LS2 -> $(node_f edge-2 "n['last_seen']"), alive $(node_f edge-2 "n['alive']"), tokens $(node_f edge-2 "n['tokens']")"
[ "$(node_f edge-2 "n['report']['version']")" != "rig" ] && ok "the forged report was not stored for edge-2 (report.version $(node_f edge-2 "n['report']['version']"))" || bad "a forged report was stored for edge-2"
grep -q '"token":"rig"\|rig.rig' <<< "$(doc op edge-1)$(doc op edge-2)" && bad "the forged challenge was published into a document" || ok "the forged challenge reached no document"
REF=$(brain_metric 'kapkan_api_node_binding_refused_total'); [ "$(python3 -c "print(int($REF - $REF0) >= 7)")" = "True" ] && ok "kapkan_api_node_binding_refused_total grew by $(python3 -c "print(int($REF - $REF0))") (seven refusals)" || bad "binding refusals metric: $REF0 -> $REF"
[ "$(node_f edge-1 "n['alive']")" = "true" ] && [ "$(sfield 1 converged)" = "true" ] && ok "edge-1 stays alive and converged through it" || bad "edge-1 after the refusals: alive $(node_f edge-1 "n['alive']")"

# ================================================================ ARM C
say "ARM C — the operator previews a stopped node's document without presence (D5)"
stop_edge 1
wait_eq 20 false node_f edge-1 "n['alive']" || bad "edge-1 not marked lost after stop"
LS1=$(node_f edge-1 "n['last_seen']")
[ "$(code op GET "$B/edge/zones?node=edge-1")" = "200" ] && [ "$(doc op edge-1 | jx "len(d.get('zones',[]))")" = "4" ] && ok "op ?node=edge-1: 200 with edge-1's document while the node is down" || bad "operator preview: $(code op GET "$B/edge/zones?node=edge-1")"
[ -n "$LS1" ] && [ "$(node_f edge-1 "n['last_seen']")" = "$LS1" ] && [ "$(node_f edge-1 "n['alive']")" = "false" ] && ok "the preview left presence untouched (last_seen still, alive false)" || bad "the preview stamped presence"
start_edge 1 t1; wait_eq 20 true node_f edge-1 "n['alive']" || bad "edge-1 did not come back"

# ================================================================ ARM T1
say "ARM T1 — tenancy is not an event for a node"
ET1=$(etag t1 edge-1); ET2=$(etag t2 edge-2); G1=$(sfield 1 generation); G2=$(sfield 2 generation); I1=$(installs 1); I2=$(installs 2)
W1=$(pgrep -f 'nginx: worker' | sort | tr '\n' ' '); E1=$(wc -l < /tmp/edge1-nginx-error.log)
SHOP_TENANT=acme; API_TENANT=acme; STATIC_TENANT=globex; zones_yaml
HUMANS_NOW="$HUMANS
$GLOBEX_OP"
brain_yaml "$AG_T1
$AG_T2" "$NODES_PLAIN" on; reload_brain; sleep 2
[ "$(etag t1 edge-1)" = "$ET1" ] && [ "$(etag t2 edge-2)" = "$ET2" ] && ok "three labels added: the agents' ETags are unchanged" || bad "labels moved an ETag: $ET1 -> $(etag t1 edge-1), $ET2 -> $(etag t2 edge-2)"
[ "$(sfield 1 generation)" = "$G1" ] && [ "$(sfield 2 generation)" = "$G2" ] && [ "$(installs 1)" = "$I1" ] && [ "$(installs 2)" = "$I2" ] && ok "no generation, no install on either node" || bad "labels installed something"
[ "$(pgrep -f 'nginx: worker' | sort | tr '\n' ' ')" = "$W1" ] && ok "nginx worker pids unchanged (no reload)" || bad "nginx workers changed"
[ "$(wc -l < /tmp/edge1-nginx-error.log)" = "$E1" ] && ok "nginx's error log is quiet" || bad "nginx error log grew"
[ "$(zst op $SHOP "z['tenant']")" = "acme" ] && ok "status for op shows tenant acme on $SHOP" || bad "tenant on $SHOP: $(zst op $SHOP "z['tenant']")"

# ================================================================ ARM T2
say "ARM T2 — default-deny: a tenant sees exactly its zones, no foreign hostname, no tenant field"
[ "$(zlist acme-view)" = "$API $SHOP" ] && ok "acme-view sees exactly $API + $SHOP" || bad "acme-view sees: $(zlist acme-view)"
[ "$(zst acme-view $API "z['mode']")" = "none" ] && [ "$(zst acme-view $API "z['nodes']")" = "0" ] && ok "$API row: mode none, nodes 0 (a file-seeded row)" || bad "$API row: $(zst acme-view $API "z")"
[ "$(api acme-view "$B/edge/zones/status" | grep -c "$STATIC\|$HOUSE\|$US\|\"tenant\"")" = "0" ] && ok "no foreign hostname and no tenant field in the tenant's body" || bad "the tenant's body leaks: $(api acme-view "$B/edge/zones/status" | grep -oE "$STATIC|$HOUSE|$US|\"tenant\"" | sort -u | tr '\n' ' ')"
[ "$(zlist globex-op)" = "$STATIC" ] && ok "globex-op (a tenant that exists only through a zone) sees exactly $STATIC" || bad "globex-op sees: $(zlist globex-op)"
[ "$(zlist op)" = "$API $HOUSE $SHOP $STATIC $US" ] && ok "op sees all five" || bad "op sees: $(zlist op)"
NA=$(api op "$B/edge/zones/status" | jx "d['nodes_alive']")
[ -n "$NA" ] && [ "$NA" = "$(api acme-view "$B/edge/zones/status" | jx "d['nodes_alive']")" ] && ok "the fleet counts are the same for everyone (nodes_alive $NA)" || bad "fleet counts differ by tenant: op '$NA', acme-view '$(api acme-view "$B/edge/zones/status" | jx "d['nodes_alive']")'"
[ "$(code acme-op GET "$B/edge/nodes")" = "403" ] && [ "$(code acme-op GET "$B/edge/zones")" = "403" ] && ok "a scoped token gets 403 on the inventory and the document (topology is not the tenant's)" || bad "scoped topology reads: nodes $(code acme-op GET "$B/edge/nodes"), zones $(code acme-op GET "$B/edge/zones")"

# ================================================================ ARM T3
say "ARM T3 — the tenant's lever: the same policy in the same document, no reload, audited under the tenant"
G1=$(sfield 1 generation); ET1=$(sfield 1 accepted_etag); A0=$(audit_n op)
[ "$(lever acme-op POST $SHOP '{"mode":"manual","ttl_seconds":600,"reason":"rig"}')" = "200" ] && ok "acme-op pulls the lever on $SHOP: 200" || bad "tenant lever: $(lever acme-op POST $SHOP '{"mode":"manual","ttl_seconds":600,"reason":"rig"}')"
wait_ne 10 "$ET1" node_etag 1 || bad "edge-1 never saw the lever"
sleep 0.5
b=$(body legit $SHOP $EDGE); is_page "$b" && ok "a plain client gets the clearance page over TCP (the page, not the solve: E4's rig proves the puzzle)" || bad "no page over TCP: $(cut -c1-100 <<< "$b")"
b=$(body legit $SHOP $EDGE --http3-only); is_page "$b" && ok "…and over HTTP/3" || bad "no page over h3: $(cut -c1-100 <<< "$b")"
[ "$(sfield 1 generation)" = "$G1" ] && ok "the lever moved no generation ($G1): the fast path" || bad "the lever reloaded (gen $G1 -> $(sfield 1 generation))"
[ "$(zst acme-view $SHOP "z['override']['mode']")" = "manual" ] && ok "acme-view sees the override on its zone" || bad "override for acme-view: $(zst acme-view $SHOP "z['override']")"
ET1=$(sfield 1 accepted_etag)
[ "$(lever acme-op DELETE $SHOP)" = "200" ] && ok "acme-op clears the lever: 200" || bad "DELETE lever: $(lever acme-op DELETE $SHOP)"
wait_ne 10 "$ET1" node_etag 1 || bad "edge-1 never saw the lever cleared"
sleep 0.5
[ "$(get legit $SHOP $EDGE)" = "200" ] && ok "the page is gone" || bad "after DELETE: $(get legit $SHOP $EDGE)"
grep -E 'operator=acme-op .*tenant=acme|tenant=acme .*operator=acme-op' /tmp/brain.log | grep -q 'edge_challenge\|override' && ok "the brain's log names operator=acme-op tenant=acme on the lever" || bad "no tenant-attributed lever line in the brain log: $(grep 'edge_challenge' /tmp/brain.log | tail -1 | cut -c1-160)"
wait_eq 20 true audit_ge op $((A0+2)) || bad "the two audit rows did not land within 20 s"
n_op=$(audit_n op); n_acme=$(audit_n acme-op); n_globex=$(audit_n globex-op)
grep -q '"events":\[\]' <<< "$(api globex-op "$B/audit?action=edge_challenge")" && ok "a tenant with no audit rows gets an empty array, not null" || bad "globex-op's empty audit: $(api globex-op "$B/audit?action=edge_challenge" | cut -c1-120)"
[ "${n_op:-0}" -ge $((A0+2)) ] 2>/dev/null && [ "$n_acme" = "$n_op" ] && [ "$n_globex" = "0" ] && ok "audit: edge_challenge rows for set and clear ($n_op); acme-op sees its own ($n_acme), globex-op none" || bad "audit rows: op $n_op, acme-op $n_acme, globex-op $n_globex (op: $(api op "$B/audit?action=edge_challenge" | cut -c1-160); globex: $(api globex-op "$B/audit?action=edge_challenge" | cut -c1-160))"

# ================================================================ ARM T4
say "ARM T4 — no existence oracle on the lever"
cbody acme-op POST "$B/edge/zones/$STATIC/challenge" '{"mode":"manual","ttl_seconds":60}' > /tmp/t4-a.txt; ca=$(lever acme-op POST $STATIC '{"mode":"manual","ttl_seconds":60}')
cbody acme-op POST "$B/edge/zones/nonexistent.test/challenge" '{"mode":"manual","ttl_seconds":60}' > /tmp/t4-b.txt; cb=$(lever acme-op POST nonexistent.test '{"mode":"manual","ttl_seconds":60}')
[ "$ca" = "404" ] && [ "$cb" = "404" ] && [ -s /tmp/t4-a.txt ] && cmp -s /tmp/t4-a.txt /tmp/t4-b.txt && ok "another tenant's zone and a nonexistent zone: 404, byte-identical bodies" || bad "oracle: $ca vs $cb, bodies $(cat /tmp/t4-a.txt) / $(cat /tmp/t4-b.txt)"
[ "$(lever acme-view POST $SHOP '{"mode":"manual","ttl_seconds":60}')" = "403" ] && ok "acme-view (viewer) may not pull the lever: 403" || bad "viewer lever: $(lever acme-view POST $SHOP '{"mode":"manual","ttl_seconds":60}')"
[ "$(get legit $STATIC $EDGE)" = "200" ] && ok "$STATIC untouched by the refused lever" || bad "$STATIC after the refused lever: $(get legit $STATIC $EDGE)"

# ================================================================ ARM T5
say "ARM T5 — a relabel follows the file; a tenant mismatch and a zone removed under a live token are refused"
# A tenant exists through its hostgroups AND its zones (E6.2), so relabelling
# shop.test to a name nobody else uses is a valid file: the label moves, the
# document does not, and acme's token loses the zone — the file is the truth.
# (The plan's row read "a wrong tenant is refused"; E6.2's rule makes it the
# reverse, and the fail-closed cases are the two below.)
ET1=$(etag t1 edge-1)
SHOP_TENANT=acmee; zones_yaml; reload_brain
[ "$(zst op $SHOP "z['tenant']")" = "acmee" ] && ok "shop.test relabelled acmee: accepted (a tenant is made by its zones)" || bad "tenant after the relabel: $(zst op $SHOP "z['tenant']")"
[ "$(zlist acme-view)" = "$API" ] && ok "acme-view no longer sees $SHOP (the file is the truth)" || bad "acme-view after the relabel: $(zlist acme-view)"
[ "$(get legit $SHOP $EDGE)" = "200" ] && [ "$(etag t1 edge-1)" = "$ET1" ] && ok "$SHOP served on the same document, ETag unchanged (a label is not an event for a node)" || bad "after the relabel: $(get legit $SHOP $EDGE), etag $(etag t1 edge-1)"
rc=$(check_config); [ "$rc" = "0" ] && ok "-check-config: OK on the relabel" || bad "-check-config on the relabel: rc=$rc $(head -2 /tmp/check.out)"
SHOP_TENANT=acme; zones_yaml; reload_brain
[ "$(zlist acme-view)" = "$API $SHOP" ] && ok "relabelled back: acme-view sees $SHOP again" || bad "acme-view after the restore: $(zlist acme-view)"
# D9: a zone owned by one tenant placed on another tenant's group — static.test
# (globex) on the acme hostgroup — is a mistake the reload refuses.
STATIC_HG=acme; zones_yaml
rc=$(check_config); [ "$rc" != "0" ] && grep -q 'globex' /tmp/check.out && grep -q '"acme"' /tmp/check.out && ok "-check-config: INVALID — $STATIC's tenant globex differs from hostgroup acme's tenant" || bad "-check-config on the mismatch: rc=$rc $(head -3 /tmp/check.out)"
F1=$(reload_failures); reload_brain
[ "$(reload_failures)" = "$((F1+1))" ] && grep 'config reload failed' /tmp/brain.log | tail -1 | grep -q "$STATIC" && ok "the reload was refused, naming $STATIC" || bad "mismatch reload: failures $F1 -> $(reload_failures): $(grep 'config reload failed' /tmp/brain.log | tail -1 | cut -c1-160)"
[ "$(get legit $STATIC $EDGE)" = "200" ] && [ "$(etag t1 edge-1)" = "$ET1" ] && [ "$(zst op $STATIC "z['placement']['hostgroup']")" = "global" ] && ok "$STATIC still served on the previous file (global, ETag unchanged)" || bad "after the refused mismatch: $(get legit $STATIC $EDGE), etag $(etag t1 edge-1), placement $(zst op $STATIC "z['placement']")"
STATIC_HG=""; zones_yaml
# The only zone carrying globex removed while globex-op exists: refused, naming the token.
python3 - <<'PY'
import re
s=open('/tmp/zones.yaml').read()
s=re.sub(r"  - name: static\.test\n(    .*\n)+?(?=  - name: )", "", s)
open('/tmp/zones-nostatic.yaml','w').write(s)
PY
cp /tmp/zones.yaml /tmp/zones-full.yaml; cp /tmp/zones-nostatic.yaml /tmp/zones.yaml
F1=$(reload_failures); reload_brain
[ "$(reload_failures)" = "$((F1+1))" ] && grep 'config reload failed' /tmp/brain.log | tail -1 | grep -q 'globex' && ok "removing the only globex zone under a live globex-op token is refused, naming the tenant" || bad "removal reload: failures $F1 -> $(reload_failures): $(grep 'config reload failed' /tmp/brain.log | tail -1 | cut -c1-160)"
[ "$(zlist globex-op)" = "$STATIC" ] && ok "globex-op still sees $STATIC (nothing changed)" || bad "globex-op after the refused removal: $(zlist globex-op)"
rc=$(check_config); [ "$rc" != "0" ] && ok "-check-config repeats the refusal (INVALID)" || bad "-check-config accepted the removal"
cp /tmp/zones-full.yaml /tmp/zones.yaml; reload_brain
rc=$(check_config); [ "$rc" = "0" ] && [ "$(etag t1 edge-1)" = "$ET1" ] && ok "restored: -check-config OK, ETag still $ET1" || bad "restore: rc=$rc etag $(etag t1 edge-1)"

# ================================================================ ARM T6
say "ARM T6 — a tenant reads its certificates' expiry without the inventory"
[ "$(zst acme-view $SHOP "len(z['certs'])")" = "2" ] && ok "acme-view: $SHOP carries two certs (one per node)" || bad "certs for acme-view on $SHOP: $(zst acme-view $SHOP "z['certs']")"
[ "$(zst acme-view $SHOP "all('not_after' in c for c in z['certs'])")" = "true" ] && ok "each cert carries not_after ($(zst acme-view $SHOP "z['certs'][0]['not_after']"))" || bad "certs without not_after"
[ "$(api acme-view "$B/edge/zones/status" | jx "sorted(set(z['zone'] for z in d['zones'] if z.get('certs')))")" = "['$API', '$SHOP']" ] && ok "…and only for its own zones ($API, a mode: none zone, has its certificate too)" || bad "certs visible to acme-view: $(api acme-view "$B/edge/zones/status" | jx "sorted(set(z['zone'] for z in d['zones'] if z.get('certs')))")"

# ================================================================ ARM S1 / S2
say "ARM S1/S2 — rows land once; an idle deciding zone writes no decided window"
S1_T0=$(date -u +'%Y-%m-%d %H:%M:%S'); H0=$(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='$HOUSE'")
for i in $(seq 1 30); do get legit $SHOP $EDGE >/dev/null; sleep 0.3; done
wait_sql 30 1 "SELECT count() >= 1 FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND ts >= toDateTime('$S1_T0')" && ok "edge_windows gained rows for ($SHOP, edge-1) within 30 s of traffic ($(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1'") in all)" || bad "no new edge_windows rows for $SHOP/edge-1: $(chq "SELECT count() FROM kapkan.edge_windows")"
[ "$(chq "SELECT count() = uniqExact(node, zone, ts) FROM kapkan.edge_windows")" = "1" ] && ok "count() == uniqExact(node, zone, ts): no duplicate windows" || bad "duplicate windows: $(chq "SELECT count(), uniqExact(node, zone, ts) FROM kapkan.edge_windows")"
wait_sql 40 1 "SELECT sum(requests) >= 30 FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND ts >= toDateTime('$S1_T0')" && ok "the windows' requests sum covers the 30 requests sent ($(chq "SELECT sum(requests) FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND ts >= toDateTime('$S1_T0')"))" || bad "requests summed after 40 s: $(chq "SELECT sum(requests) FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND ts >= toDateTime('$S1_T0')")"
[ "$(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='$API'")" = "0" ] && ok "$API (mode none) has no rows" || bad "$API rows: $(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='$API'")"
# The CA's HTTP-01 probes on :80 are requests the node counts for the zone
# (three per validation, 2xx, decided 0) — on edge-1 for BOTH nodes'
# issuances, since the zone's hosts entry points there. A quiet deciding zone
# has no decided window, no empty window, and its row count does not move
# while its neighbour takes traffic.
H1=$(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='$HOUSE'")
[ "$H1" = "$H0" ] && [ "$(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='$HOUSE' AND (decided > 0 OR requests = 0)")" = "0" ] && [ "$(chq "SELECT sum(status_2xx) = sum(requests) FROM kapkan.edge_windows WHERE zone='$HOUSE'")" = "1" ] && ok "$HOUSE (deciding, idle) wrote nothing across $SHOP's traffic ($H0 rows before and after), has no decided and no empty window: its only rows are the CA's own HTTP-01 probes ($(chq "SELECT sum(requests) FROM kapkan.edge_windows WHERE zone='$HOUSE'") requests, all 2xx, decided 0)" || bad "$HOUSE rows $H0 -> $H1; decided/empty: $(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='$HOUSE' AND (decided > 0 OR requests = 0)"); $(chq "SELECT ts, node, requests, decided, status_2xx FROM kapkan.edge_windows WHERE zone='$HOUSE' ORDER BY ts DESC LIMIT 3" | tr '\n\t' ' ,')"
chq "SELECT table, sum(rows), sum(data_compressed_bytes), round(sum(data_compressed_bytes)/greatest(sum(rows),1),1) FROM system.parts WHERE database='kapkan' AND table LIKE 'edge_%' AND active GROUP BY table ORDER BY table" > /tmp/bytes-per-row.tsv
echo "  (system.parts so far — table, rows, compressed bytes, bytes/row:)"; sed 's/^/    /' /tmp/bytes-per-row.tsv

# ================================================================ ARM S3
say "ARM S3 — would-be over a period; only the telling sources"
SHOP_RPS=2; SHOP_DRY=true; zones_yaml; ET1=$(sfield 1 accepted_etag); reload_brain
wait_ne 10 "$ET1" node_etag 1 || bad "the dry-run rate never reached edge-1"
sleep 0.5; : > /tmp/origin.log; S3_T0=$(date -u +'%Y-%m-%d %H:%M:%S')
for i in $(seq 1 40); do get attacker $SHOP $EDGE >/dev/null; done
for i in 1 2; do get legit $SHOP $EDGE >/dev/null; sleep 1.5; done
grep -q '"mark": "would-deny:rate"' /tmp/origin.log && ok "the watch-only zone marked would-deny:rate at the origin" || bad "no would-deny mark: $(tail -1 /tmp/origin.log)"
wait_sql 30 1 "SELECT count() >= 1 FROM kapkan.edge_sources WHERE zone='$SHOP' AND source='198.51.100.3' AND state='would-deny' AND ts >= toDateTime('$S3_T0')" && ok "edge_sources has would-deny rows for the attacker" || bad "no would-deny rows for the attacker: $(chq "SELECT source, state, count() FROM kapkan.edge_sources GROUP BY source, state")"
[ "$(chq "SELECT count() FROM kapkan.edge_sources WHERE state IN ('allow','cleared','marked')")" = "0" ] && ok "no allow/cleared/marked rows: visitors are never written" || bad "visitor rows: $(chq "SELECT state, count() FROM kapkan.edge_sources GROUP BY state")"
[ "$(chq "SELECT count() FROM kapkan.edge_sources WHERE source='203.0.113.2' AND ts >= toDateTime('$S3_T0')")" = "0" ] && ok "the legitimate client is absent from edge_sources for the period (its only row is T3's, when the lever challenged it; the report's allow entry for it is the node's — the write path's telling-only rule is unit-tested)" || bad "legit client rows since $S3_T0: $(chq "SELECT ts, state, requests FROM kapkan.edge_sources WHERE source='203.0.113.2' AND ts >= toDateTime('$S3_T0')" | tr '\n\t' ' ,')"
[ "$(api op "$B/edge/history/sources?zone=$SHOP" | jx "d['sources'][0]['source']")" = "198.51.100.3" ] && ok "/edge/history/sources puts the attacker first ($(api op "$B/edge/history/sources?zone=$SHOP" | jx "d['sources'][0]['state']"), $(api op "$B/edge/history/sources?zone=$SHOP" | jx "d['sources'][0]['requests']") requests)" || bad "sources read: $(api op "$B/edge/history/sources?zone=$SHOP" | cut -c1-200)"
SHOP_RPS=1000; SHOP_DRY=false; zones_yaml; reload_brain; sleep 1.5

# ================================================================ ARM S4
say "ARM S4 — the read API equals SQL; scope is default-deny"
from=$(date -u -d '-10 min' +%Y-%m-%dT%H:%M:%SZ); to=$(date -u -d '+1 min' +%Y-%m-%dT%H:%M:%SZ)
FROM_SQL=$(date -u -d '-10 min' +'%Y-%m-%d %H:%M:%S'); TO_SQL=$(date -u -d '+1 min' +'%Y-%m-%d %H:%M:%S')
BOUND="ts >= toDateTime('$FROM_SQL') AND ts < toDateTime('$TO_SQL')"
sum_api=$(hist op "zone=$SHOP&from=$from&to=$to&step=60" | jx "sum(p['requests'] for p in d['points'])")
sum_sql=$(chq "SELECT sum(requests) FROM kapkan.edge_windows WHERE zone='$SHOP' AND $BOUND")
[ -n "$sum_api" ] && [ "$sum_api" = "$sum_sql" ] && ok "history at step 60 sums to the SQL total over the same bounds ($sum_api)" || bad "history $sum_api vs SQL $sum_sql"
sum10=$(hist op "zone=$SHOP&from=$from&to=$to&step=10" | jx "sum(p['requests'] for p in d['points'])")
[ -n "$sum10" ] && [ "$sum10" = "$sum_sql" ] && ok "…and at step 10" || bad "step 10: $sum10"
n_api=$(hist op "zone=$SHOP&node=edge-1&from=$from&to=$to" | jx "d['available'] and d['node']=='edge-1' and sum(p['requests'] for p in d['points'])")
[ -n "$n_api" ] && [ "$n_api" = "$(chq "SELECT sum(requests) FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND $BOUND")" ] && ok "node=edge-1 works for op and equals its SQL sum ($n_api)" || bad "node filter: $(hist op "zone=$SHOP&node=edge-1&from=$from&to=$to" | cut -c1-160)"
[ "$(hist acme-view "zone=$SHOP" | jx "d['available'] and d['zone']")" = "$SHOP" ] && ok "acme-view reads its own zone's history (available:true)" || bad "acme-view history: $(hist acme-view "zone=$SHOP" | cut -c1-120)"
[ "$(code acme-view GET "$B/edge/history?zone=$STATIC")" = "403" ] && [ "$(code acme-view GET "$B/edge/history?zone=nope.test")" = "403" ] && ok "acme-view on another tenant's zone and on a nonexistent one: 403 both" || bad "scoped foreign zone: $(code acme-view GET "$B/edge/history?zone=$STATIC") / $(code acme-view GET "$B/edge/history?zone=nope.test")"
[ "$(code acme-view GET "$B/edge/history?zone=$SHOP&node=edge-1")" = "403" ] && [ "$(code acme-view GET "$B/edge/events")" = "403" ] && ok "node= and /edge/events are 403 for a tenant" || bad "scoped node/events: $(code acme-view GET "$B/edge/history?zone=$SHOP&node=edge-1") / $(code acme-view GET "$B/edge/events")"
[ "$(code t1 GET "$B/edge/history?zone=$SHOP")" = "403" ] && ok "the agent gets 403 on the history" || bad "agent history: $(code t1 GET "$B/edge/history?zone=$SHOP")"

# ================================================================ ARM S5
say "ARM S5 — the node's chronology as events"
NL0=$(ev_count node_lost edge-2); NA0=$(ev_count node_alive edge-2)
stop_edge 2
wait_eq 20 true ev_more node_lost "$NL0" edge-2 && ok "node_lost written for edge-2 within stale_after" || bad "no node_lost event: $(events op 'kind=node_lost' | cut -c1-200)"
# The inventory's last_seen is frozen once the node is lost; the row must be
# stamped exactly there plus stale_after — and the brain's own INFO line
# names the same instant.
LS2=$(node_f edge-2 "n['last_seen']"); EV=$(ev_newest node_lost edge-2 event_time)
LOST_AT=$(grep 'edge node lost' /tmp/brain.log | tail -1 | grep -oE 'lost_at=[^ ]+' | cut -d= -f2)
python3 - "$LS2" "$EV" "$STALE" "$LOST_AT" <<'PY' && ok "node_lost is stamped last_seen + stale_after exactly ($EV = $LS2 + ${STALE}s), the instant the brain's log names (lost_at=$LOST_AT)" || bad "node_lost stamp: event $EV, inventory last_seen $LS2, log lost_at=$LOST_AT"
import sys, datetime
ls = datetime.datetime.fromisoformat(sys.argv[1].replace('Z', '+00:00')).replace(microsecond=0)
ev = datetime.datetime.strptime(sys.argv[2], '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
lost = datetime.datetime.fromisoformat(sys.argv[4].replace('Z', '+00:00')).replace(microsecond=0)
want = ls + datetime.timedelta(seconds=int(sys.argv[3]))
raise SystemExit(0 if ev == want and abs((ev - lost).total_seconds()) <= 1 else 1)
PY
grep -q 'edge node lost' /tmp/brain.log && ok "…and the INFO line reached the brain's log" || bad "no 'edge node lost' in the brain log"
start_edge 2 t2
wait_eq 20 true ev_more node_alive "$NA0" edge-2 && ok "node_alive written when edge-2 returned" || bad "no node_alive event"
N_R=$(ev_count document_rendered); N_I=$(ev_count generation_installed)
G1=$(sfield 1 generation); SHOP_ORIGIN_PORT=8082; zones_yaml; reload_brain
wait_gen 1 $((G1+1)) 30 || bad "the origin change did not install on edge-1 (gen $(sfield 1 generation))"
wait_eq 20 true ev_more generation_installed "$N_I" && ok "an origin change wrote generation_installed ($(ev_count generation_installed) now)" || bad "no generation_installed after the origin change"
[ "$(ev_more document_rendered "$N_R")" = "true" ] && ok "…and document_rendered" || bad "no document_rendered after the origin change"
grep -q '"port": 8082' <<< "$(body legit $SHOP $EDGE)" && ok "the request now reaches the second origin" || bad "origin change did not take"
echo 'this is not nginx;' > /tmp/bad-extra.conf; G1=$(sfield 1 generation); N_F=$(ev_count generation_refused)
SHOP_EXTRA=/tmp/bad-extra.conf; zones_yaml; reload_brain
wait_eq 30 true ev_more generation_refused "$N_F" && ok "a broken extra_directives_file wrote generation_refused ($(ev_newest generation_refused edge-1 detail | cut -c1-60))" || bad "no generation_refused event"
[ "$(sfield 1 generation)" = "$G1" ] && [ "$(get legit $SHOP $EDGE)" = "200" ] && ok "the previous generation keeps serving ($G1)" || bad "after the refused generation: gen $(sfield 1 generation), $(get legit $SHOP $EDGE)"
# The restored file is the document that is already live: nothing to
# install, the node converges on its current generation.
SHOP_EXTRA=""; zones_yaml; reload_brain
wait_eq 30 true sfield 1 converged && [ "$(sfield 1 generation)" = "$G1" ] && [ "$(get legit $SHOP $EDGE)" = "200" ] && ok "the restored file converged on the live generation ($G1): the refused render left nothing behind" || bad "after the restore: gen $(sfield 1 generation), converged $(sfield 1 converged), $(get legit $SHOP $EDGE)"
settle 2
[ "$(ev_count cert_issued)" -ge 1 ] 2>/dev/null && ok "cert_issued events exist from Pebble's issuance ($(ev_count cert_issued))" || bad "no cert_issued events"

# ================================================================ ARM D
say "ARM D — placement: one document per node, rendered only where placed"
settle 1; settle 2; G1=$(sfield 1 generation); G2=$(sfield 2 generation); I1=$(installs 1); I2=$(installs 2)
brain_yaml "$AG_T1
$AG_T2" "$NODES_SCOPED" on; reload_brain
wait_ne 40 "$G2" sfield 2 generation && ok "edge-2 (scope [edge-us, global]) installed a new generation for $US ($G2 -> $(sfield 2 generation))" || bad "edge-2 after the scopes: gen $(sfield 2 generation)"
[ -f $STATE2/conf/live/kapkan_zone_$US.conf ] && ok "edge-2 renders kapkan_zone_$US.conf" || bad "no $US render on edge-2"
# Pebble issues us.test on edge-2 for the first time (its hosts entry points
# there): the certificate is a second install — placing a zone is a render
# generation plus a certificate install.
for i in $(seq 1 600); do [ "$(get legit $US $EDGE2)" = "200" ] && break; sleep 0.2; done
[ "$(get legit $US $EDGE2)" = "200" ] && ok "$US is served by edge-2 (Pebble issued it there)" || bad "$US on edge-2 after 120 s: $(get legit $US $EDGE2)"
settle 2
[ "$(installs 2)" = "$((I2+2))" ] && ok "edge-2 installed exactly twice: the render with $US and its certificate ($I2 -> $(installs 2))" || bad "edge-2 installs: $I2 -> $(installs 2), want +2 (render + certificate)"
[ "$(sfield 1 generation)" = "$G1" ] && [ "$(installs 1)" = "$I1" ] && ok "edge-1 (scope [edge-eu, global]) installed nothing: its document did not change" || bad "edge-1 after the scopes: gen $G1 -> $(sfield 1 generation), installs $I1 -> $(installs 1)"
[ ! -f $STATE1/conf/live/kapkan_zone_$US.conf ] && ok "edge-1 never renders $US" || bad "$US rendered on edge-1"
[ "$(get legit $US $EDGE)" != "200" ] && ok "$US via edge-1 is refused ('$(get legit $US $EDGE)': no server, no certificate for the name)" || bad "$US served by edge-1"
doc op edge-1 > /tmp/doc-e1.json; doc op edge-2 > /tmp/doc-e2.json
! cmp -s /tmp/doc-e1.json /tmp/doc-e2.json && [ "$(etag op edge-1)" != "$(etag op edge-2)" ] && ok "the two documents differ, and so do their ETags" || bad "documents identical under placement"
[ "$(jx "sorted(z['name'] for z in d['zones'])" < /tmp/doc-e1.json)" = "['$API', '$HOUSE', '$SHOP', '$STATIC']" ] && [ "$(jx "sorted(z['name'] for z in d['zones'])" < /tmp/doc-e2.json)" = "['$API', '$HOUSE', '$SHOP', '$STATIC', '$US']" ] && ok "edge-1's document has the four global zones, edge-2's five" || bad "zones: e1 $(jx "sorted(z['name'] for z in d['zones'])" < /tmp/doc-e1.json), e2 $(jx "sorted(z['name'] for z in d['zones'])" < /tmp/doc-e2.json)"
[ "$(api op "$B/edge/zones" | jx "len(d['zones'])")" = "5" ] && ok "the bare GET (no node) is the whole file: five zones" || bad "bare GET zones: $(api op "$B/edge/zones" | jx "len(d['zones'])")"
grep -q 'hostgroup' /tmp/doc-e2.json && bad "placement leaked into the document" || ok "the placement itself never enters the document"
[ "$(zst op $US "z['placement']")" = "{'hostgroup': 'edge-us', 'nodes': ['edge-2'], 'alive': ['edge-2']}" ] && ok "status: $US placement {edge-us, nodes [edge-2], alive [edge-2]}" || bad "$US placement: $(zst op $US "z['placement']")"
[ "$(node_f edge-2 "n['zones_placed']")" = "5" ] && [ "$(node_f edge-1 "n['zones_placed']")" = "4" ] && [ "$(node_f edge-2 "n['hostgroups']")" = "['edge-us', 'global']" ] && ok "inventory: hostgroups and zones_placed (edge-2: 5, edge-1: 4)" || bad "inventory placement: e1 $(node_f edge-1 "n['zones_placed']") e2 $(node_f edge-2 "n['zones_placed']") $(node_f edge-2 "n['hostgroups']")"

# ================================================================ ARM E
say "ARM E — fan-out only to the serving nodes; a slot outside the scope is 404"
# A fresh issuance of us.test on edge-2 (its certificate removed, the node
# restarted): the challenge is fanned out to the document of every node that
# serves the zone — edge-2 — and never edge-1's. Poll both documents every
# 200 ms until the certificate lands.
N_US=$(grep -c "certificate issued.*$US" /tmp/edge2.log)
stop_edge 2; rm -rf "$STATE2/certs/$US"; start_edge 2 t2
: > /tmp/fanout-e1.txt; : > /tmp/fanout-e2.txt
for i in $(seq 1 600); do
  doc op edge-1 | jx "[c['token'] for c in d.get('acme_challenges',[]) if c.get('zone')=='$US']" >> /tmp/fanout-e1.txt
  doc op edge-2 | jx "[c['token'] for c in d.get('acme_challenges',[]) if c.get('zone')=='$US']" >> /tmp/fanout-e2.txt
  [ "$(grep -c "certificate issued.*$US" /tmp/edge2.log)" -gt "$N_US" ] && break
  sleep 0.2
done
[ "$(grep -c "certificate issued.*$US" /tmp/edge2.log)" -gt "$N_US" ] && ok "Pebble re-issued $US on edge-2" || bad "$US not re-issued on edge-2 in 120 s: $(grep -i "$US" /tmp/edge2.log | tail -2)"
[ "$(grep -cv '^\[\]$' /tmp/fanout-e2.txt)" -ge 1 ] && ok "the challenge appeared in edge-2's document ($(grep -cv '^\[\]$' /tmp/fanout-e2.txt) polls)" || bad "the challenge never showed in edge-2's document (polls: $(wc -l < /tmp/fanout-e2.txt))"
[ "$(wc -l < /tmp/fanout-e1.txt)" -ge 1 ] && [ "$(grep -cv '^\[\]$' /tmp/fanout-e1.txt)" = "0" ] && ok "…and never in edge-1's ($(wc -l < /tmp/fanout-e1.txt) polls)" || bad "a $US challenge reached edge-1's document"
tokn=$(grep -v '^\[\]$' /tmp/fanout-e2.txt | head -1 | tr -d "[]' ")
# A node with no server for the Host closes the connection (nginx return 444
# on the catch-all): the CA's probe of the wrong node gets no answer, never a
# 200 (the plan's row said 404; this is what the render does).
c80=$(ip netns exec legit curl -s -o /dev/null -w '%{http_code}' -m3 -H "Host: $US" "http://$EDGE/.well-known/acme-challenge/$tokn")
[ -n "$tokn" ] && [ "$c80" != "200" ] && ok "edge-1's :80 does not answer $US's token ('$c80': no server for the Host, the connection is closed)" || bad "edge-1 :80 for the token '$tokn': $c80"
cbody t1 POST "$B/edge/nodes/edge-1/acme/slot" "{\"zone\":\"$US\"}" > /tmp/slot-us.txt; c1=$(code t1 POST "$B/edge/nodes/edge-1/acme/slot" "{\"zone\":\"$US\"}")
cbody t1 POST "$B/edge/nodes/edge-1/acme/slot" '{"zone":"nonexistent.test"}' > /tmp/slot-nx.txt; c2=$(code t1 POST "$B/edge/nodes/edge-1/acme/slot" '{"zone":"nonexistent.test"}')
[ "$c1" = "404" ] && [ "$c2" = "404" ] && [ -s /tmp/slot-us.txt ] && cmp -s /tmp/slot-us.txt /tmp/slot-nx.txt && ok "edge-1 asking a slot for $US: 404, byte-identical with a nonexistent zone" || bad "slot outside scope: $c1 / $c2, bodies $(cat /tmp/slot-us.txt) / $(cat /tmp/slot-nx.txt)"
[ ! -d $STATE1/certs/$US ] && [ -d $STATE2/certs/$US ] && ok "edge-1 has no certs/$US; edge-2 has" || bad "certs dirs: e1 $(ls -d $STATE1/certs/$US 2>&1 | head -1), e2 $(ls -d $STATE2/certs/$US 2>&1 | head -1)"
[ "$(get legit $STATIC $EDGE2)" = "200" ] && ok "$STATIC (global) still served by edge-2 too (its setup certificate validated through edge-1's :80 — the fan-out of a global zone)" || bad "$STATIC on edge-2: $(get legit $STATIC $EDGE2)"

# ================================================================ ARM F
say "ARM F — unserved, and the lever by placement"
stop_edge 2
wait_eq 20 true zst op $US "z['unserved']" && ok "$US is unserved with edge-2 down" || bad "$US unserved: $(zst op $US "z['unserved']")"
[ "$(zst op $US "z['placement']['alive']")" = "[]" ] && ok "placement.alive is [] for $US" || bad "placement.alive: $(zst op $US "z['placement']['alive']")"
[ "$(zst op $SHOP "z.get('unserved', False)")" = "false" ] && [ "$(zst op $SHOP "z['placement']['alive']")" = "['edge-1']" ] && ok "$SHOP is untouched (alive [edge-1], not unserved)" || bad "$SHOP: $(zst op $SHOP "z['placement']")"
ET1=$(etag t1 edge-1)
cbody op POST "$B/edge/zones/$US/challenge" '{"mode":"manual","ttl_seconds":120}' > /tmp/lever-us.txt
[ "$(jx "sorted(n['name'] for n in d['nodes'])" < /tmp/lever-us.txt)" = "['edge-2']" ] && [ "$(jx "d['nodes'][0]['alive']" < /tmp/lever-us.txt)" = "false" ] && ok "the lever on $US names only edge-2 (alive false)" || bad "lever on $US: $(cat /tmp/lever-us.txt | cut -c1-200)"
sleep 1.5
[ "$(etag t1 edge-1)" = "$ET1" ] && ok "edge-1's document did not move for a lever on a zone it does not serve" || bad "edge-1's ETag moved on $US's lever"
cbody op POST "$B/edge/zones/$STATIC/challenge" '{"mode":"manual","ttl_seconds":120}' > /tmp/lever-static.txt
[ "$(jx "sorted(n['name'] for n in d['nodes'])" < /tmp/lever-static.txt)" = "['edge-1', 'edge-2']" ] && ok "the lever on $STATIC (global) names both nodes" || bad "lever on $STATIC: $(cut -c1-200 /tmp/lever-static.txt)"
wait_ne 10 "$ET1" etag t1 edge-1 && ok "…and edge-1's document moved for it" || bad "edge-1's ETag did not move for $STATIC's lever"
lever op DELETE $US >/dev/null; lever op DELETE $STATIC >/dev/null
start_edge 2 t2; wait_eq 20 true node_f edge-2 "n['alive']" || bad "edge-2 did not come back"
wait_eq 10 false zst op $US "z.get('unserved', False)" && [ "$(get legit $US $EDGE2)" = "200" ] && ok "edge-2 back: $US served again" || bad "$US still unserved or unserved: $(zst op $US "z.get('unserved', False)") / $(get legit $US $EDGE2)"

# ================================================================ ARM G
say "ARM G — an impossible or broken configuration never goes live"
ET1=$(settle_etag t1 edge-1); ET2=$(settle_etag t2 edge-2); INV=$(api op "$B/edge/nodes" | jx "sorted((n['name'], n['zones_placed'], n['hostgroups']) for n in d['nodes'])")
R0=$(reloads); F0=$(reload_failures)
brain_yaml "$AG_T0
$AG_T1
$AG_T2" "$NODES_SCOPED" on
rc=$(check_config); [ "$rc" != "0" ] && grep -q 'INVALID' /tmp/check.out && grep -q 't0' /tmp/check.out && ok "scopes + an unbound agent token: -check-config INVALID, naming t0" || bad "-check-config: rc=$rc $(head -3 /tmp/check.out)"
reload_brain
[ "$(reloads)" = "$R0" ] && [ "$(reload_failures)" = "$((F0+1))" ] && ok "the brain refused the reload and kept the previous config ($(grep 'config reload failed' /tmp/brain.log | tail -1 | grep -oE 't0[^;]*' | head -1))" || bad "reload lines: reloaded $R0 -> $(reloads), failed $F0 -> $(reload_failures)"
[ "$(get legit $SHOP $EDGE)" = "200" ] && [ "$(get legit $US $EDGE2)" = "200" ] && [ "$(etag t1 edge-1)" = "$ET1" ] && [ "$(etag t2 edge-2)" = "$ET2" ] && ok "both zones served, ETags unchanged" || bad "after the refused reload: etags $ET1 -> $(etag t1 edge-1), $ET2 -> $(etag t2 edge-2)"
[ "$(api op "$B/edge/nodes" | jx "sorted((n['name'], n['zones_placed'], n['hostgroups']) for n in d['nodes'])")" = "$INV" ] && ok "the inventory is unchanged" || bad "inventory changed under a refused reload"
brain_yaml "$AG_T1
$AG_T2" "$NODES_SCOPED" on
US_HG=typo; zones_yaml
rc=$(check_config); [ "$rc" != "0" ] && grep -q 'typo' /tmp/check.out && ok "zones[].hostgroup: typo — -check-config INVALID naming it" || bad "-check-config on the typo: rc=$rc $(head -3 /tmp/check.out)"
F1=$(reload_failures); reload_brain
[ "$(reload_failures)" = "$((F1+1))" ] && grep 'config reload failed' /tmp/brain.log | tail -1 | grep -q 'typo' && ok "the reload with the typo was refused, naming it" || bad "typo reload: failures $F1 -> $(reload_failures): $(grep 'config reload failed' /tmp/brain.log | tail -1 | cut -c1-160)"
[ "$(etag t2 edge-2)" = "$ET2" ] && [ "$(get legit $US $EDGE2)" = "200" ] && ok "the previous zones stay live, edge-2's ETag unchanged" || bad "the typo went live: etag $ET2 -> $(etag t2 edge-2)"
US_HG=edge-us; HOUSE_HG=edge-asia; zones_yaml
rc=$(check_config); [ "$rc" = "0" ] && grep -q "WARNING.*no node's scope" /tmp/check.out && ok "a zone on a group no node lists: OK with a WARNING" || bad "-check-config on edge-asia: rc=$rc $(grep -i warning /tmp/check.out | head -1)"
grep -q 'edge-1 .*scope=\[' /tmp/check.out && ok "-check-config prints the fleet matrix ($(grep -oE 'edge-1 .*' /tmp/check.out | head -1 | tr -s ' '))" || bad "no matrix in -check-config: $(cat /tmp/check.out | head -8)"
reload_brain; sleep 1.5
[ "$(zst op $HOUSE "z['placement']['nodes']")" = "[]" ] && [ "$(zst op $HOUSE "z.get('unserved', False)")" = "false" ] && ok "status: $HOUSE placement.nodes [] and not unserved (nothing to serve it is a warning, not an alarm)" || bad "$HOUSE placement: $(zst op $HOUSE "z['placement']") unserved $(zst op $HOUSE "z.get('unserved')")"
wait_ne 20 200 get legit $HOUSE $EDGE && wait_ne 20 200 get legit $HOUSE $EDGE2 && ok "$HOUSE left both nodes' renders ('$(get legit $HOUSE $EDGE)' / '$(get legit $HOUSE $EDGE2)')" || bad "$HOUSE still served: $(get legit $HOUSE $EDGE) / $(get legit $HOUSE $EDGE2)"
HOUSE_HG=""; zones_yaml; reload_brain
for i in $(seq 1 100); do [ "$(get legit $HOUSE $EDGE)" = "200" ] && break; sleep 0.3; done
[ "$(get legit $HOUSE $EDGE)" = "200" ] && ok "$HOUSE back on global: served again" || bad "$HOUSE after restore: $(get legit $HOUSE $EDGE)"

# ================================================================ ARM H
say "ARM H — fail-static under a wrong rebind, ended by the reload itself"
settle 1; G1=$(sfield 1 generation); I1=$(installs 1); R1=$(refusals 1)
SHOP_RPS=2; zones_yaml; E1=$(sfield 1 accepted_etag); reload_brain; wait_ne 10 "$E1" node_etag 1 || bad "the low ceiling never reached edge-1"
brain_yaml "$AG_T1_WRONG
$AG_T2" "$NODES_SCOPED" on; T0=$(date +%s%N); reload_brain
# The parked poll is ended by the reload (holdStillAuthorized), so the node
# sees its 403 within seconds — not when the hold would have timed out.
for i in $(seq 1 25); do [ "$(refusals 1)" -gt "$R1" ] && break; sleep 0.2; done
[ "$(refusals 1)" -gt "$R1" ] && ok "edge-1's log shows the 403 $(( ($(date +%s%N) - T0) / 1000000 )) ms after the reload: the parked poll was ended by the rebind" || bad "no 403 in edge-1's log within 5 s of the reload"
wait_eq 12 false node_f edge-1 "n['alive']" && ok "t1 rebound to edge-2: edge-1 is LOST within stale_after of the reload" || bad "edge-1 alive 12 s after the wrong rebind: $(node_f edge-1 "n['alive']")"
[ "$(get legit $SHOP $EDGE)" = "200" ] && ok "edge-1 serves TLS meanwhile" || bad "edge-1 under the wrong rebind (TLS): $(get legit $SHOP $EDGE)"
sleep 1 # the ceiling is 2 rps: give the h3 request its own second
h=$(h3get legit $SHOP $EDGE); [ "$h" = "200 3" ] && ok "…and h3" || bad "edge-1 under the wrong rebind (h3): '$h'"
r=$(burst_refused attacker $SHOP $EDGE 30 198.51.100.4); [ "${r%%/*}" -ge 1 ] && ok "…and still decides: $r from a fresh source (429 = its ceiling, 403 = the rollup's flood rule)" || bad "no refusal from the refused node under a burst ($r)"
SHOP_RPS=1000; zones_yaml
brain_yaml "$AG_T1
$AG_T2" "$NODES_SCOPED" on; reload_brain
wait_eq 20 true node_f edge-1 "n['alive']" && ok "rebind fixed: edge-1 alive" || bad "edge-1 not alive after the fix"
sleep 2; [ "$(sfield 1 generation)" = "$G1" ] && [ "$(installs 1)" = "$I1" ] && ok "no install across the episode (generation $G1)" || bad "an install happened: $I1 -> $(installs 1)"

# ================================================================ ARM I
say "ARM I — moving a zone: $US from edge-us to edge-eu"
settle 1; settle 2; G1=$(sfield 1 generation); G2=$(sfield 2 generation); I1=$(installs 1); I2=$(installs 2)
hosts_drop "$US"; printf '%s %s\n' "$EDGE" "$US" >> /etc/hosts # the zone's DNS follows its placement
[ "$(grep -c " $US\$" /etc/hosts)" = "1" ] && grep -q "^$EDGE $US\$" /etc/hosts && ok "$US's DNS now points at edge-1 (one hosts line)" || bad "hosts after the move: $(grep " $US\$" /etc/hosts | tr '\n' ' ')"
sleep 6 # Go's resolver (Pebble) re-reads /etc/hosts every five seconds
US_HG=edge-eu; zones_yaml; reload_brain
wait_gen 1 $((G1+1)) 40 && ok "edge-1 installed a generation (gains $US)" || bad "edge-1 after the move: gen $(sfield 1 generation)"
wait_gen 2 $((G2+1)) 40 && ok "edge-2 installed a generation (loses $US)" || bad "edge-2 after the move: gen $(sfield 2 generation)"
for i in $(seq 1 200); do [ "$(get legit $US $EDGE)" = "200" ] && break; sleep 0.2; done
if [ "$(get legit $US $EDGE)" != "200" ]; then
  echo "  (first order after the move did not land: $(grep 'certificate order failed' /tmp/edge1.log | tail -1 | grep -oE 'err=.*' | cut -c1-140); hosts: $(grep " $US\$" /etc/hosts | tr '\n' ' '); the CA resolves $US to $(ip netns exec ca curl -s -o /dev/null -w '%{remote_ip}' -m3 "http://$US/.well-known/acme-challenge/probe"); retrying through a node restart)"
  stop_edge 1; start_edge 1 t1
  for i in $(seq 1 600); do [ "$(get legit $US $EDGE)" = "200" ] && break; sleep 0.2; done
fi
[ "$(get legit $US $EDGE)" = "200" ] && ok "$US served by edge-1 (its own certificate from Pebble)" || bad "$US on edge-1 after the move: $(get legit $US $EDGE); $(grep 'certificate order failed' /tmp/edge1.log | tail -1 | grep -oE 'err=.*' | cut -c1-160)"
settle 1; settle 2
[ "$(installs 1)" = "$((I1+2))" ] && [ "$(installs 2)" = "$((I2+1))" ] && ok "installs: edge-1 twice (the render with $US, then its certificate), edge-2 once (the render without it)" || bad "installs: e1 $I1 -> $(installs 1) (want +2), e2 $I2 -> $(installs 2) (want +1)"
[ -d $STATE2/certs/$US ] && ok "edge-2 keeps its $US certificate set on disk" || bad "edge-2's $US certificates gone"
[ "$(zst op $US "z['placement']")" = "{'hostgroup': 'edge-eu', 'nodes': ['edge-1'], 'alive': ['edge-1']}" ] && ok "placement follows: {edge-eu, [edge-1], [edge-1]}" || bad "$US placement: $(zst op $US "z['placement']")"
cbody op POST "$B/edge/zones/$US/challenge" '{"mode":"manual","ttl_seconds":60}' > /tmp/lever-us2.txt; lever op DELETE $US >/dev/null
[ "$(jx "sorted(n['name'] for n in d['nodes'])" < /tmp/lever-us2.txt)" = "['edge-1']" ] && ok "the lever on $US now names edge-1" || bad "lever on $US after the move: $(cut -c1-160 /tmp/lever-us2.txt)"

# ================================================================ ARM J
say "ARM J — the brain dead and restarted under placement"
settle 1; settle 2; G1=$(sfield 1 generation); G2=$(sfield 2 generation); I1=$(installs 1); I2=$(installs 2)
kill_brain && ok "the brain is dead" || bad "the brain is still answering"
[ "$(get legit $SHOP $EDGE)" = "200" ] && [ "$(get legit $SHOP $EDGE2)" = "200" ] && [ "$(get legit $US $EDGE)" = "200" ] && [ "$(get legit $US $EDGE2)" != "200" ] && ok "both nodes serve their own sets with the brain dead" || bad "with the brain dead: shop $(get legit $SHOP $EDGE)/$(get legit $SHOP $EDGE2), us $(get legit $US $EDGE)/$(get legit $US $EDGE2)"
mv /tmp/brain.log /tmp/brain-1.log; start_brain
wait_eq 20 true node_f edge-1 "n['alive']" && wait_eq 20 true node_f edge-2 "n['alive']" && ok "the brain is back and both nodes poll it" || bad "nodes after the brain's return: $(node_f edge-1 "n['alive']") $(node_f edge-2 "n['alive']")"
sleep 3
[ "$(sfield 1 generation)" = "$G1" ] && [ "$(sfield 2 generation)" = "$G2" ] && [ "$(installs 1)" = "$I1" ] && [ "$(installs 2)" = "$I2" ] && ok "no install on either node: the returned brain answers each poll with the node's own document" || bad "installs after the brain's return: e1 $I1 -> $(installs 1), e2 $I2 -> $(installs 2)"

# ================================================================ ARM S6
say "ARM S6 — the report is not trusted"
D0=$(brain_metric 'kapkan_edge_history_dropped_total{reason="unknown_zone"}'); CS0=$(ev_count clock_skew edge-1)
ahead=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
[ "$(code t1 POST "$B/edge/nodes/edge-1/report" "{\"version\":\"1.8.0\",\"zones\":[{\"zone\":\"$SHOP\",\"at\":\"$ahead\",\"window_seconds\":10,\"requests\":7777,\"decided\":7777}]}")" = "204" ] && ok "a forged report with a window an hour ahead is accepted (204)" || bad "forged report: $(code t1 POST "$B/edge/nodes/edge-1/report" "{\"version\":\"1.8.0\",\"zones\":[{\"zone\":\"$SHOP\",\"at\":\"$ahead\",\"window_seconds\":10,\"requests\":7777}]}")"
wait_sql 15 1 "SELECT count() FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND requests=7777 AND ts BETWEEN now() - INTERVAL 60 SECOND AND now() + INTERVAL 60 SECOND" && [ "$(chq "SELECT count() FROM kapkan.edge_windows WHERE ts > now() + INTERVAL 30 MINUTE")" = "0" ] && ok "the window landed once, re-stamped with the brain's clock (ts within a minute of now, nothing an hour ahead)" || bad "re-stamp: rows with requests=7777 near now: $(chq "SELECT count() FROM kapkan.edge_windows WHERE requests=7777 AND ts BETWEEN now() - INTERVAL 60 SECOND AND now() + INTERVAL 60 SECOND"); future rows: $(chq "SELECT count() FROM kapkan.edge_windows WHERE ts > now() + INTERVAL 30 MINUTE")"
# The node's own report follows within a second and is within the gate, so
# the two events — the skew and its recovery — arrive as a pair: exactly two
# new clock_skew events, one of each kind, in that order (newest first).
wait_eq 15 true ev_more clock_skew "$((CS0+1))" edge-1
NEWSKEW=$(events op "kind=clock_skew&node=edge-1" | jx "[e['detail'][:14] for e in (d.get('events') or [])[:len(d.get('events') or [])-$CS0]]")
[ "$NEWSKEW" = "['recovered: the', 'node clock off']" ] && ok "exactly one clock_skew for the forged window (\"node clock off by …\") and exactly one recovery when the node's own report followed" || bad "clock_skew events since the forgery (newest first): $NEWSKEW (all: $(events op "kind=clock_skew&node=edge-1" | cut -c1-240))"
code t1 POST "$B/edge/nodes/edge-1/report" "{\"version\":\"1.8.0\",\"zones\":[{\"zone\":\"evil.test\",\"at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"window_seconds\":10,\"requests\":1}]}" >/dev/null
[ "$(python3 -c "print($(brain_metric 'kapkan_edge_history_dropped_total{reason="unknown_zone"}') - $D0 >= 1)")" = "True" ] && ok "a window for evil.test is dropped and counted (unknown_zone)" || bad "unknown_zone did not move: $D0 -> $(brain_metric 'kapkan_edge_history_dropped_total{reason="unknown_zone"}')"
[ "$(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='evil.test'")" = "0" ] && ok "…and never written" || bad "evil.test rows exist"
# The per-window source cap: 150 sources (1 000 exceed the 64 KiB report body
# and are 413 — a real node sheds detail instead) → at most 20 rows.
at=$(date -u -d '-3 sec' +%Y-%m-%dT%H:%M:%SZ)
python3 -c "
import json
srcs=[{'source':'198.51.%d.%d'%(i//250,i%250+1),'requests':1000-i,'state':'would-deny'} for i in range(150)]
print(json.dumps({'version':'1.8.0','zones':[{'zone':'$SHOP','at':'$at','window_seconds':10,'requests':500000,'decided':500000,'would_deny':500000,'top_sources':srcs}]}))" > /tmp/report-150.json
c=$(ip netns exec edge curl -s -o /dev/null -w '%{http_code}' -m5 -X POST -H "Authorization: Bearer t1tok" -H 'Content-Type: application/json' --data-binary @/tmp/report-150.json "$B/edge/nodes/edge-1/report")
wait_sql 15 1 "SELECT count() FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND requests=500000" || bad "the 150-source window never landed"
n=$(chq "SELECT count() FROM kapkan.edge_sources WHERE zone='$SHOP' AND node='edge-1' AND ts = (SELECT max(ts) FROM kapkan.edge_windows WHERE zone='$SHOP' AND node='edge-1' AND requests=500000)")
[ "$c" = "204" ] && [ "${n:-0}" -le 20 ] && [ "${n:-0}" -ge 1 ] && ok "a report with 150 sources: 204, at most 20 rows written ($n)" || bad "150-source report: $c, rows $n"

# ================================================================ ARM S7
say "ARM S7 — never blocks: ClickHouse stalled, then dead, under a report burst"
E0=$(brain_metric 'kapkan_storage_rows_total{.*result="error"'); DR0=$(brain_metric 'kapkan_storage_rows_total{.*result="dropped"')
# First a STALLED sink: packets to :8123 are dropped in the brain's netns, so
# every flush hangs on the client's timeout and the queue of 50 fills.
ip netns exec edge iptables -A OUTPUT -p tcp --dport 8123 -j DROP
[ -z "$(chq 'SELECT 1')" ] && ok "ClickHouse black-holed (:8123 swallows packets; a flush now waits on its timeout)" || bad "ClickHouse still answers through the black hole"
# Eight paced reports: each must be a 204 in under 50 ms — the answer never
# waits for storage.
slowbad=0; worst="";
for i in $(seq 1 8); do
  r=$(ip netns exec edge curl -s -o /dev/null -w '%{http_code} %{time_total}' -m5 -X POST -H "Authorization: Bearer t1tok" -H 'Content-Type: application/json' -d "{\"version\":\"1.8.0\",\"zones\":[{\"zone\":\"$SHOP\",\"at\":\"$(date -u -d "-$i sec" +%Y-%m-%dT%H:%M:%SZ)\",\"window_seconds\":10,\"requests\":$i,\"top_sources\":[{\"source\":\"198.51.200.7\",\"requests\":$i,\"state\":\"would-deny\"}]}]}" "$B/edge/nodes/edge-1/report")
  python3 -c "import sys; c,t=sys.argv[1].split(); sys.exit(0 if c=='204' and float(t) < 0.05 else 1)" "$r" || { slowbad=$((slowbad+1)); worst="$worst[$r]"; }
  sleep 0.5
done
[ "$slowbad" = "0" ] && ok "eight paced reports: every one a 204 in under 50 ms with the sink stalled" || bad "$slowbad of 8 reports were not a 204 under 50 ms: $worst"
# A burst of eighty concurrent reports with distinct windows (a window and a
# source row each) inside one flush interval: more than the writer's queue of
# 50 — the surplus is dropped and counted, never waited for. (Sixty paced
# reports were not enough: each second's flush fails and empties the queue
# into `error`, so the queue never fills — the drop path needs a real burst.)
: > /tmp/burst.txt; BURST_PIDS=""
for i in $(seq 1 80); do
  ( ip netns exec edge curl -s -o /dev/null -w '%{http_code} %{time_total}\n' -m5 -X POST -H "Authorization: Bearer t1tok" -H 'Content-Type: application/json' -d "{\"version\":\"1.8.0\",\"zones\":[{\"zone\":\"$SHOP\",\"at\":\"$(date -u -d "-$((i+10)) sec" +%Y-%m-%dT%H:%M:%SZ)\",\"window_seconds\":10,\"requests\":$((9000+i)),\"top_sources\":[{\"source\":\"198.51.200.7\",\"requests\":$((9000+i)),\"state\":\"would-deny\"}]}]}" "$B/edge/nodes/edge-1/report" >> /tmp/burst.txt ) &
  BURST_PIDS="$BURST_PIDS $!"
done
# Wait for the burst alone: a bare `wait` would wait for every background job
# of this shell — the brain, the nodes, nginx, Pebble, the origins — forever.
wait $BURST_PIDS
burstbad=$(python3 -c "
import sys
bad=0; n=0
for l in open('/tmp/burst.txt'):
    p=l.split()
    if len(p)!=2: continue
    n+=1
    if p[0]!='204' or float(p[1])>=0.05: bad+=1
print(bad if n==80 else 80)")
[ "$burstbad" = "0" ] && ok "a burst of 80 concurrent reports into a stalled sink: every one a 204 in under 50 ms (worst $(awk '{print $2}' /tmp/burst.txt | sort -n | tail -1) s)" || bad "$burstbad of 80 burst reports were not a 204 under 50 ms (or fewer answered): $(sort /tmp/burst.txt | uniq -c | sort -rn | head -3 | tr '\n' ';')"
for i in $(seq 1 40); do DR=$(brain_metric 'kapkan_storage_rows_total{.*result="dropped"'); [ "$(python3 -c "print(($DR - $DR0) > 0)")" = "True" ] && break; sleep 0.5; done
[ "$(python3 -c "print(($DR - $DR0) > 0)")" = "True" ] && ok "kapkan_storage_rows_total{result=dropped} grew (+$(python3 -c "print(int($DR - $DR0))")): the full queue dropped the surplus, the handler never waited" || bad "no dropped rows counted under the burst into a stalled sink: $DR0 -> $DR"
# Then DEAD: the black hole lifted with ClickHouse stopped, so every pending
# flush fails fast and is counted as error — nothing of the stall is kept.
stop_ch; ip netns exec edge iptables -D OUTPUT -p tcp --dport 8123 -j DROP
[ -z "$(chq 'SELECT 1')" ] && ok "ClickHouse stopped (:8123 refuses)" || bad "ClickHouse still answers after stop"
for i in $(seq 1 40); do E=$(brain_metric 'kapkan_storage_rows_total{.*result="error"'); [ "$(python3 -c "print(($E - $E0) > 0)")" = "True" ] && break; sleep 0.5; done
[ "$(python3 -c "print(($E - $E0) > 0)")" = "True" ] && ok "kapkan_storage_rows_total{result=error} grew (+$(python3 -c "print(int($E - $E0))")): the flushes failed against the dead server" || bad "no error rows counted: $E0 -> $E"
grep -qi 'clickhouse.*\(fail\|error\|refused\)\|insert.*fail' /tmp/brain.log && ok "the brain logged the failed insert" || bad "no insert failure in the brain log"
[ "$(code op GET "$B/edge/zones/status")" = "200" ] && [ "$(zst op $SHOP "z['nodes'] >= 1")" = "true" ] && ok "the zone status is untouched" || bad "zone status with storage down: $(code op GET "$B/edge/zones/status")"
start_ch; wait_ch && ok "ClickHouse restarted" || bad "ClickHouse did not come back"
W1=$(chq "SELECT count() FROM kapkan.edge_windows"); for i in $(seq 1 10); do get legit $SHOP $EDGE >/dev/null; sleep 0.3; done
wait_ne 40 "$W1" chq "SELECT count() FROM kapkan.edge_windows" && ok "rows land again after the restart ($W1 -> $(chq "SELECT count() FROM kapkan.edge_windows"))" || bad "no new rows after ClickHouse's return"
sleep 3
[ "$(chq "SELECT count() FROM kapkan.edge_sources WHERE source='198.51.200.7'")" = "0" ] && [ "$(chq "SELECT count() FROM kapkan.edge_windows WHERE requests BETWEEN 9001 AND 9080")" = "0" ] && ok "what was dropped while ClickHouse was dead is not back-filled (no row of the dead-time reports)" || bad "dead-time rows appeared: sources $(chq "SELECT count() FROM kapkan.edge_sources WHERE source='198.51.200.7'"), windows $(chq "SELECT count() FROM kapkan.edge_windows WHERE requests BETWEEN 9001 AND 9080")"

# ================================================================ ARM S9
say "ARM S9 — retention"
chq "SHOW CREATE TABLE kapkan.edge_windows" | grep -q 'TTL ts + toIntervalDay(1)' && ok "edge_windows carries TTL ts + toIntervalDay(1)" || bad "TTL clause: $(chq "SHOW CREATE TABLE kapkan.edge_windows" | grep -oE 'TTL[^\\]*' | head -1)"
ins=$(chq_code "INSERT INTO kapkan.edge_windows (ts, received_at, zone, node) VALUES (now() - INTERVAL 2 DAY, now(), 'ttl.test', 'rig-old'), (now(), now(), 'ttl.test', 'rig-fresh')")
chq "OPTIMIZE TABLE kapkan.edge_windows FINAL" >/dev/null
[ "$ins" = "200" ] && [ "$(chq "SELECT count() FROM kapkan.edge_windows WHERE zone='ttl.test'")" = "1" ] && [ "$(chq "SELECT node FROM kapkan.edge_windows WHERE zone='ttl.test'")" = "rig-fresh" ] && ok "of two rows inserted in one statement (200), the fresh one landed and the two-day-old one never did (TTL filters at insert; OPTIMIZE FINAL leaves it out)" || bad "TTL: insert $ins, ttl.test rows $(chq "SELECT node FROM kapkan.edge_windows WHERE zone='ttl.test'" | tr '\n' ' ')"

# ================================================================ ARM S8
say "ARM S8 — storage off is byte-identical"
# Positive control while storage is still on: a forged report is flushed to
# :8123 within a second, and the tap on lo sees it.
timeout 8 ip netns exec edge tcpdump -i lo -nn -c 1 'tcp port 8123' >/tmp/tcpdump-8123-on.log 2>&1 &
TCPD=$!; sleep 0.7
code t1 POST "$B/edge/nodes/edge-1/report" "{\"version\":\"1.8.0\",\"zones\":[{\"zone\":\"$SHOP\",\"at\":\"$(date -u -d '-2 sec' +%Y-%m-%dT%H:%M:%SZ)\",\"window_seconds\":10,\"requests\":4242,\"decided\":4242}]}" >/dev/null
wait $TCPD; rc_on=$?
grep -q 'listening on lo' /tmp/tcpdump-8123-on.log && [ "$rc_on" = "0" ] && ok "positive control: with storage on, the tap on lo sees the flush to :8123 within a second of a report" || bad "the :8123 tap sees nothing with storage on (rc $rc_on) — the negative below would prove nothing: $(head -3 /tmp/tcpdump-8123-on.log | tr '\n' '|')"
ET1=$(settle_etag t1 edge-1); ET2=$(settle_etag t2 edge-2); I1=$(installs 1); I2=$(installs 2); G1=$(sfield 1 generation); G2=$(sfield 2 generation)
kill_brain; mv /tmp/brain.log /tmp/brain-2.log
brain_yaml "$AG_T1
$AG_T2" "$NODES_SCOPED" off; start_brain
wait_eq 30 true node_f edge-1 "n['alive']" || bad "edge-1 did not poll the storage-less brain"
wait_eq 30 true node_f edge-2 "n['alive']" || bad "edge-2 did not poll the storage-less brain"
[ "$(etag t1 edge-1)" = "$ET1" ] && [ "$(etag t2 edge-2)" = "$ET2" ] && [ "$(installs 1)" = "$I1" ] && [ "$(installs 2)" = "$I2" ] && [ "$(sfield 1 generation)" = "$G1" ] && [ "$(sfield 2 generation)" = "$G2" ] && ok "storage off: the same documents (ETags $ET1 / $ET2), no install, no generation moved" || bad "storage off changed a document: etags $ET1 -> $(etag t1 edge-1), $ET2 -> $(etag t2 edge-2); installs $I1 -> $(installs 1), $I2 -> $(installs 2)"
[ "$(hist op "zone=$SHOP" | jx "d['available']")" = "false" ] && [ "$(hist op "zone=$SHOP" | jx "d['points']")" = "[]" ] && ok "/edge/history answers {available:false, points:[]}" || bad "history without storage: $(hist op "zone=$SHOP" | cut -c1-120)"
[ "$(hist acme-view "zone=$STATIC" | jx "d['available']")" = "false" ] && ok "…for every token, no zone looked at (acme-view on another tenant's zone: available:false, not 403)" || bad "scoped history without storage: $(hist acme-view "zone=$STATIC" | cut -c1-120)"
[ -z "$(ip netns exec edge curl -s -m3 http://$BRAIN:8080/metrics | grep '^kapkan_storage_rows_total')" ] && ok "/metrics carries no kapkan_storage_rows_total series" || bad "storage metrics present without storage"
# The negative, deterministic: the same forged report during a capture — with
# storage on it was flushed within a second; now nothing must reach :8123.
timeout 5 ip netns exec edge tcpdump -i lo -nn -c 1 'tcp port 8123' >/tmp/tcpdump-8123-off.log 2>&1 &
TCPD=$!; sleep 0.7
code t1 POST "$B/edge/nodes/edge-1/report" "{\"version\":\"1.8.0\",\"zones\":[{\"zone\":\"$SHOP\",\"at\":\"$(date -u -d '-2 sec' +%Y-%m-%dT%H:%M:%SZ)\",\"window_seconds\":10,\"requests\":4243,\"decided\":4243}]}" >/dev/null
for i in 1 2 3; do get legit $SHOP $EDGE >/dev/null; sleep 0.3; done
wait $TCPD; rc_off=$?
grep -q 'listening on lo' /tmp/tcpdump-8123-off.log && [ "$rc_off" = "124" ] && ok "tcpdump on lo (capturing) saw no packet to :8123 through a report and three requests: storage off talks to nobody" || bad "the :8123 tap with storage off: rc $rc_off, $(grep -c '8123' /tmp/tcpdump-8123-off.log) packet line(s): $(head -3 /tmp/tcpdump-8123-off.log | tr '\n' '|')"
[ "$(get legit $SHOP $EDGE)" = "200" ] && [ "$(h3get legit $SHOP $EDGE2)" = "200 3" ] && ok "TLS and h3 served as before" || bad "serving without storage: $(get legit $SHOP $EDGE)"
l1=$(lever acme-op POST $SHOP '{"mode":"manual","ttl_seconds":60}'); l2=$(lever acme-op DELETE $SHOP)
[ "$l1" = "200" ] && [ "$l2" = "200" ] && ok "the tenant's lever works without storage" || bad "lever without storage: POST $l1, DELETE $l2"
# A node the ticker never heard from is baselined lost silently — both nodes
# polled the restarted brain above, so this loss is a transition and a line.
stop_edge 2; wait_eq 45 false node_f edge-2 "n['alive']" || bad "edge-2 not lost after stop (storage off): alive $(node_f edge-2 "n['alive']")"
sleep 3
grep -q 'edge node lost' /tmp/brain.log && ok "presence INFO lines are logged with storage off" || bad "no presence line without storage: $(grep -c . /tmp/brain.log) lines, tail: $(tail -2 /tmp/brain.log | cut -c1-120 | tr '\n' '|')"
start_edge 2 t2; wait_eq 20 true node_f edge-2 "n['alive']" || bad "edge-2 did not come back after the storage-off loss"

# ================================================================ ARM S10
say "ARM S10 — nothing to steal; fail-static with the brain and ClickHouse dead"
doc op edge-1 | python3 -c "
import json,sys
d=json.load(sys.stdin); out=[]
def walk(x):
    if isinstance(x, dict):
        for k,v in x.items(): walk(v)
    elif isinstance(x, list):
        for v in x: walk(v)
    elif isinstance(x, str) and len(x) >= 24 and ' ' not in x: out.append(x)
walk(d.get('clearance_keys') or [z.get('clearance_keys') for z in d.get('zones',[])])
print('\n'.join(sorted(set(out))))" > /tmp/s10-keys
NK=$(grep -c . /tmp/s10-keys)
[ "$NK" -ge 1 ] && ok "harvested $NK clearance key strings from edge-1's document (kept in memory only)" || bad "no clearance key strings harvested from the document — S10 would prove nothing"
start_ch; wait_ch || bad "ClickHouse did not come back for the dump"
chq "SELECT table, sum(rows), sum(data_compressed_bytes), round(sum(data_compressed_bytes)/greatest(sum(rows),1),1) FROM system.parts WHERE database='kapkan' AND table LIKE 'edge_%' AND active GROUP BY table ORDER BY table" > /tmp/bytes-per-row-final.tsv
for t in edge_windows edge_sources edge_events; do chq "SELECT * FROM kapkan.$t FORMAT TSV" > /tmp/dump-$t.tsv; done
NROWS=$(cat /tmp/dump-*.tsv | wc -l)
[ "$NROWS" -ge 1 ] && ok "the three tables dumped ($NROWS rows)" || bad "the table dumps are empty"
hits=0; while read -r s; do [ -n "$s" ] && grep -qF "$s" /tmp/dump-*.tsv && hits=$((hits+1)); done < /tmp/s10-keys
rm -f /tmp/s10-keys
[ "$NK" -ge 1 ] && [ "$NROWS" -ge 1 ] && [ "$hits" = "0" ] && ok "none of the $NK clearance key strings appears in the $NROWS rows" || bad "$hits clearance key strings found in the tables"
grep -q 'PRIVATE KEY' /tmp/dump-*.tsv && bad "a PEM private key in the tables" || ok "no PEM key material in the tables"
kill_brain; stop_ch
[ "$(get legit $SHOP $EDGE)" = "200" ] && [ "$(h3get legit $SHOP $EDGE)" = "200 3" ] && [ "$(get legit $US $EDGE)" = "200" ] && ok "brain and ClickHouse dead: the node serves TLS, h3 and its placed zone" || bad "fail-static with everything dead: shop $(get legit $SHOP $EDGE), h3 $(h3get legit $SHOP $EDGE), us $(get legit $US $EDGE)"

echo
echo "== E6 acceptance: $PASS passed, $FAIL failed =="
echo "== bytes per row (system.parts, whole run): $(tr '\n' ';' < /tmp/bytes-per-row-final.tsv) =="
echo "== bytes per row (system.parts, after S1/S2): $(tr '\n' ';' < /tmp/bytes-per-row.tsv) =="
[ "$FAIL" -eq 0 ]
