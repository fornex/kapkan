#!/usr/bin/env bash
#
# E3 acceptance, on a real kernel with a real nginx: the "zones + ACME +
# renderer + decision service" milestone from the edge spec
# (engine/docs/edge-spec.md, milestone E3). A brain serves a zones document; an
# edge box running stock nginx and `kapkan edge` turns it into a managed HTTPS
# front: the certificate is issued ON the node from a real ACME CA (Pebble, with
# a real HTTP-01 fetch), the configuration is rendered and installed behind
# `nginx -t`, every request is decided locally, and the brain is never in the
# request path. The arms prove the §8 criteria:
#
#   A. issuance + serving: the zone gets a Pebble-issued certificate through the
#      brain's slot + fan-out, nginx serves it over TLS, the origin sees
#      X-Kapkan-Zone, /healthz is converged, the brain's inventory shows the node;
#   B. dry-run then live: over the zone's rate a client still reaches the origin
#      with X-Kapkan-Mark: would-deny:rate (watch-only, the default); live, the
#      same burst is answered 429 with Retry-After, a slow client passes;
#   C. fast path: tightening the rate on the brain reaches the node without a
#      render or a reload — the generation number does not move;
#   D. slow path: a zone added on the brain is a new generation, tested and
#      reloaded, and served;
#   E. broken edit: a zone snippet nginx rejects never becomes live — the
#      previous generation keeps serving, /healthz stays 200 with converged:false
#      and the tester's message, the brain's report names the RENDERED document;
#   F. kill-brain: with the brain dead the node keeps deciding and serving, and a
#      restarted node comes back into service from disk before the brain returns;
#      when the brain returns the node's first poll is answered 304;
#   G. rollups: a source that keeps pushing through its ceiling is promoted to a
#      deny (403) while a legit client is untouched;
#   H. latency: the decision adds single-digit milliseconds at most to a request,
#      measured against a mode:none zone on the same node.
#
# Topology (one privileged container, netns per role; the CA resolves the zone
# name through /etc/hosts to the edge, exactly as DNS would):
#
#     legit    203.0.113.2   ─┐
#     attacker 198.51.100.3  ─┤  br0 203.0.113.1 / 198.51.100.1
#     brain    203.0.113.20  ─┼──── edge 203.0.113.10  (nginx :80/:443 + kapkan edge)
#     origin   203.0.113.30  ─┤
#     ca       203.0.113.40  ─┘  (Pebble ACME, directory :14000, validates on :80)
#
# Build the binaries for the container arch first (from engine/), then run this
# inside one privileged debian container:
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan
#   GOBIN=/tmp/lab CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
#     go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
#   docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:12-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq \
#              iproute2 nginx openssl curl python3 procps iputils-ping ca-certificates >/dev/null \
#            && KAPKAN=/lab/kapkan PEBBLE=/lab/pebble bash engine/scripts/labnet/edge-e3.sh'
#
set -uo pipefail
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
KAPKAN=${KAPKAN:-/lab/kapkan}
PEBBLE=${PEBBLE:-/lab/pebble}
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
say() { echo; echo "== $1 =="; }
[ -x "$KAPKAN" ] || { echo "kapkan binary not found at $KAPKAN"; exit 2; }
[ -x "$PEBBLE" ] || { echo "pebble binary not found at $PEBBLE"; exit 2; }

EDGE=203.0.113.10; BRAIN=203.0.113.20; ORIGIN=203.0.113.30; CA=203.0.113.40
ZONE=shop.test; ZONE2=static.test
STATE=/var/lib/kapkan-edge; SOCKS=/run/kapkan-edge
export KAPKAN_API_TOKEN=optok KAPKAN_EDGE_TOKEN=agenttok

cleanup() {
  # Keep the logs where the host can read them (the container is --rm).
  if [ -d /lab ]; then mkdir -p /lab/logs && cp -f /tmp/*.log /lab/logs/ 2>/dev/null; cp -f /tmp/zones.yaml /tmp/edge.yaml /tmp/brain.yaml /lab/logs/ 2>/dev/null; fi
  pkill -f "$KAPKAN" 2>/dev/null; pkill -f "$PEBBLE" 2>/dev/null
  pkill -f nginx 2>/dev/null; pkill -f origin.py 2>/dev/null
  for ns in edge brain origin ca legit attacker bursty; do ip netns del "$ns" 2>/dev/null; done
  ip link del br0 2>/dev/null
}
trap cleanup EXIT
cleanup

# ---------------------------------------------------------------- topology
say "building the netns topology"
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
add_ns brain    $BRAIN       24 203.0.113.1
add_ns origin   $ORIGIN      24 203.0.113.1
add_ns ca       $CA          24 203.0.113.1
add_ns legit    203.0.113.2  24 203.0.113.1
add_ns attacker 198.51.100.3 24 198.51.100.1
# A separate client for the BURST tests: a source that gets 20+ denials in one
# 10 s window is exactly what the rollups promote to a deny (arm G proves it),
# and the legit client must stay legit for the whole run.
add_ns bursty   203.0.113.4  24 203.0.113.1
# The zone names resolve to the edge for everyone in the container — the CA's
# validation fetch included, exactly as public DNS would.
printf '%s %s\n%s %s\n' "$EDGE" "$ZONE" "$EDGE" "$ZONE2" >> /etc/hosts
ip netns exec legit ping -c1 -W1 $EDGE >/dev/null 2>&1 && ok "legit reaches the edge" || bad "no path legit -> edge (topology broken; nothing below is meaningful)"
ip netns exec ca ping -c1 -W1 $EDGE >/dev/null 2>&1 && ok "the CA reaches the edge (validation path)" || bad "no path ca -> edge"

# ---------------------------------------------------------------- origin
say "starting the origin (echoes the headers kapkan sets)"
cat > /tmp/origin.py <<'PY'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "zone": self.headers.get("X-Kapkan-Zone", ""), "mark": self.headers.get("X-Kapkan-Mark", "")}).encode()
        with open("/tmp/origin.log", "a") as f:
            f.write(body.decode() + "\n")
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8081), H).serve_forever()
PY
: > /tmp/origin.log
ip netns exec origin python3 /tmp/origin.py &
for i in $(seq 1 20); do ip netns exec legit curl -s -m1 http://$ORIGIN:8081/ >/dev/null 2>&1 && break; sleep 0.3; done
ip netns exec legit curl -s -m2 http://$ORIGIN:8081/ | grep -q '"path"' && ok "origin answers directly" || bad "origin not answering"

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
ip netns exec edge curl -sk -m2 https://$CA:14000/dir | grep -q newOrder && ok "Pebble directory is up" || bad "Pebble not answering (see /tmp/pebble.log)"

# ---------------------------------------------------------------- the brain
say "starting the brain with the zones file and the edge block"
zones_yaml() { # $1 = shop rps ; $2 = extra zone yaml (may be empty) ; $3 = extra_directives_file for shop (may be empty)
cat > /tmp/zones.yaml <<YAML
zones:
  - name: $ZONE
    origins: ["$ORIGIN:8081"]
    tls: { min_version: "1.2" }
    acme: { directory: "https://$CA:14000/dir" }
    policy: { mode: decide, failure_mode: open, rate: { rps: $1 } }
${3:+    extra_directives_file: $3}
$2
YAML
}
zones_yaml 5 "" ""
cat > /tmp/brain.yaml <<YAML
dry_run: true
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
api:
  listen: "$BRAIN:8080"
  tokens:
    - { name: op, token_env: KAPKAN_API_TOKEN, role: operator }
    - { name: edge-agent, token_env: KAPKAN_EDGE_TOKEN, role: agent }
edge:
  zones_file: /tmp/zones.yaml
  stale_after_seconds: 5
  nodes:
    - name: edge-1
YAML
start_brain() {
  ip netns exec brain "$KAPKAN" -config /tmp/brain.yaml -log-format text -log-level info -pid-file /tmp/brain.pid >>/tmp/brain.log 2>&1 &
  for i in $(seq 1 40); do ip netns exec brain curl -s -m1 http://$BRAIN:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done
}
brain_api() { ip netns exec brain curl -s -m3 -H "Authorization: Bearer optok" "$@"; }
reload_brain() { ip netns exec brain "$KAPKAN" -s reload -pid-file /tmp/brain.pid >/dev/null 2>&1; sleep 0.5; }
: > /tmp/brain.log
start_brain
code=$(ip netns exec brain curl -s -o /dev/null -w '%{http_code}' -m3 -H "Authorization: Bearer agenttok" "http://$BRAIN:8080/api/v1/edge/zones?node=edge-1")
[ "$code" = "200" ] && ok "brain serves the zones document to the agent" || { bad "brain does not serve the zones document (got '$code')"; tail -15 /tmp/brain.log; }

# ---------------------------------------------------------------- nginx on the edge
say "starting stock nginx on the edge with kapkan's include"
# Only the parent: `live` is a symlink the node creates and retargets itself
# (a wildcard include of a missing directory is fine for nginx).
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
pgrep -f 'nginx: master' >/dev/null && ok "nginx master is up (empty include, nothing served yet)" || bad "nginx did not start (see /tmp/edge-nginx.log)"

# ---------------------------------------------------------------- kapkan edge
edge_yaml() { # $1 = dry_run
cat > /tmp/edge.yaml <<YAML
dry_run: $1
controller: { url: "http://$BRAIN:8080", token_env: KAPKAN_EDGE_TOKEN, name: edge-1, report_interval_seconds: 1 }
state_dir: $STATE
sockets_dir: $SOCKS
socket_group: www-data
terminator: { binary: nginx, main_conf: /tmp/edge-nginx.conf, reload: exec, pid_file: /tmp/edge-nginx.pid }
acme: { contact: ["mailto:lab@example.test"] }
status_listen: 127.0.0.1:9102
YAML
}
start_edge() {
  SSL_CERT_FILE=/tmp/pebble.crt ip netns exec edge "$KAPKAN" edge -config /tmp/edge.yaml -log-format text -log-level info >>/tmp/edge.log 2>&1 &
}
stop_edge() { pkill -f "$KAPKAN edge" 2>/dev/null; for i in $(seq 1 30); do pgrep -f "$KAPKAN edge" >/dev/null || break; sleep 0.2; done; }
status() { ip netns exec edge curl -s -m2 http://127.0.0.1:9102/healthz 2>/dev/null; }
sfield() { status | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('$1',''); print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }
wait_status() { # field value timeout-seconds
  local i; for i in $(seq 1 $(( $3 * 5 ))); do [ "$(sfield "$1")" = "$2" ] && return 0; sleep 0.2; done; return 1
}
# get NS URL [curl args...] -> http code
get() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -o /dev/null -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" --resolve "$ZONE2:443:$EDGE" "$@" "$url" 2>/dev/null; }
# report FIELD -> the node's report field as the brain returns it (JSON-decoded)
report_field() { brain_api "http://$BRAIN:8080/api/v1/edge/nodes" | python3 -c "
import json,sys
d=json.load(sys.stdin)
nodes=d.get('nodes', d if isinstance(d, list) else [])
for n in nodes:
    if n.get('name')=='edge-1':
        r=n.get('report') or {}
        v=r.get('$1', (r.get('terminator') or {}).get('$1',''))
        print(v)
" 2>/dev/null; }
installs() { grep -c 'configuration installed' /tmp/edge.log; }

say "ARM A — issuance through the brain's slot + fan-out, a Pebble certificate served by nginx"
: > /tmp/edge.log
edge_yaml true
"$KAPKAN" edge -config /tmp/edge.yaml -check 2>&1 | grep -q 'is valid' && ok "edge.yaml passes -check" || bad "edge.yaml fails -check"
start_edge
wait_status healthy true 30 && ok "node healthy: a tested generation is live" || { bad "node never became healthy (see /tmp/edge.log)"; tail -20 /tmp/edge.log; }
# The first generation has no certificate yet: :80 answers 503 except for ACME.
# Issuance follows at once (the document wakes the manager).
for i in $(seq 1 150); do grep -q 'certificate issued' /tmp/edge.log && break; sleep 0.2; done
grep -q 'certificate issued' /tmp/edge.log && ok "certificate issued by Pebble through a real HTTP-01 fetch on the edge" || { bad "no certificate issued in 30 s"; grep -i 'acme\|certificate' /tmp/edge.log | tail -5; }
grep -q 'edge acme slot requested' /tmp/brain.log && ok "the node took the zone's issuance slot on the brain" || bad "no slot request reached the brain"
grep -q 'edge acme challenge published' /tmp/brain.log && ok "the node fanned its challenge out through the brain" || bad "no challenge published to the brain"
ls $STATE/certs/$ZONE/current/privkey.pem >/dev/null 2>&1 && [ "$(stat -c %a $STATE/certs/$ZONE/current/privkey.pem)" = "600" ] \
  && ok "private key is 0600 under the node's state directory" || bad "key missing or not 0600"
# Trust Pebble's root for the clients.
ip netns exec legit curl -sk -m3 https://$CA:15000/roots/0 > /tmp/pebble-root.crt 2>/dev/null
grep -q 'BEGIN CERTIFICATE' /tmp/pebble-root.crt && ok "fetched Pebble's root for the clients" || bad "could not fetch Pebble's root"
wait_status converged true 30 || true
for i in $(seq 1 50); do [ "$(get legit https://$ZONE/hello)" = "200" ] && break; sleep 0.2; done
[ "$(get legit https://$ZONE/hello)" = "200" ] && ok "TLS request to the zone is served through nginx to the origin" || bad "zone not served over TLS (see /tmp/edge-nginx-error.log)"
grep -q "\"zone\": \"$ZONE\"" /tmp/origin.log && ok "origin received X-Kapkan-Zone" || bad "X-Kapkan-Zone did not reach the origin"
[ "$(get legit http://$ZONE/hello)" = "301" ] && ok ":80 redirects to https" || bad ":80 did not redirect"
[ "$(get legit https://203.0.113.10/ --resolve unknown.test:443:$EDGE -H 'Host: unknown.test')" != "200" ] && ok "an unknown host is refused by the catch-all" || bad "unknown host served"
GEN1=$(sfield generation); [ "$GEN1" -ge 2 ] 2>/dev/null && ok "issuance produced a new tested generation ($GEN1)" || bad "generation after issuance: $GEN1"
brain_api "http://$BRAIN:8080/api/v1/edge/nodes" | grep -q '"edge-1"' && ok "the brain's inventory lists the node" || bad "node missing from the brain's inventory"
sleep 1.5
brain_api "http://$BRAIN:8080/api/v1/edge/nodes" | grep -q "\"generation\": *$GEN1" && ok "the node's report reached the brain with its live generation" || bad "no report with generation $GEN1 on the brain"

say "ARM B — dry-run marks, then live 429s"
: > /tmp/origin.log
# In a subshell: a bare `wait` in the main shell would wait for every service
# started in the background above (origin, Pebble, brain, nginx, the node).
( for i in $(seq 1 20); do get bursty https://$ZONE/burst-$i >/dev/null & done; wait )
grep -q 'would-deny:rate' /tmp/origin.log && ok "dry-run: over-rate requests reached the origin marked would-deny:rate" || bad "no would-deny:rate mark at the origin in dry-run"
[ "$(grep -c '"path"' /tmp/origin.log)" -ge 20 ] && ok "dry-run refused nothing (all 20 reached the origin)" || bad "dry-run dropped requests: $(grep -c '"path"' /tmp/origin.log)/20"
stop_edge
edge_yaml false
start_edge
wait_status healthy true 30 && ok "live node back up (started from disk, no re-issuance)" || bad "live node not healthy"
grep -c 'certificate issued' /tmp/edge.log | grep -q '^1$' && ok "no second issuance on restart (the certificate was on disk)" || bad "restart re-issued the certificate"
sleep 1.2  # let the bucket refill after the dry-run burst
codes=$(for i in $(seq 1 20); do get bursty https://$ZONE/live-$i & done; wait)
echo "$codes" | grep -q 429 && ok "live: a 20-request burst at rps=5 gets 429s ($(echo "$codes" | grep -o 429 | wc -l | tr -d ' ') of 20)" || bad "no 429 in a live burst: $codes"
for i in $(seq 1 8); do ip netns exec bursty curl -s -D - -o /dev/null -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" https://$ZONE/ra-$i 2>/dev/null; done > /tmp/ra.txt
grep -q ' 429' /tmp/ra.txt && grep -qi 'retry-after' /tmp/ra.txt && ok "a 429 carries Retry-After" || { bad "429 without Retry-After"; grep -i 'HTTP/\|retry' /tmp/ra.txt | head -6; }
sleep 1.5
[ "$(get legit https://$ZONE/slow)" = "200" ] && ok "a slow client passes" || bad "slow client refused ($(get legit https://$ZONE/slow2))"

say "ARM C — fast path: a rate change never reloads nginx"
GEN_BEFORE=$(sfield generation); RELOADS_BEFORE=$(grep -c 'configuration installed' /tmp/edge.log)
zones_yaml 100 "" ""; reload_brain
for i in $(seq 1 50); do [ "$(sfield accepted_etag)" != "$(sfield zones_etag)" ] || { grep -q 'rps: 100' /tmp/zones.yaml && break; }; sleep 0.2; done
sleep 1.5
codes=$(for i in $(seq 1 20); do get bursty https://$ZONE/fast-$i & done; wait)
echo "$codes" | grep -q 429 && bad "rate raised to 100 but the burst still got 429: $codes" || ok "the new rate (100 rps) is enforced: 20-request burst all served"
[ "$(sfield generation)" = "$GEN_BEFORE" ] && ok "generation unchanged ($GEN_BEFORE): no render, no reload" || bad "a rate change produced a new generation ($GEN_BEFORE -> $(sfield generation))"
[ "$(grep -c 'configuration installed' /tmp/edge.log)" = "$RELOADS_BEFORE" ] && ok "no 'configuration installed' line for the rate change" || bad "the rate change installed a configuration"

say "ARM D — slow path: a zone added on the brain is a new, tested, reloaded generation"
zones_yaml 100 "  - name: $ZONE2
    origins: [\"$ORIGIN:8081\"]
    acme: { directory: \"https://$CA:14000/dir\" }
    policy: { mode: none }" ""
reload_brain
for i in $(seq 1 100); do [ "$(sfield zones)" = "2" ] && [ "$(sfield generation)" != "$GEN_BEFORE" ] && break; sleep 0.2; done
[ "$(sfield zones)" = "2" ] && ok "node holds two zones" || bad "second zone not accepted"
[ "$(sfield generation)" != "$GEN_BEFORE" ] && ok "a zone change produced a new generation ($GEN_BEFORE -> $(sfield generation))" || bad "no new generation for a zone change"
for i in $(seq 1 150); do [ "$(grep -c 'certificate issued' /tmp/edge.log)" -ge 2 ] && break; sleep 0.2; done
[ "$(grep -c 'certificate issued' /tmp/edge.log)" -ge 2 ] && ok "the new zone got its certificate at once (the document woke the manager)" || bad "second zone not issued in 30 s"
for i in $(seq 1 50); do [ "$(get legit https://$ZONE2/hi)" = "200" ] && break; sleep 0.2; done
[ "$(get legit https://$ZONE2/hi)" = "200" ] && ok "the mode:none zone is served over TLS" || bad "second zone not served"
wait_status converged true 20 && ok "node converged on the two-zone document" || bad "not converged: $(sfield last_error)"

say "ARM E — a broken edit never goes live"
echo 'bogus_directive on;' > /tmp/bad.conf
GEN_GOOD=$(sfield generation); ETAG_GOOD=$(sfield zones_etag)
zones_yaml 100 "  - name: $ZONE2
    origins: [\"$ORIGIN:8081\"]
    acme: { directory: \"https://$CA:14000/dir\" }
    policy: { mode: none }" /tmp/bad.conf
reload_brain
for i in $(seq 1 100); do [ -n "$(sfield test_error)" ] && break; sleep 0.2; done
[ -n "$(sfield test_error)" ] && ok "nginx -t refused the candidate: $(sfield test_error | cut -c1-70)" || bad "no test error recorded"
[ "$(sfield generation)" = "$GEN_GOOD" ] && ok "the previous generation ($GEN_GOOD) is still live" || bad "generation moved on a refused candidate"
[ "$(sfield healthy)" = "true" ] && [ "$(sfield converged)" = "false" ] && ok "/healthz stays 200 (serving) with converged:false" || bad "health after a refused document: healthy=$(sfield healthy) converged=$(sfield converged)"
[ "$(sfield zones_etag)" = "$ETAG_GOOD" ] && [ "$(sfield accepted_etag)" != "$ETAG_GOOD" ] && ok "rendered ETag stays on the good document; accepted moved on" || bad "etags: rendered=$(sfield zones_etag) accepted=$(sfield accepted_etag)"
code=$(get legit https://$ZONE/still); [ "$code" = "200" ] && ok "requests are still served during the refusal" || bad "serving broke during a refused document (got $code)"
sleep 1.5
[ "$(report_field zones_etag)" = "$ETAG_GOOD" ] && ok "the brain's report names the RENDERED document" || bad "report does not carry the rendered ETag (report: $(report_field zones_etag), rendered: $ETAG_GOOD)"
brain_api "http://$BRAIN:8080/api/v1/edge/nodes" | grep -q 'bogus_directive' && ok "the brain's report carries the tester's message" || bad "test error not reported to the brain"
# Fix it: the next document applies at once (a newer document, not the retry).
zones_yaml 100 "  - name: $ZONE2
    origins: [\"$ORIGIN:8081\"]
    acme: { directory: \"https://$CA:14000/dir\" }
    policy: { mode: none }" ""
reload_brain
wait_status converged true 30 && ok "fixed document converged again" || bad "did not converge after the fix: $(sfield last_error)"

say "ARM F — kill the brain: the node keeps serving, restarts from disk, then re-syncs with a 304"
pkill -f "$KAPKAN -config /tmp/brain.yaml" 2>/dev/null; sleep 1
INSTALLS_BEFORE=$(installs)
code=$(get legit https://$ZONE/nobrain); [ "$code" = "200" ] && ok "served with the brain dead" || bad "not served with the brain dead (got $code)"
codes=$(for i in $(seq 1 20); do get attacker https://$ZONE/nobrain-$i & done; wait)
echo "$codes" | grep -q 200 && ok "decisions are still made locally with the brain dead" || bad "no request decided with the brain dead: $codes"
stop_edge; start_edge
wait_status healthy true 20 && ok "restarted node is serving from disk before the brain is back" || bad "restart with the brain dead did not come back"
[ "$(sfield zones)" = "2" ] && [ "$(get legit https://$ZONE/afterrestart)" = "200" ] && ok "both zones and the certificates came from disk" || bad "disk start lost state"
BRAIN_SEEN=$(sfield brain_seen)
: > /tmp/brain.log; start_brain
for i in $(seq 1 50); do [ "$(sfield brain_seen)" != "$BRAIN_SEEN" ] && break; sleep 0.2; done
[ "$(sfield brain_seen)" != "$BRAIN_SEEN" ] && ok "brain back: the node's poll reaches it again" || bad "node did not see the returned brain"
sleep 1
[ "$(installs)" = "$INSTALLS_BEFORE" ] && ok "re-sync with the unchanged document installed nothing (first poll answered 304)" || bad "re-sync with an unchanged document installed a generation ($INSTALLS_BEFORE -> $(installs))"

say "ARM G — rollups promote a persistent over-rate source to a deny"
zones_yaml 5 "  - name: $ZONE2
    origins: [\"$ORIGIN:8081\"]
    acme: { directory: \"https://$CA:14000/dir\" }
    policy: { mode: none }" ""
reload_brain; sleep 1.5
cat > /tmp/flood.py <<PY
import http.client, ssl, sys, time
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
end = time.time() + float(sys.argv[1]); codes = {}
while time.time() < end:
    try:
        # By NAME (resolved through /etc/hosts to the edge) so the SNI is the
        # zone; an IP would hit the catch-all's ssl_reject_handshake.
        c = http.client.HTTPSConnection("$ZONE", 443, context=ctx, timeout=3)
        c.request("GET", "/flood"); r = c.getresponse(); r.read()
        codes[r.status] = codes.get(r.status, 0) + 1; c.close()
    except Exception as e:
        codes["err"] = codes.get("err", 0) + 1
    time.sleep(0.02)
print(codes)
PY
ip netns exec attacker python3 /tmp/flood.py 16 > /tmp/flood.out 2>&1
cat /tmp/flood.out
grep -q '429' /tmp/flood.out && ok "the attacker was rate-limited during the flood" || bad "flood saw no 429"
sleep 1.5
[ "$(get attacker https://$ZONE/after)" = "403" ] && ok "the attacker is now denied (403): promoted by the flood rule" || bad "attacker not promoted to a deny after the flood: $(get attacker https://$ZONE/after)"
[ "$(get legit https://$ZONE/legit)" = "200" ] && ok "the legit client is untouched" || bad "legit client refused"

say "ARM H — the decision costs single-digit milliseconds"
lat() { ip netns exec legit curl -s -o /dev/null -w '%{time_total}\n' -m5 --cacert /tmp/pebble-root.crt --resolve "$1:443:$EDGE" "https://$1/lat"; }
zones_yaml 1000 "  - name: $ZONE2
    origins: [\"$ORIGIN:8081\"]
    acme: { directory: \"https://$CA:14000/dir\" }
    policy: { mode: none }" ""
reload_brain; sleep 2
for i in $(seq 1 60); do lat $ZONE2; done > /tmp/lat-none.txt
for i in $(seq 1 60); do lat $ZONE; done > /tmp/lat-decide.txt
python3 - <<'PY'
import statistics
n = sorted(float(x) for x in open('/tmp/lat-none.txt'))
d = sorted(float(x) for x in open('/tmp/lat-decide.txt'))
pn, pd = statistics.median(n)*1000, statistics.median(d)*1000
print(f"  p50 mode:none {pn:.2f} ms   p50 mode:decide {pd:.2f} ms   overhead {pd-pn:+.2f} ms")
open('/tmp/lat-overhead.txt','w').write(str(pd-pn))
PY
OVER=$(cat /tmp/lat-overhead.txt)
python3 -c "import sys; sys.exit(0 if float('$OVER') < 5 else 1)" && ok "decision overhead at p50 is under 5 ms ($OVER ms)" || bad "decision overhead too high: $OVER ms"

echo
echo "== E3 acceptance: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
