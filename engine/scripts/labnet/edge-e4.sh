#!/usr/bin/env bash
#
# E4 acceptance, on a real kernel with a real nginx: the proof-of-work rung of
# the edge spec (engine/docs/edge-spec.md §5, §8) — the clearance page, the
# ladder, the zone-wide trigger, the three watch-only layers and the operator's
# lever, on the E3 rig's topology. The arms map to §8 and to the charter:
#
#   A. upgrade renders once, toggles never reload: the clearance machinery is in
#      the rendered configuration for every deciding zone; switching the rung
#      between off/manual/auto moves the accepted ETag and nothing else;
#   B. manual, enforced: a plain client gets the page (403, no cookie); a
#      browser solves the puzzle once, is cleared and reaches the origin marked
#      `cleared`; its cookie is useless from another address; it expires;
#   C. the residential-proxy flood collapses to challenge-passers (§8, 1): 64
#      sources each under the zone's per-source ceiling trip the zone-wide
#      trigger; from the flip on none of them reaches the origin, the browser
#      does, and a plain client without a solver is challenged too — the rung,
#      not an allowlist, is what passes traffic;
#   D. the same flood in dry-run touches nothing (§8, 2): every request reaches
#      the origin marked would-challenge, the status names who would have been
#      challenged, no cookie is set, no generation moves; the node's own dry-run
#      floors the zone's;
#   E. the local ladder: one flooder is rate-limited, then challenged, then
#      denied; a cleared flooder is denied at once;
#   F. no JavaScript: the timed ticket is refused early and clears after 4 s
#      with the shorter `cleared:nojs` mark;
#   G. exempt paths pass without a clearance; a non-GET original gets the JSON
#      refusal, not the page;
#   H. kill the brain mid-challenge: cookies keep verifying, new visitors still
#      clear, the node restarts from disk with its keys, the brain's return is
#      a 304;
#   I. the lever: an operator puts the zone under challenge for a bounded time
#      without a reload; it is audited; clearing puts the document back;
#   J. cost: the challenge answer's p50 against a mode:none 200.
#
# Topology: edge-e3.sh's, plus a `botnet` netns holding 64 addresses
# 198.51.100.64–127 on one interface (real TCP stacks, distinct sources).
#
# Build the binaries for the container arch first (from engine/), then run this
# inside one privileged debian container (never two rigs at once):
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan ./cmd/kapkan
#   git clone --depth 1 https://github.com/letsencrypt/pebble /tmp/pebble-src \
#     && (cd /tmp/pebble-src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/pebble ./cmd/pebble)
#   docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:12-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq \
#              iproute2 nginx openssl curl python3 procps iputils-ping ca-certificates >/dev/null \
#            && KAPKAN=/lab/kapkan PEBBLE=/lab/pebble bash engine/scripts/labnet/edge-e4.sh'
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
  if [ -d /lab ]; then mkdir -p /lab/logs && cp -f /tmp/*.log /tmp/*.out /tmp/*.txt /tmp/hdr-* /lab/logs/ 2>/dev/null; cp -f /tmp/zones.yaml /tmp/edge.yaml /tmp/brain.yaml /lab/logs/ 2>/dev/null; fi
  kill "$(cat /tmp/brain.pid 2>/dev/null)" "$(cat /tmp/edge-nginx.pid 2>/dev/null)" 2>/dev/null
  pkill -f "^$KAPKAN " 2>/dev/null; pkill -f "^$PEBBLE " 2>/dev/null
  pkill -f '^nginx: master' 2>/dev/null; pkill -f '^python3 /tmp/origin.py' 2>/dev/null
  pkill -f '^python3 /tmp/flood.py' 2>/dev/null; pkill -f '^python3 /tmp/botnet.py' 2>/dev/null; pkill -f '^python3 /tmp/browser.py' 2>/dev/null
  for ns in edge brain origin ca legit attacker bursty botnet; do ip netns del "$ns" 2>/dev/null; done
  ip link del br0 2>/dev/null
  sed -i "/ $ZONE\$/d;/ $ZONE2\$/d" /etc/hosts 2>/dev/null
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
add_ns bursty   203.0.113.4  24 203.0.113.1
for i in 5 6 7 8; do ip netns exec bursty ip addr add 203.0.113.$i/24 dev vbursty; done
# The botnet: 64 distinct sources on one interface — the residential-proxy
# flood, where no single address trips its own ceiling.
add_ns botnet 198.51.100.64 24 198.51.100.1
for i in $(seq 65 127); do ip netns exec botnet ip addr add 198.51.100.$i/24 dev vbotnet; done
printf '%s %s\n%s %s\n' "$EDGE" "$ZONE" "$EDGE" "$ZONE2" >> /etc/hosts
ip netns exec legit ping -c1 -W1 $EDGE >/dev/null 2>&1 && ok "legit reaches the edge" || bad "no path legit -> edge (topology broken; nothing below is meaningful)"
ip netns exec botnet ping -c1 -W1 -I 198.51.100.127 $EDGE >/dev/null 2>&1 && ok "the botnet's last alias reaches the edge" || bad "no path botnet -> edge"

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
grep -q newOrder <<< "$(ip netns exec edge curl -sk -m2 https://$CA:14000/dir)" && ok "Pebble directory is up" || bad "Pebble not answering (see /tmp/pebble.log)"

# ---------------------------------------------------------------- the brain
say "starting the brain with the zones file and the edge block"
# zones_yaml CHALLENGE RUNG_DRY ZONE_DRY ZONE_RPS RPS — the rung's knobs the arms
# turn: difficulty 12 (a python solver clears it in milliseconds), the shortest
# cookie life the file admits, /api/ exempt, a 30 s zone-wide hold.
zones_yaml() {
cat > /tmp/zones.yaml <<YAML
zones:
  - name: $ZONE
    origins: ["$ORIGIN:8081"]
    tls: { min_version: "1.2" }
    acme: { directory: "https://$CA:14000/dir" }
    policy:
      mode: decide
      failure_mode: open
      dry_run: $3
      challenge: "$1"
      challenge_options:
        dry_run: $2
        difficulty: 12
        cookie_ttl_seconds: 60
        exempt_paths: ["/api/"]
        auto: { zone_rps: $4, hold_seconds: 30 }
      rate: { rps: $5 }
  - name: $ZONE2
    origins: ["$ORIGIN:8081"]
    acme: { directory: "https://$CA:14000/dir" }
    policy: { mode: none }
YAML
}
zones_yaml off true false 0 5
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
  state_file: /tmp/edge-state.json
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
grep -q clearance_keys <<< "$(ip netns exec brain curl -s -m3 -H "Authorization: Bearer agenttok" "http://$BRAIN:8080/api/v1/edge/zones?node=edge-1")" && ok "the document carries the rung's keys" || bad "no clearance keys in the document"

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
pgrep -f 'nginx: master' >/dev/null && ok "nginx master is up" || bad "nginx did not start (see /tmp/edge-nginx.log)"

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
stop_edge() {
  local t0=$(date +%s%N); pkill -f "^$KAPKAN edge" 2>/dev/null
  for i in $(seq 1 100); do pgrep -f "^$KAPKAN edge" >/dev/null || break; sleep 0.1; done
  pgrep -f "^$KAPKAN edge" >/dev/null && bad "the node did not stop within 10 s of SIGTERM" || echo "  (node stopped in $(( ($(date +%s%N) - t0) / 1000000 )) ms)"
}
status() { ip netns exec edge curl -s -m2 http://127.0.0.1:9102/healthz 2>/dev/null; }
sfield() { status | python3 -c "import json,sys; d=json.load(sys.stdin); v=d.get('$1',''); print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }
wait_status() { local i; for i in $(seq 1 $(( $3 * 5 ))); do [ "$(sfield "$1")" = "$2" ] && return 0; sleep 0.2; done; return 1; }
wait_etag() { # wait until the accepted ETag differs from $1 (a document reached the fast path)
  local i; for i in $(seq 1 100); do [ "$(sfield accepted_etag)" != "$1" ] && return 0; sleep 0.2; done; return 1
}
# get NS URL [curl args...] -> http code
get() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -o /dev/null -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" --resolve "$ZONE2:443:$EDGE" "$@" "$url" 2>/dev/null; }
# getsrc IP URL [curl args...] -> http code, from the bursty netns bound to IP
getsrc() { local ip=$1 url=$2; shift 2; ip netns exec bursty curl -s -o /dev/null -w '%{http_code}' -m5 --interface "$ip" --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" "$@" "$url" 2>/dev/null; }
# body NS URL [curl args...] -> the response body
body() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" "$@" "$url" 2>/dev/null; }
# hdrs NS URL [curl args...] -> the response headers
hdrs() { local ns=$1 url=$2; shift 2; ip netns exec "$ns" curl -s -o /dev/null -D - -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" "$@" "$url" 2>/dev/null; }
alive() { brain_api "http://$BRAIN:8080/api/v1/edge/nodes" | python3 -c "
import json,sys
d=json.load(sys.stdin)
sys.exit(0 if any(n.get('name')=='edge-1' and n.get('alive') is True for n in d.get('nodes',[])) else 1)" 2>/dev/null; }
installs() { grep -c 'configuration installed' /tmp/edge.log; }
metric() { # metric name with labels as a grep pattern -> its value (0 when absent)
  ip netns exec edge curl -s -m2 http://127.0.0.1:9102/metrics 2>/dev/null | grep "^$1" | awk '{s+=$NF} END {print s+0}'
}
# zstatus JSON-PATH -> a field of the brain's GET /api/v1/edge/zones/status for ZONE
zstatus() { brain_api "http://$BRAIN:8080/api/v1/edge/zones/status" | python3 -c "
import json,sys
d=json.load(sys.stdin)
z=[z for z in d.get('zones',[]) if z.get('zone')=='$ZONE']
z=z[0] if z else {}
try:
    v=eval(sys.argv[1], {}, {'z': z, 'd': d, 'len': len, 'all': all, 'sorted': sorted, 'set': set})
except Exception as e:
    v=''
print(v if not isinstance(v,bool) else str(v).lower())" "$1" 2>/dev/null; }
wait_zstatus() { # expr value timeout-seconds
  local i; for i in $(seq 1 $(( $3 * 2 ))); do [ "$(zstatus "$1")" = "$2" ] && return 0; sleep 0.5; done; return 1
}
is_page() { grep -q 'kapkan-puzzle' <<< "$1"; }

# ---------------------------------------------------------------- the clients
# browser.py ZONE PATHPREFIX COUNT INTERVAL COOKIEFILE [BINDIP]: a browser. It
# fetches PATHPREFIX-<n> every INTERVAL seconds; a 403 that carries the puzzle
# is solved (SHA-256 hashcash over nonce+solution, leading zero bits >=
# difficulty), the answer is posted, the 303's cookie is kept in COOKIEFILE and
# sent from then on. Prints a JSON summary.
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
try:
    cookie = open(cookiefile).read().strip()
except OSError:
    pass
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
            else:
                codes["answer-%d" % r2.status] = codes.get("answer-%d" % r2.status, 0) + 1
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
# nojs.py ZONE PATH BINDIP: a client without JavaScript. It reads the ticket
# out of the page, tries it at once (too early), waits, and follows it.
cat > /tmp/nojs.py <<'PY'
import http.client, ssl, sys, time, json, re
zone, path, bind = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
def conn(): return http.client.HTTPSConnection(zone, 443, context=ctx, timeout=5, source_address=(bind, 0))
out = {}
c = conn(); c.request("GET", path); r = c.getresponse(); b = r.read().decode(errors="replace"); c.close()
out["page"] = r.status
m = re.search(r'name="t" value="([^"]+)"', b); t = m.group(1) if m else ""
out["meta_refresh"] = bool(re.search(r'http-equiv="refresh" content="\d+;url=/_kapkan/clearance/nojs\?t=', b))
c = conn(); c.request("GET", "/_kapkan/clearance/nojs?t=" + t); r = c.getresponse(); b = r.read().decode(errors="replace"); c.close()
out["early"] = r.status; out["early_html"] = "text/html" in (r.getheader("Content-Type") or ""); out["early_cookie"] = bool(r.getheader("Set-Cookie"))
time.sleep(4.5)
c = conn(); c.request("GET", "/_kapkan/clearance/nojs?t=" + t); r = c.getresponse(); r.read()
out["redeem"] = r.status; out["location"] = r.getheader("Location") or ""
sc = r.getheader("Set-Cookie") or ""; m2 = re.search(r"kapkan_clr=([^;]+)", sc); c.close()
cookie = m2.group(1) if m2 else ""
out["cookie"] = bool(cookie)
if cookie:
    c = conn(); c.request("GET", path + "?after", headers={"Cookie": "kapkan_clr=" + cookie}); r = c.getresponse(); r.read(); c.close()
    out["after"] = r.status
print(json.dumps(out))
PY
# botnet.py ZONE SECONDS SPLIT: 64 sources at 2 rps each (under the per-source
# ceiling of 5), distinct paths per source. Status histograms before and after
# SPLIT seconds, the Set-Cookie headers seen, the requests made.
cat > /tmp/botnet.py <<'PY'
import http.client, ssl, sys, time, json, threading
zone, secs, split = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
lock = threading.Lock(); before, after, cookies, total = {}, {}, [0], [0]
start = time.time()
def run(ip):
    n = 0
    end = start + secs
    while time.time() < end:
        t0 = time.time(); n += 1
        try:
            c = http.client.HTTPSConnection(zone, 443, context=ctx, timeout=5, source_address=(ip, 0))
            c.request("GET", "/bot/%s/%d" % (ip, n)); r = c.getresponse(); r.read()
            sc = r.getheader("Set-Cookie"); st = r.status; c.close()
        except Exception:
            sc, st = None, "err"
        with lock:
            h = after if time.time() - start >= split else before
            h[st] = h.get(st, 0) + 1; total[0] += 1
            if sc: cookies[0] += 1
        dt = 0.5 - (time.time() - t0)
        if dt > 0: time.sleep(dt)
ts = [threading.Thread(target=run, args=("198.51.100.%d" % i,)) for i in range(64, 128)]
for t in ts: t.start()
for t in ts: t.join()
print(json.dumps({"before": before, "after": after, "set_cookie": cookies[0], "requests": total[0]}))
PY
# flood.py ZONE SECONDS PATH [COOKIE]: one source flooding at ~50 rps; counts
# statuses and tells a challenge page (403 with the puzzle) from a bare 403.
cat > /tmp/flood.py <<'PY'
import http.client, ssl, sys, time, json
zone, secs, path = sys.argv[1], float(sys.argv[2]), sys.argv[3]
cookie = sys.argv[4] if len(sys.argv) > 4 else ""
ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
end = time.time() + secs; codes = {}; last = None
while time.time() < end:
    try:
        c = http.client.HTTPSConnection(zone, 443, context=ctx, timeout=3)
        c.request("GET", path, headers={"Cookie": "kapkan_clr=" + cookie} if cookie else {}); r = c.getresponse(); b = r.read()
        k = "page" if r.status == 403 and b"kapkan-puzzle" in b else str(r.status)
        codes[k] = codes.get(k, 0) + 1; last = k; c.close()
    except Exception:
        codes["err"] = codes.get("err", 0) + 1
    time.sleep(0.02)
print(json.dumps({"codes": codes, "last": last}))
PY
jget() { python3 -c "import json,sys; d=json.load(open('$1')); v=d$2; print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }

# ================================================================ ARM A
say "ARM A — the upgrade renders once; switching the rung never reloads"
: > /tmp/edge.log
edge_yaml false
"$KAPKAN" edge -config /tmp/edge.yaml -check 2>&1 | grep -q 'is valid' && ok "edge.yaml passes -check" || bad "edge.yaml fails -check"
start_edge
wait_status healthy true 30 && ok "node healthy: a tested generation is live" || { bad "node never became healthy (see /tmp/edge.log)"; tail -20 /tmp/edge.log; }
for i in $(seq 1 150); do [ "$(grep -c 'certificate issued' /tmp/edge.log)" -ge 2 ] && break; sleep 0.2; done
[ "$(grep -c 'certificate issued' /tmp/edge.log)" -ge 2 ] && ok "both zones issued by Pebble" || { bad "certificates not issued in 30 s"; grep -i 'acme\|certificate' /tmp/edge.log | tail -5; }
ip netns exec legit curl -sk -m3 https://$CA:15000/roots/0 > /tmp/pebble-root.crt 2>/dev/null
grep -q 'BEGIN CERTIFICATE' /tmp/pebble-root.crt && ok "fetched Pebble's root for the clients" || bad "could not fetch Pebble's root"
wait_status converged true 30 || true
for i in $(seq 1 50); do [ "$(get legit https://$ZONE/hello)" = "200" ] && break; sleep 0.2; done
[ "$(get legit https://$ZONE/hello)" = "200" ] && ok "the zone is served through nginx to the origin" || bad "zone not served over TLS (see /tmp/edge-nginx-error.log)"
grep -q 'kapkan_clearance' $STATE/conf/live/kapkan_zone_$ZONE.conf 2>/dev/null && grep -q '/_kapkan/clearance/' $STATE/conf/live/kapkan_zone_$ZONE.conf && ok "the rendered zone carries the clearance machinery while the rung is off" || bad "no clearance machinery in the rendered zone file"
[ -S $SOCKS/edge-clearance.sock ] && ok "the fourth socket is up" || bad "no clearance socket"
GEN0=$(sfield generation); INST0=$(installs); ET=$(sfield accepted_etag)
zones_yaml manual true false 0 5; reload_brain
wait_etag "$ET" && ok "challenge: manual reached the node (new accepted ETag)" || bad "the rung change never reached the node"
sleep 0.5; ET=$(sfield accepted_etag)
zones_yaml auto true false 40 5; reload_brain
wait_etag "$ET" && ok "challenge: auto reached the node" || bad "the second rung change never reached the node"
sleep 0.5; ET=$(sfield accepted_etag)
zones_yaml off true false 0 5; reload_brain
wait_etag "$ET" && ok "challenge: off reached the node" || bad "the third rung change never reached the node"
[ "$(sfield generation)" = "$GEN0" ] && [ "$(installs)" = "$INST0" ] && ok "three rung changes: generation $GEN0 unchanged, nothing installed — never a reload (§2.2)" || bad "a rung change rendered or reloaded (gen $GEN0 -> $(sfield generation), installs $INST0 -> $(installs))"

# ================================================================ ARM B
say "ARM B — manual, enforced: the page, a browser that clears, a cookie bound to its source"
ET=$(sfield accepted_etag); zones_yaml manual false false 0 5; reload_brain; wait_etag "$ET"; sleep 0.5
: > /tmp/origin.log; rm -f /tmp/hdr-b
code=$(ip netns exec legit curl -s -o /tmp/page-b.html -D /tmp/hdr-b -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" https://$ZONE/shop 2>/dev/null)
[ "$code" = "403" ] && is_page "$(cat /tmp/page-b.html)" && ok "a plain client gets the clearance page (403 with the puzzle)" || bad "plain client got $code without the page"
grep -qi '^cache-control: no-store' /tmp/hdr-b && ok "the page is never cached (Cache-Control: no-store)" || bad "page without Cache-Control: no-store"
grep -qi '^set-cookie' /tmp/hdr-b && bad "the page set a cookie before the puzzle was solved" || ok "no cookie before the puzzle is solved"
grep -qi 'content-security-policy' /tmp/hdr-b && ok "the page carries a CSP" || bad "page without a CSP"
[ "$(grep -c '"path"' /tmp/origin.log)" = "0" ] && ok "nothing reached the origin from the challenged client" || bad "a challenged request reached the origin"
rm -f /tmp/cookie-legit
ip netns exec legit python3 /tmp/browser.py $ZONE /browser 3 0.3 /tmp/cookie-legit > /tmp/browser-b.out 2>&1
cat /tmp/browser-b.out
[ "$(jget /tmp/browser-b.out "['solved']")" = "1" ] && ok "the browser solved the puzzle once and got its cookie (303 + Set-Cookie)" || bad "browser did not clear: $(cat /tmp/browser-b.out)"
[ "$(jget /tmp/browser-b.out "['cleared_gets']")" -ge 2 ] 2>/dev/null && ok "the cleared browser is served on the next requests without another puzzle" || bad "cleared browser not served: $(cat /tmp/browser-b.out)"
grep -q '"mark": "cleared"' /tmp/origin.log && ok "the origin sees X-Kapkan-Mark: cleared" || bad "no cleared mark at the origin: $(tail -2 /tmp/origin.log)"
COOKIE=$(cat /tmp/cookie-legit 2>/dev/null)
code=$(getsrc 203.0.113.5 https://$ZONE/stolen -H "Cookie: kapkan_clr=$COOKIE"); [ "$code" = "403" ] && ok "the cookie is refused from another source address (bound to the source key)" || bad "a cookie from another address was accepted ($code)"
[ "$(get legit https://$ZONE/keep -H "Cookie: kapkan_clr=$COOKIE")" = "200" ] && ok "the same cookie still passes from its own address" || bad "own cookie refused"
ISSUED=$(metric 'kapkan_edge_clearance_total{.*result="issued"'); [ "$ISSUED" -ge 1 ] 2>/dev/null && ok "kapkan_edge_clearance_total{result=\"issued\"} counted the clearance ($ISSUED)" || bad "no issued clearance in the metrics"
COOKIE_T0=$(date +%s)

# ================================================================ ARM C
say "ARM C — the residential-proxy flood collapses to challenge-passers (§8)"
ET=$(sfield accepted_etag); zones_yaml auto false false 40 5; reload_brain; wait_etag "$ET"; sleep 0.5
: > /tmp/origin.log
NGX_ERR0=$(wc -l < /tmp/edge-nginx-error.log)
ip netns exec botnet python3 /tmp/botnet.py $ZONE 30 15 > /tmp/botnet-c.out 2>&1 &
BOTPID=$!
rm -f /tmp/cookie-browser-c
ip netns exec bursty python3 /tmp/browser.py $ZONE /browser-c 28 1 /tmp/cookie-browser-c 203.0.113.6 > /tmp/browser-c.out 2>&1 &
BRPID=$!
# The flip should come within one or two ten-second windows.
wait_zstatus "len(z.get('challenge_active',[]))" 1 20 && ok "zone-wide challenge in force within two windows (status: challenge_active)" || bad "no zone-wide challenge after 20 s: $(brain_api http://$BRAIN:8080/api/v1/edge/zones/status | cut -c1-300)"
[ "$(zstatus "z.get('challenge_active',[{}])[0].get('reason','')")" = "zone-rps" ] && ok "its reason is zone-rps" || bad "reason: $(zstatus "z.get('challenge_active',[{}])[0].get('reason','')")"
[ "$(zstatus "z.get('challenge_active',[{}])[0].get('dry_run',False)")" = "false" ] && ok "the flip bites (dry_run false on the node)" || bad "the flip previews: $(zstatus "z.get('challenge_active',[{}])[0]")"
[ "$(metric 'kapkan_edge_challenge_active{')" = "1" ] && ok "kapkan_edge_challenge_active is 1 on the node" || bad "gauge: $(metric 'kapkan_edge_challenge_active{')"
FLIP_T=$(date +%s); : > /tmp/origin-after-flip.marker; sleep 1
: > /tmp/origin.log   # from here on: who reaches the origin under the flip
code=$(get legit https://$ZONE/plain); [ "$code" = "403" ] && is_page "$(body legit https://$ZONE/plain2)" && ok "a plain client without a solver is challenged under the flip (the rung, not an allowlist, passes traffic)" || bad "plain client under the flip: $code"
wait $BOTPID; wait $BRPID
echo "  botnet: $(cat /tmp/botnet-c.out)"; echo "  browser: $(cat /tmp/browser-c.out)"
BOTS=$(grep -c '"path": "/bot/' /tmp/origin.log); [ "$BOTS" = "0" ] && ok "from the flip on, no botnet request reached the origin" || bad "$BOTS botnet requests reached the origin under the flip"
BRW=$(grep -c '"path": "/browser-c' /tmp/origin.log); [ "$BRW" -ge 10 ] && ok "the browser kept reaching the origin under the flip ($BRW requests, cleared)" || bad "the browser was walled out too ($BRW requests reached)"
python3 - <<'PY' && ok "the botnet's own view: >= 95% of its requests after the flip were refused (403 page)" || bad "botnet after-flip histogram: $(jget /tmp/botnet-c.out "['after']")"
import json
d = json.load(open('/tmp/botnet-c.out')); a = d['after']; tot = sum(a.values()); refused = a.get('403', 0)
raise SystemExit(0 if tot > 0 and refused / tot >= 0.95 else 1)
PY
[ "$(jget /tmp/botnet-c.out "['set_cookie']")" = "0" ] && ok "no cookie was ever set for a bot (it never solved)" || bad "bots received cookies: $(jget /tmp/botnet-c.out "['set_cookie']")"
CH=$(metric 'kapkan_edge_decisions_total{.*result="challenge"'); [ "$CH" -ge 500 ] 2>/dev/null && ok "kapkan_edge_decisions_total{result=\"challenge\"} counts the refused flood ($CH)" || bad "challenge decisions: $CH"
[ "$(sfield generation)" = "$GEN0" ] && ok "the flip and the flood moved no generation ($GEN0)" || bad "generation moved during the flood"
sleep 1.5
[ "$(zstatus "z.get('challenged',0) > 0")" = "true" ] && ok "the fleet status sums the challenged requests" || bad "status shows no challenged requests: $(zstatus "z")"

# ================================================================ ARM B (tail) — the cookie expires
say "ARM B (tail) — the clearance expires after cookie_ttl_seconds"
NOW=$(date +%s); WAIT=$(( COOKIE_T0 + 62 - NOW )); [ "$WAIT" -gt 0 ] && sleep $WAIT
# The zone is still under the flip (30 s hold from the last window over) or
# back to auto without one; either way a cookie past its life is a plain client.
code=$(get legit https://$ZONE/expired -H "Cookie: kapkan_clr=$COOKIE")
if [ "$code" = "403" ]; then ok "an expired cookie is refused (403) after cookie_ttl_seconds"; else
  # No flip live and auto mode: a plain client is allowed — prove expiry through
  # the mark instead: an expired cookie earns no `cleared`.
  : > /tmp/origin.log; get legit https://$ZONE/expired2 -H "Cookie: kapkan_clr=$COOKIE" >/dev/null
  grep -q '"mark": "cleared"' /tmp/origin.log && bad "an expired cookie still clears" || ok "an expired cookie no longer clears (no cleared mark at the origin)"
fi

# ================================================================ ARM D
say "ARM D — the same flood in dry-run touches nothing (§8): who would have been challenged"
# Let the flip lapse first (30 s hold), so the dry-run run flips afresh.
for i in $(seq 1 90); do [ "$(zstatus "len(z.get('challenge_active',[]))")" = "0" ] && break; sleep 1; done
[ "$(zstatus "len(z.get('challenge_active',[]))")" = "0" ] && ok "the zone-wide challenge lapsed on its own (hold_seconds)" || bad "the flip did not lapse within 90 s"
ET=$(sfield accepted_etag); zones_yaml auto true false 40 5; reload_brain; wait_etag "$ET"; sleep 0.5
: > /tmp/origin.log; GEN_D=$(sfield generation); INST_D=$(installs); NGX_ERR0=$(wc -l < /tmp/edge-nginx-error.log)
CLR0=$(metric 'kapkan_edge_clearance_total{')
ip netns exec botnet python3 /tmp/botnet.py $ZONE 25 12 > /tmp/botnet-d.out 2>&1 &
BOTPID=$!
wait_zstatus "len(z.get('challenge_active',[]))" 1 20 && ok "the trigger flips the zone in dry-run too (the preview shows the flip enforcement would make)" || bad "no flip in dry-run"
[ "$(zstatus "z.get('challenge_active',[{}])[0].get('dry_run',False)")" = "true" ] && ok "the status says the flip previews (dry_run: true)" || bad "flip not marked as a preview"
wait $BOTPID; echo "  botnet: $(cat /tmp/botnet-d.out)"
REQ=$(jget /tmp/botnet-d.out "['requests']"); REACHED=$(grep -c '"path": "/bot/' /tmp/origin.log)
[ "$REACHED" = "$REQ" ] && ok "every botnet request reached the origin ($REQ of $REQ)" || bad "$REACHED of $REQ botnet requests reached the origin in dry-run"
grep -q '"mark": "would-challenge:zone:zone-rps"' /tmp/origin.log && ok "they were marked would-challenge:zone:zone-rps" || bad "no would-challenge:zone mark at the origin: $(grep -o '"mark": "[^"]*"' /tmp/origin.log | sort | uniq -c | head -3)"
python3 - <<'PY' && ok "the botnet saw only 200s and no cookie" || bad "dry-run botnet histogram: $(cat /tmp/botnet-d.out)"
import json
d = json.load(open('/tmp/botnet-d.out')); h = {**d['before'], **d['after']}
raise SystemExit(0 if set(map(str, h)) <= {"200"} and d['set_cookie'] == 0 else 1)
PY
sleep 1.5
WB=$(zstatus "len(z.get('would_be',[]))"); WC=$(zstatus "z.get('would_challenge',0)")
[ "$WB" -ge 20 ] 2>/dev/null && [ "$(zstatus "z.get('partial',False)")" = "true" ] && ok "the status names the would-be set (20 per node, the bound) and says it is partial — the flood is bigger than the list" || bad "would-be set: $WB names, partial=$(zstatus "z.get('partial',False)") (would_challenge=$WC)"
[ "$(zstatus "all(s.get('state')=='would-challenge' for s in z.get('would_be',[]))")" = "true" ] && ok "every named source is a would-challenge" || bad "states in the would-be set: $(zstatus "sorted(set(s.get('state') for s in z.get('would_be',[])))")"
[ "$(zstatus "len(z.get('rung_watch_only',[]))")" = "1" ] && ok "the status names the node as rung-watch-only" || bad "rung_watch_only: $(zstatus "z.get('rung_watch_only')")"
[ "$(sfield generation)" = "$GEN_D" ] && [ "$(installs)" = "$INST_D" ] && ok "no generation, no install during the dry-run flood" || bad "dry-run flood rendered or reloaded"
[ "$(metric 'kapkan_edge_clearance_total{')" = "$CLR0" ] && ok "the clearance page served nothing (kapkan_edge_clearance_total unchanged)" || bad "clearance page served in dry-run"
[ "$(wc -l < /tmp/edge-nginx-error.log)" = "$NGX_ERR0" ] && ok "nginx's error log has no new lines" || { bad "nginx error log grew"; tail -3 /tmp/edge-nginx-error.log; }
# The node's own dry-run floors the zone's: the rung set live in the file still
# previews on a watch-only node.
say "ARM D (tail) — the node's dry-run floors the zone's"
for i in $(seq 1 90); do [ "$(zstatus "len(z.get('challenge_active',[]))")" = "0" ] && break; sleep 1; done
stop_edge; edge_yaml true; start_edge; wait_status healthy true 30 || bad "watch-only node did not come back"
ET=$(sfield accepted_etag); zones_yaml auto false false 40 5; reload_brain; wait_etag "$ET"; sleep 0.5
: > /tmp/origin.log
ip netns exec botnet python3 /tmp/botnet.py $ZONE 20 10 > /tmp/botnet-d2.out 2>&1
echo "  botnet: $(cat /tmp/botnet-d2.out)"
python3 - <<'PY' && ok "with the node in dry-run the enforcing zone still refused nothing" || bad "watch-only node refused: $(cat /tmp/botnet-d2.out)"
import json
d = json.load(open('/tmp/botnet-d2.out')); h = {**d['before'], **d['after']}
raise SystemExit(0 if set(map(str, h)) <= {"200"} and d['set_cookie'] == 0 else 1)
PY
grep -q '"mark": "would-challenge:zone:zone-rps"' /tmp/origin.log && ok "and marked the flood would-challenge (the node floor wins)" || bad "no would-challenge mark under the node's dry-run"
[ "$(zstatus "len(z.get('watch_only',[]))")" = "1" ] && ok "the status names the node as watch-only" || bad "watch_only: $(zstatus "z.get('watch_only')")"
stop_edge; edge_yaml false; start_edge; wait_status healthy true 30 || bad "live node did not come back"
for i in $(seq 1 90); do [ "$(zstatus "len(z.get('challenge_active',[]))")" = "0" ] && break; sleep 1; done

# ================================================================ ARM E
say "ARM E — the local ladder: ceiling, rung, block"
ET=$(sfield accepted_etag); zones_yaml auto false false 0 5; reload_brain; wait_etag "$ET"; sleep 1
# The node restarted in arm D, so its counters start afresh here.
CH=$(metric 'kapkan_edge_decisions_total{.*result="challenge"')
ip netns exec attacker python3 /tmp/flood.py $ZONE 11 /flood > /tmp/flood-e1.out 2>&1
echo "  attacker, window 1: $(cat /tmp/flood-e1.out)"
grep -q '"429"' /tmp/flood-e1.out && ok "the flooder was rate-limited (429) in its first window" || bad "no 429 in the first window"
sleep 1.5
ip netns exec attacker python3 /tmp/flood.py $ZONE 11 /flood > /tmp/flood-e2.out 2>&1
echo "  attacker, window 2: $(cat /tmp/flood-e2.out)"
grep -q '"page"' /tmp/flood-e2.out && ok "after one window the flooder is challenged: the page instead of 429s (table:flood)" || bad "flooder not challenged in the second window"
[ "$(metric 'kapkan_edge_decisions_total{.*result="challenge"')" -gt "$CH" ] 2>/dev/null && ok "challenge decisions grew for the single flooder" || bad "no challenge decisions for the flooder"
sleep 1.5
ip netns exec attacker python3 /tmp/flood.py $ZONE 11 /flood > /tmp/flood-e3.out 2>&1
echo "  attacker, window 3: $(cat /tmp/flood-e3.out)"
[ "$(jget /tmp/flood-e3.out "['last']")" = "403" ] && ok "flooding on while challenged, the flooder is denied (a bare 403, no page)" || bad "flooder not denied after flooding through the rung: $(cat /tmp/flood-e3.out)"
[ "$(get legit https://$ZONE/legit-e -H "Cookie: kapkan_clr=$(cat /tmp/cookie-legit)")" != "429" ] && ok "the legit client is untouched by the ladder" || bad "legit client hit by the flooder's ladder"
# A cleared flooder is denied at once — no second rung. From .7 (untouched so
# far): flood until challenged, solve the puzzle when the page comes, then
# flood on with the cookie: the next window's verdict is a deny, not a page.
ip netns exec bursty python3 - <<PY > /tmp/cleared-flood.out 2>&1
import http.client, ssl, time, json, re, hashlib, urllib.parse
zone="$ZONE"; ctx = ssl.create_default_context(cafile="/tmp/pebble-root.crt")
def conn(): return http.client.HTTPSConnection(zone, 443, context=ctx, timeout=3, source_address=("203.0.113.7", 0))
def bits(nonce, sol):
    h = hashlib.sha256((nonce + sol).encode()).digest(); return 256 - int.from_bytes(h, "big").bit_length()
cookie=""; phases=[]
def flood(secs, tag):
    global cookie
    end=time.time()+secs; codes={}
    while time.time()<end:
        try:
            c=conn(); c.request("GET","/cf", headers={"Cookie":"kapkan_clr="+cookie} if cookie else {}); r=c.getresponse(); b=r.read()
            k="page" if r.status==403 and b"kapkan-puzzle" in b else str(r.status); codes[k]=codes.get(k,0)+1; c.close()
            if k=="page" and not cookie:
                p=json.loads(re.search(r'id="kapkan-puzzle">(.*?)</script>', b.decode(), re.S).group(1)); i=0
                while bits(p["nonce"], str(i)) < p["difficulty"]: i+=1
                c2=conn(); c2.request("POST","/_kapkan/clearance/answer", body=urllib.parse.urlencode({"nonce":p["nonce"],"solution":str(i),"return":p["return"]}), headers={"Content-Type":"application/x-www-form-urlencoded"})
                r2=c2.getresponse(); r2.read(); m=re.search(r"kapkan_clr=([^;]+)", r2.getheader("Set-Cookie") or "")
                if m: cookie=m.group(1); codes["solved"]=codes.get("solved",0)+1
                c2.close()
        except Exception: codes["err"]=codes.get("err",0)+1
        time.sleep(0.02)
    phases.append({tag: codes})
flood(11,"w1"); time.sleep(1.5); flood(11,"w2"); time.sleep(1.5); flood(11,"w3")
print(json.dumps({"phases":phases,"cookie":bool(cookie)}))
PY
echo "  cleared flooder: $(cat /tmp/cleared-flood.out)"
python3 - <<'PY' && ok "a flooder that cleared the rung and floods on is denied directly (bare 403s follow the clearance)" || bad "cleared flooder was not denied: $(cat /tmp/cleared-flood.out)"
import json
d = json.load(open('/tmp/cleared-flood.out')); ph = d['phases']
solved = any('solved' in list(p.values())[0] for p in ph)
last = list(ph[-1].values())[0]
raise SystemExit(0 if solved and last.get('403', 0) > 0 and last.get('page', 0) == 0 else 1)
PY

# ================================================================ ARM F
say "ARM F — no JavaScript: the timed ticket"
ET=$(sfield accepted_etag); zones_yaml manual false false 0 5; reload_brain; wait_etag "$ET"; sleep 0.5
: > /tmp/origin.log
ip netns exec bursty python3 /tmp/nojs.py $ZONE /nojs 203.0.113.8 > /tmp/nojs.out 2>&1
echo "  nojs: $(cat /tmp/nojs.out)"
[ "$(jget /tmp/nojs.out "['meta_refresh']")" = "true" ] && ok "the page carries the <noscript> meta refresh to the ticket" || bad "no meta refresh in the page"
[ "$(jget /tmp/nojs.out "['early']")" = "403" ] && [ "$(jget /tmp/nojs.out "['early_cookie']")" = "false" ] && [ "$(jget /tmp/nojs.out "['early_html']")" = "true" ] && ok "a ticket redeemed too early is refused with a page (no cookie)" || bad "early ticket: $(cat /tmp/nojs.out)"
[ "$(jget /tmp/nojs.out "['redeem']")" = "303" ] && [ "$(jget /tmp/nojs.out "['cookie']")" = "true" ] && ok "after 4 s the ticket clears: 303 with the cookie" || bad "ticket not redeemed: $(cat /tmp/nojs.out)"
[ "$(jget /tmp/nojs.out "['location']")" = "/nojs" ] && ok "the 303 sends the visitor back where it came from" || bad "location: $(jget /tmp/nojs.out "['location']")"
[ "$(jget /tmp/nojs.out "['after']")" = "200" ] && grep -q '"mark": "cleared:nojs"' /tmp/origin.log && ok "the no-JS clearance reaches the origin marked cleared:nojs" || bad "no cleared:nojs at the origin"
[ "$(metric 'kapkan_edge_clearance_total{.*result="issued_nojs"')" -ge 1 ] 2>/dev/null && ok "kapkan_edge_clearance_total{result=\"issued_nojs\"} counted it" || bad "no issued_nojs in the metrics"

# ================================================================ ARM G
say "ARM G — exempt paths and non-browser clients"
: > /tmp/origin.log
[ "$(get legit https://$ZONE/api/ping)" = "200" ] && ok "an exempt path passes without a clearance" || bad "exempt path challenged"
grep -q '"path": "/api/ping"' /tmp/origin.log && ok "and reaches the origin" || bad "exempt request did not reach the origin"
[ "$(get legit https://$ZONE/api/../admin --path-as-is)" = "403" ] && ok "a dot-segment escape from the exempt prefix is challenged" || bad "/api/../admin passed"
rm -f /tmp/hdr-g; code=$(ip netns exec legit curl -s -o /tmp/body-g -D /tmp/hdr-g -w '%{http_code}' -m5 --cacert /tmp/pebble-root.crt --resolve "$ZONE:443:$EDGE" -X POST -d 'x=1' https://$ZONE/form 2>/dev/null)
[ "$code" = "403" ] && grep -q 'challenge_required' /tmp/body-g && grep -qi 'content-type: application/json' /tmp/hdr-g && ok "a POST without a clearance gets the compact JSON refusal, not the page" || bad "POST under challenge: $code $(head -c 120 /tmp/body-g)"
[ "$(metric 'kapkan_edge_clearance_total{.*result="page_json"')" -ge 1 ] 2>/dev/null && ok "counted as page_json" || bad "no page_json in the metrics"

# ================================================================ ARM H
say "ARM H — kill the brain mid-challenge: cookies keep verifying, new visitors clear, the node restarts with its keys"
rm -f /tmp/cookie-h
ip netns exec bursty python3 /tmp/browser.py $ZONE /pre-h 2 0.2 /tmp/cookie-h 203.0.113.5 > /tmp/browser-h0.out 2>&1
COOKIE_H=$(cat /tmp/cookie-h 2>/dev/null); [ -n "$COOKIE_H" ] && ok "a browser cleared before the brain died" || bad "browser could not clear: $(cat /tmp/browser-h0.out)"
# zone_keys -> the document's clearance keys for ZONE, canonicalised
zone_keys() { ip netns exec brain curl -s -m3 -H "Authorization: Bearer agenttok" "http://$BRAIN:8080/api/v1/edge/zones" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for z in d.get('zones',[]):
    if z.get('name')=='$ZONE': print(json.dumps(z.get('clearance_keys'), sort_keys=True))" 2>/dev/null; }
KEYS_BEFORE=$(zone_keys)
kill_brain() { kill "$(cat /tmp/brain.pid 2>/dev/null)" 2>/dev/null; for i in $(seq 1 30); do ip netns exec brain curl -s -m1 "http://$BRAIN:8080/healthz" >/dev/null 2>&1 || return 0; sleep 0.2; done; return 1; }
kill_brain && ok "the brain is dead" || bad "the brain is still answering"
[ "$(getsrc 203.0.113.5 https://$ZONE/nobrain -H "Cookie: kapkan_clr=$COOKIE_H")" = "200" ] && ok "the cookie still verifies with the brain dead (cached keys)" || bad "cookie refused with the brain dead"
[ "$(get legit https://$ZONE/nobrain-plain)" = "403" ] && ok "a plain client is still challenged with the brain dead" || bad "no challenge with the brain dead"
rm -f /tmp/cookie-h2
ip netns exec bursty python3 /tmp/browser.py $ZONE /new-h 2 0.2 /tmp/cookie-h2 203.0.113.6 > /tmp/browser-h1.out 2>&1
[ "$(jget /tmp/browser-h1.out "['solved']")" = "1" ] && ok "a new visitor clears with the brain dead (the node signs with the document's keys)" || bad "new visitor could not clear with the brain dead: $(cat /tmp/browser-h1.out)"
INST_H=$(installs)
stop_edge; start_edge
wait_status healthy true 20 && ok "the node restarted from disk with the brain still dead" || bad "restart with the brain dead did not come back"
[ "$(getsrc 203.0.113.5 https://$ZONE/afterrestart -H "Cookie: kapkan_clr=$COOKIE_H")" = "200" ] && ok "the cookie issued before the restart still verifies (keys came from the cached document)" || bad "cookie refused after the node's restart"
AE=$(sfield accepted_etag); BRAIN_SEEN=$(sfield brain_seen)
mv /tmp/brain.log /tmp/brain-1.log; start_brain
for i in $(seq 1 100); do [ "$(sfield brain_seen)" != "$BRAIN_SEEN" ] && break; sleep 0.3; done
[ "$(sfield brain_seen)" != "$BRAIN_SEEN" ] && ok "brain back: the node's poll reaches it again" || bad "node did not see the returned brain"
sleep 1
# The ETag may move (the restarted brain forgets fanned-out ACME challenges the
# cached document still carries — E3 arm F); the KEYS must not: they are
# persisted in edge.state_file, so nobody solves again.
[ -n "$KEYS_BEFORE" ] && [ "$(zone_keys)" = "$KEYS_BEFORE" ] && ok "the returned brain serves the same clearance keys (persisted in edge.state_file): no re-key, nobody solves again" || bad "the brain re-keyed on restart (keys before: ${KEYS_BEFORE:0:60}… after: $(zone_keys | cut -c1-60)…)"
[ "$(installs)" = "$INST_H" ] && ok "nothing was installed across the brain's death and return" || bad "an install happened ($INST_H -> $(installs))"
[ "$(getsrc 203.0.113.5 https://$ZONE/afterbrain -H "Cookie: kapkan_clr=$COOKIE_H")" = "200" ] && ok "the cookie is still good after the brain's return" || bad "cookie refused after the brain returned"

# ================================================================ ARM I
say "ARM I — the operator's lever"
ET=$(sfield accepted_etag); zones_yaml off false false 0 5; reload_brain; wait_etag "$ET"; sleep 0.5
[ "$(get legit https://$ZONE/off)" = "200" ] && ok "with the rung off a plain client is served" || bad "rung off, client refused"
GEN_I=$(sfield generation); INST_I=$(installs); ET=$(sfield accepted_etag)
resp=$(brain_api -X POST -H 'Content-Type: application/json' -d '{"mode":"manual","ttl_seconds":60,"reason":"rig arm I"}' "http://$BRAIN:8080/api/v1/edge/zones/$ZONE/challenge")
grep -q '"mode": *"manual"' <<< "$resp" && grep -q '"file_mode": *"off"' <<< "$resp" && ok "POST …/challenge set a manual lever over an off file (response says both)" || bad "lever response: $resp"
grep -q '"name": *"edge-1"' <<< "$resp" && grep -q '"alive": *true' <<< "$resp" && ok "the response lists the node as alive and enforcing" || bad "nodes in the lever response: $resp"
wait_etag "$ET" && ok "the lever reached the node (new accepted ETag)" || bad "the lever never reached the node"
sleep 0.5
code=$(get legit https://$ZONE/lever); [ "$code" = "403" ] && is_page "$(body legit https://$ZONE/lever2)" && ok "the node challenges every plain request under the lever" || bad "no challenge under the lever ($code)"
[ "$(sfield generation)" = "$GEN_I" ] && [ "$(installs)" = "$INST_I" ] && ok "the lever reloaded nothing" || bad "the lever rendered or reloaded"
grep -q 'audit.*action=edge_challenge.*result=set' /tmp/brain.log && ok "the lever is audited (edge_challenge set)" || bad "no audit line for the lever"
sleep 1.5
[ "$(zstatus "z.get('override',{}).get('mode','')")" = "manual" ] && ok "GET /api/v1/edge/zones/status shows the override" || bad "no override in the status: $(zstatus "z.get('override')")"
[ "$(zstatus "z.get('challenge','')")" = "manual" ] && ok "and the zone's mode as the node applies it (manual)" || bad "status mode under the lever: $(zstatus "z.get('challenge','')")"
ET=$(sfield accepted_etag)
code=$(brain_api -o /dev/null -w '%{http_code}' -X DELETE "http://$BRAIN:8080/api/v1/edge/zones/$ZONE/challenge"); [ "$code" = "200" ] && ok "DELETE clears the lever" || bad "DELETE: $code"
wait_etag "$ET" && ok "the clear reached the node" || bad "the clear never reached the node"
sleep 0.5
[ "$(get legit https://$ZONE/afterlever)" = "200" ] && ok "the zone follows its file again (off): served" || bad "still challenged after the clear"
grep -q 'audit.*action=edge_challenge.*result=cleared' /tmp/brain.log && ok "the clear is audited" || bad "no audit line for the clear"
code=$(brain_api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"mode":"manual","ttl_seconds":5}' "http://$BRAIN:8080/api/v1/edge/zones/$ZONE/challenge"); [ "$code" = "400" ] && ok "a TTL under 60 s is refused (400)" || bad "short TTL accepted: $code"
code=$(brain_api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"mode":"manual","ttl_seconds":600}' "http://$BRAIN:8080/api/v1/edge/zones/$ZONE2/challenge"); [ "$code" = "409" ] && ok "a lever on a mode:none zone is refused (409)" || bad "lever on a none zone: $code"

# ================================================================ ARM J
say "ARM J — the challenge answer costs little"
ET=$(sfield accepted_etag); zones_yaml manual false false 0 1000; reload_brain; wait_etag "$ET"; sleep 1
lat() { ip netns exec legit curl -s -o /dev/null -w '%{time_total}\n' -m5 --cacert /tmp/pebble-root.crt --resolve "$1:443:$EDGE" "https://$1/lat"; }
for i in $(seq 1 60); do lat $ZONE2; done > /tmp/lat-none.txt
for i in $(seq 1 60); do lat $ZONE; done > /tmp/lat-page.txt
python3 - <<'PY'
import statistics
n = sorted(float(x) for x in open('/tmp/lat-none.txt'))
d = sorted(float(x) for x in open('/tmp/lat-page.txt'))
pn, pd = statistics.median(n)*1000, statistics.median(d)*1000
print(f"  p50 mode:none 200 {pn:.2f} ms   p50 challenge page 403 {pd:.2f} ms   overhead {pd-pn:+.2f} ms")
open('/tmp/lat-overhead.txt','w').write(str(pd-pn))
PY
OVER=$(cat /tmp/lat-overhead.txt)
python3 -c "import sys; sys.exit(0 if float('$OVER') < 10 else 1)" && ok "the challenge page adds under 10 ms at p50 ($OVER ms)" || bad "challenge page overhead too high: $OVER ms"

echo
echo "== E4 acceptance: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
