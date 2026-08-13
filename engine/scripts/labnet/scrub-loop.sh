#!/usr/bin/env bash
#
# The full scrub-node loop, on a real kernel: a kapkan brain detects a flowgen
# attack, escalates to divert toward a managed node, and a real `kapkan scrub`
# agent pulls the ban, attaches XDP to a veth, and installs the drop rules — the
# end-to-end path the network-integration guide's "confirm XDP is attached and
# dropping" step describes.
#
# Unlike plumbing.sh this needs the kapkan binary AND flowinject, cross-compiled
# for the container's architecture. Build them first (from engine/):
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/kapkan     ./cmd/kapkan
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/lab/flowinject ./scripts/flowinject
#   docker run --privileged --rm -v /tmp/lab:/lab -v "$PWD:/w" -w /w debian:12-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq iproute2 curl python3 >/dev/null \
#            && KAPKAN=/lab/kapkan FLOWINJECT=/lab/flowinject bash engine/scripts/labnet/scrub-loop.sh'
#
# The kernel needs BPF/BTF + XDP (CONFIG_BPF_SYSCALL, DEBUG_INFO_BTF, XDP) — the
# linuxkit kernel has them, which is why `make dataplane-test` already runs here.
set -uo pipefail
export PATH=/usr/sbin:/sbin:/usr/bin:/bin
KAPKAN=${KAPKAN:-/lab/kapkan}
FLOWINJECT=${FLOWINJECT:-/lab/flowinject}
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

command -v "$KAPKAN" >/dev/null 2>&1 || [ -x "$KAPKAN" ] || { echo "kapkan binary not found at $KAPKAN"; exit 2; }
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

cat > /tmp/brain.yaml <<'YAML'
dry_run: false
listen: { netflow: "127.0.0.1:2055" }
sampling: { default_rate: 1000 }
networks: ["203.0.113.0/24"]
thresholds: { pps: 80000, mbps: 1000, flows_per_sec: 35000, udp_pps: 50000 }
ban: { ttl_seconds: 600, unban_hysteresis_seconds: 60, max_active_bans: 50 }
flowspec: { action: discard }
scrubbing:
  next_hop: "192.0.2.9"
  nodes: [{ name: scrub1, next_hop: "192.0.2.10" }]
hostgroups:
  - { name: web, networks: ["203.0.113.0/26"], thresholds: { pps: 20000, mbps: 500, flows_per_sec: 10000 }, mitigation: divert }
bgp:
  local_asn: 65010
  router_id: "10.0.0.1"
  next_hop: "192.0.2.1"
  community: "65010:666"
  neighbors: [{ address: "127.0.0.2", remote_asn: 65000 }]
api:
  listen: "127.0.0.1:8080"
  tokens:
    - { name: admin,        token_env: KAPKAN_ADMIN_TOKEN, role: operator }
    - { name: scrub1-agent, token_env: KAPKAN_AGENT_TOKEN, role: agent }
YAML
export KAPKAN_ADMIN_TOKEN=admintok KAPKAN_AGENT_TOKEN=agenttok

"$KAPKAN" -config /tmp/brain.yaml -log-format text -log-level error >/tmp/brain.log 2>&1 &
for i in $(seq 1 30); do curl -s -m1 http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.3; done

echo "== injecting the attack scene, waiting for divert bans with rules =="
"$FLOWINJECT" -target 127.0.0.1:2055 -interval 250ms -duration 12s >/tmp/inject.log 2>&1 &
for i in $(seq 1 20); do
  bans=$(curl -s -H "Authorization: Bearer agenttok" "http://127.0.0.1:8080/api/v1/dataplane/rules?node=scrub1" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print(sum(1 for b in d["bans"] if b.get("flowspec")))' 2>/dev/null || echo 0)
  [ "${bans:-0}" -ge 1 ] && break; sleep 1
done
[ "${bans:-0}" -ge 1 ] && ok "brain serves $bans divert ban(s) WITH FlowSpec rules to the agent" \
                       || bad "no divert ban carried FlowSpec rules (the node would drop nothing)"

echo "== starting a real scrub node: XDP on a veth, polling the brain =="
ip link add dirty0 type veth peer name dirty0p; ip link set dirty0 up; ip link set dirty0p up
cat > /tmp/scrub.yaml <<'YAML'
dry_run: false
controller: { url: "http://127.0.0.1:8080", token_env: KAPKAN_AGENT_TOKEN, name: scrub1, report_interval_seconds: 2 }
dataplane: { interfaces: [dirty0], xdp_mode: generic, pin_path: /sys/fs/bpf/kapkan-scrub }
YAML
"$KAPKAN" scrub -config /tmp/scrub.yaml -log-format text -log-level info >/tmp/scrub.log 2>&1 &
SCRUB=$!
for i in $(seq 1 15); do grep -q "installed rules" /tmp/scrub.log && break; sleep 1; done

grep -q "data plane attached" /tmp/scrub.log && ok "the agent attached XDP to dirty0" || bad "the agent did not attach XDP"
grep -q "installed rules" /tmp/scrub.log     && ok "the agent installed the brain's rules in the kernel" || bad "the agent installed no rules"
dyn=$("$KAPKAN" dataplane status -pin-path /sys/fs/bpf/kapkan-scrub 2>/dev/null | grep -oE 'dynamic *[0-9]+' | grep -oE '[0-9]+' | head -1)
[ "${dyn:-0}" -ge 1 ] && ok "kapkan dataplane status confirms $dyn dynamic rule block(s) live in the kernel" \
                      || bad "dataplane status shows no dynamic rules"
alive=$(curl -s -H "Authorization: Bearer admintok" http://127.0.0.1:8080/api/v1/dataplane/nodes \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["nodes"][0]["alive"])' 2>/dev/null)
[ "$alive" = True ] && ok "the brain sees scrub1 alive (the rules poll is the liveness signal)" \
                    || bad "the brain does not see scrub1 alive"

kill "$SCRUB" 2>/dev/null; pkill -f "$KAPKAN" 2>/dev/null
ip link del dirty0 2>/dev/null
echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
