#!/usr/bin/env bash
#
# The network-integration lab: every plumbing recipe in https://kapkan.io/docs/
# network-integration, executed for real so the guide never documents a command that
# was not run. Each recipe builds a throwaway network-namespace topology inside
# ONE privileged container, asserts the outcome, and tears it down.
#
#   docker run --privileged --rm -v "$PWD:/w" -w /w debian:12-slim \
#     sh -c 'apt-get update -qq && apt-get install -y -qq iproute2 iptables \
#            iputils-ping curl python3 procps >/dev/null && bash engine/scripts/labnet/plumbing.sh'
#
# It needs a kernel with GRE/IPIP, netfilter TCPMSS and policy routing — the
# Docker Desktop linuxkit kernel (6.12) has all three. It does NOT need kapkan;
# the full attack→divert→scrub→drop loop with real XDP lives in scrub-loop.sh,
# which needs the kapkan binary too.
#
# VRF: the return-path recipe is verified here with POLICY ROUTING (route-
# leaking, `ip rule` + a dedicated table), the portable form that works on every
# kernel with CONFIG_IP_MULTIPLE_TABLES. The VRF-device form is the same
# isolation on kernels built with CONFIG_NET_VRF; the guide presents it as a
# variant, not a separately-lab-run transcript, because linuxkit ships no VRF.
set -uo pipefail
export PATH=/usr/sbin:/sbin:/usr/bin:/bin

PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
title(){ echo; echo "== $1 =="; }
veth(){ ip link add "$1" type veth peer name "$2"; ip link set "$1" netns "$3"; ip link set "$2" netns "$4"; }
nsclean(){ for n in "$@"; do ip netns del "$n" 2>/dev/null; done; }

# ---------------------------------------------------------------------------
# Recipe 1 — GRE diversion with MSS clamping, and the failure signature.
#
# The single most common scrub-node incident: a tunnel shrinks the path MTU, the
# "packet too big" ICMP that would fix it is filtered somewhere, and the result
# is that TCP HANDSHAKES COMPLETE while any large response STALLS. Clamping the
# MSS at the tunnel routers is the fix.
# ---------------------------------------------------------------------------
recipe_gre_mss() {
  title "GRE diversion + MSS clamp (with the failure signature)"
  nsclean cli rA rB srv
  for n in cli rA rB srv; do ip netns add "$n"; ip -n "$n" link set lo up; done
  veth cli-rA rA-cli cli rA; veth rA-rB rB-rA rA rB; veth rB-srv srv-rB rB srv
  ip -n cli addr add 10.0.1.2/24 dev cli-rA; ip -n cli link set cli-rA up
  ip -n rA  addr add 10.0.1.1/24 dev rA-cli; ip -n rA  link set rA-cli up
  ip -n rA  addr add 10.0.2.1/24 dev rA-rB;  ip -n rA  link set rA-rB up
  ip -n rB  addr add 10.0.2.2/24 dev rB-rA;  ip -n rB  link set rB-rA up
  ip -n rB  addr add 10.0.3.1/24 dev rB-srv; ip -n rB  link set rB-srv up
  ip -n srv addr add 10.0.3.2/24 dev srv-rB; ip -n srv link set srv-rB up
  for n in rA rB; do ip netns exec "$n" sysctl -qw net.ipv4.ip_forward=1; done
  ip -n rA tunnel add gre1 mode gre remote 10.0.2.2 local 10.0.2.1 ttl 255
  ip -n rB tunnel add gre1 mode gre remote 10.0.2.1 local 10.0.2.2 ttl 255
  ip -n rA link set gre1 mtu 1400; ip -n rB link set gre1 mtu 1400
  ip -n rA addr add 10.9.0.1/30 dev gre1; ip -n rA link set gre1 up
  ip -n rB addr add 10.9.0.2/30 dev gre1; ip -n rB link set gre1 up
  ip -n rA route add 10.0.3.0/24 via 10.9.0.2 dev gre1
  ip -n rB route add 10.0.1.0/24 via 10.9.0.1 dev gre1
  ip -n cli route add default via 10.0.1.1
  ip -n srv route add default via 10.0.3.1
  # The realistic PMTUD black hole: each router's own "packet too big" ICMP is
  # filtered (OUTPUT chain — it is locally generated, not forwarded).
  for n in rA rB; do ip netns exec "$n" iptables -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP; done
  ip netns exec srv bash -c 'head -c 4000000 /dev/urandom >/tmp/big.bin; cd /tmp; python3 -m http.server 8080 >/dev/null 2>&1 &'
  sleep 1
  ip netns exec cli curl -s -m5 -o /dev/null http://10.0.3.2:8080/ \
    && ok "small request completes through the tunnel" || bad "small request failed"
  local n
  n=$(ip netns exec cli curl -s -m6 -o /dev/null -w '%{size_download}' http://10.0.3.2:8080/big.bin 2>/dev/null || echo 0)
  [ "${n:-0}" -lt 4000000 ] && ok "WITHOUT clamp: large response stalls (got ${n:-0}/4000000 B — the signature)" \
                            || bad "large response unexpectedly completed without a clamp"
  for n in rA rB; do
    ip netns exec "$n" iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o gre1 -j TCPMSS --clamp-mss-to-pmtu
    ip netns exec "$n" iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -i gre1 -j TCPMSS --clamp-mss-to-pmtu
  done
  n=$(ip netns exec cli curl -s -m8 -o /dev/null -w '%{size_download}' http://10.0.3.2:8080/big.bin 2>/dev/null || echo 0)
  [ "${n:-0}" -eq 4000000 ] && ok "WITH clamp: the same large response completes (${n} B)" \
                            || bad "large response still stalls after the clamp (got ${n:-0} B)"
  nsclean cli rA rB srv
}

# ---------------------------------------------------------------------------
# Recipe 2 — IPIP diversion (20-byte overhead vs GRE's 24).
# ---------------------------------------------------------------------------
recipe_ipip() {
  title "IPIP diversion tunnel"
  nsclean rA rB
  for n in rA rB; do ip netns add "$n"; ip -n "$n" link set lo up; ip netns exec "$n" sysctl -qw net.ipv4.ip_forward=1; done
  veth rA-rB rB-rA rA rB
  ip -n rA addr add 10.0.2.1/24 dev rA-rB; ip -n rA link set rA-rB up
  ip -n rB addr add 10.0.2.2/24 dev rB-rA; ip -n rB link set rB-rA up
  ip -n rA tunnel add ipip1 mode ipip remote 10.0.2.2 local 10.0.2.1
  ip -n rB tunnel add ipip1 mode ipip remote 10.0.2.1 local 10.0.2.2
  ip -n rA addr add 10.9.0.1/30 dev ipip1; ip -n rA link set ipip1 up
  ip -n rB addr add 10.9.0.2/30 dev ipip1; ip -n rB link set ipip1 up
  ip netns exec rA ping -c1 -W2 10.9.0.2 >/dev/null 2>&1 \
    && ok "IPIP tunnel up ($(ip -n rA link show ipip1 | grep -o 'mtu [0-9]*'))" || bad "IPIP tunnel did not come up"
  nsclean rA rB
}

# ---------------------------------------------------------------------------
# Recipe 3 — L2 insertion: the scrub node bridged in-path, XDP on the ingress
# port, no L3 address on the box at all.
# ---------------------------------------------------------------------------
recipe_l2() {
  title "L2 insertion (bridged in-path)"
  nsclean cli sc gw
  for n in cli sc gw; do ip netns add "$n"; ip -n "$n" link set lo up; done
  veth cli-sc sc-cli cli sc; veth gw-sc sc-gw gw sc
  ip netns exec sc ip link add br0 type bridge
  ip netns exec sc ip link set sc-cli master br0; ip netns exec sc ip link set sc-gw master br0
  ip netns exec sc ip link set sc-cli up; ip netns exec sc ip link set sc-gw up; ip netns exec sc ip link set br0 up
  ip -n cli addr add 10.0.5.2/24 dev cli-sc; ip -n cli link set cli-sc up
  ip -n gw  addr add 10.0.5.1/24 dev gw-sc;  ip -n gw  link set gw-sc up
  ip netns exec cli ping -c1 -W2 10.0.5.1 >/dev/null 2>&1 \
    && ok "client reaches the gateway through the L2-bridged scrub node (XDP would attach to sc-cli)" \
    || bad "L2 bridge path did not forward"
  nsclean cli sc gw
}

# ---------------------------------------------------------------------------
# Recipe 4 — asymmetric return + rp_filter. The victim prefix is diverted toward
# the scrub node, so a border router's REVERSE ROUTE to the victim points at the
# tunnel. The victim's replies, arriving on a normal link, fail strict
# rp_filter's reverse-path check and are dropped. Loose (2) or off (0) pass.
# ---------------------------------------------------------------------------
recipe_rpfilter() {
  title "asymmetric return + rp_filter"
  nsclean R A
  for n in R A; do ip netns add "$n"; ip -n "$n" link set lo up; done
  ip netns exec R sysctl -qw net.ipv4.ip_forward=1 >/dev/null
  veth A-R R-A A R
  ip link add R-if2 type veth peer name if2-peer; ip link set R-if2 netns R
  ip -n A addr add 10.10.0.2/24 dev A-R; ip -n A link set A-R up; ip -n A route add default via 10.10.0.1
  ip -n R addr add 10.10.0.1/24 dev R-A;  ip -n R link set R-A up
  ip -n R addr add 10.20.0.1/24 dev R-if2; ip -n R link set R-if2 up
  # The victim prefix's reverse route points at the OTHER interface (the divert side).
  ip -n R route add 192.0.2.0/24 via 10.20.0.99 dev R-if2
  probe() {
    ip netns exec R sysctl -qw net.ipv4.conf.all.rp_filter="$1" net.ipv4.conf.R-A.rp_filter="$1" >/dev/null
    ip netns exec R timeout 2 python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",9999)); s.settimeout(1.2)
try: s.recvfrom(100); print("RECEIVED")
except socket.timeout: print("DROPPED")' &
    local rl=$!; sleep 0.3
    ip netns exec A python3 -c '
import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
src=socket.inet_aton("192.0.2.5"); dst=socket.inet_aton("10.10.0.1")
udp=struct.pack("!HHHH",5000,9999,10,0)+b"hi"
iph=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),0,0,64,17,0,src,dst)
s.sendto(iph+udp,("10.10.0.1",0))' 2>/dev/null
    wait "$rl"
  }
  [ "$(probe 1)" = DROPPED  ] && ok "rp_filter=1 (strict): the asymmetric reply is dropped (the trap)" || bad "strict rp_filter did not drop"
  [ "$(probe 2)" = RECEIVED ] && ok "rp_filter=2 (loose): the reply passes (the fix)"                 || bad "loose rp_filter did not pass"
  [ "$(probe 0)" = RECEIVED ] && ok "rp_filter=0 (off): the reply passes"                             || bad "rp_filter=0 did not pass"
  nsclean R A
}

# ---------------------------------------------------------------------------
# Recipe 5 — route-leaking return path (the portable VRF form). Reinjected clean
# traffic must leave via the CLEAN uplink, not back down the dirty tunnel. An
# `ip rule` selects a dedicated table for the victim prefix's source.
# ---------------------------------------------------------------------------
recipe_routeleak() {
  title "route-leaking return path (policy routing)"
  nsclean sc up1 up2
  for n in sc up1 up2; do ip netns add "$n"; ip -n "$n" link set lo up; done
  ip netns exec sc sysctl -qw net.ipv4.ip_forward=1 >/dev/null
  veth sc-up1 up1-sc sc up1; veth sc-up2 up2-sc sc up2
  ip -n sc addr add 10.30.0.1/24 dev sc-up1; ip -n sc link set sc-up1 up
  ip -n sc addr add 10.31.0.1/24 dev sc-up2; ip -n sc link set sc-up2 up
  ip -n up1 addr add 10.30.0.2/24 dev up1-sc; ip -n up1 link set up1-sc up
  ip -n up2 addr add 10.31.0.2/24 dev up2-sc; ip -n up2 link set up2-sc up
  ip -n sc route add default via 10.30.0.2 dev sc-up1                 # main table: the dirty uplink
  ip -n sc route add default via 10.31.0.2 dev sc-up2 table 100       # table 100: the clean uplink
  ip -n sc rule add from 203.0.113.0/24 lookup 100                    # leak: victim source -> clean uplink
  local got
  got=$(ip netns exec sc ip route get 8.8.8.8 from 203.0.113.10 iif sc-up1 2>&1 | head -1)
  echo "$got" | grep -q 'dev sc-up2 table 100' \
    && ok "reinjected (victim-source) traffic egresses the CLEAN uplink via table 100" \
    || bad "route-leak did not steer victim-source traffic to the clean uplink ($got)"
  nsclean sc up1 up2
}

echo "network-integration lab — kernel $(uname -r)"
recipe_gre_mss
recipe_ipip
recipe_l2
recipe_rpfilter
recipe_routeleak
echo
echo "==================================================="
echo "  $PASS passed, $FAIL failed"
echo "==================================================="
[ "$FAIL" -eq 0 ]
