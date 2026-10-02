#!/usr/bin/env bash
# xgate 端到端测试：在两个 network namespace 之间验证真实的内核转发行为。
#
# 需要 Linux（内核 ≥ 5.2）、root，以及 nft、conntrack、socat、curl。
# 用法：sudo test/integration.sh [path/to/xgate]
#   未指定二进制时用 go build 现编一个。
# macOS 上可以用：docker run --rm --privileged -v "$PWD":/src -w /src golang:1 \
#   bash -c 'apt-get update -qq && apt-get install -y -qq nftables conntrack socat curl iproute2 >/dev/null && test/integration.sh'
set -euo pipefail

SRV=xg-srv CLI=xg-cli
SRV4=10.99.0.1 CLI4=10.99.0.2 CLI4B=10.99.0.3
SRV6=fd99::1 CLI6=fd99::2
API=http://127.0.0.1:7070

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
for bin in ip nft conntrack socat curl; do
	command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

WORK=$(mktemp -d)
XGATE=${1:-}
if [[ -z $XGATE ]]; then
	XGATE=$WORK/xgate
	(cd "$(dirname "$0")/.." && CGO_ENABLED=0 go build -o "$XGATE" ./cmd/xgate)
fi
XGATE=$(realpath "$XGATE")

PIDS=()
cleanup() {
	set +e
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	[[ -n ${XGATE_PID:-} ]] && kill "$XGATE_PID" 2>/dev/null
	wait 2>/dev/null
	ip netns del $SRV 2>/dev/null
	ip netns del $CLI 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

srv() { ip netns exec $SRV "$@"; }
cli() { ip netns exec $CLI "$@"; }

# --- 网络拓扑 ---------------------------------------------------------------
ip netns add $SRV
ip netns add $CLI
ip link add xg-veth-s netns $SRV type veth peer name xg-veth-c netns $CLI
srv ip link set lo up
cli ip link set lo up
srv ip addr add $SRV4/24 dev xg-veth-s
srv ip addr add $SRV6/64 dev xg-veth-s nodad
cli ip addr add $CLI4/24 dev xg-veth-c
cli ip addr add $CLI4B/24 dev xg-veth-c
cli ip addr add $CLI6/64 dev xg-veth-c nodad
srv ip link set xg-veth-s up
cli ip link set xg-veth-c up

# --- 后端服务（监听 8080，双栈）---------------------------------------------
srv socat TCP6-LISTEN:8080,ipv6only=0,reuseaddr,fork SYSTEM:'echo tcp-ok' &
PIDS+=($!)
srv socat UDP6-RECVFROM:8080,ipv6only=0,reuseaddr,fork SYSTEM:'echo udp-ok' &
PIDS+=($!)

# --- xgate ------------------------------------------------------------------
cat >"$WORK/config.yaml" <<EOF
api: {listen: "127.0.0.1:7070"}
db: $WORK/xgate.db
reconcile_interval: 2s
forwards:
  - {name: default, listen_port: 35353, target_port: 8080, protocols: [tcp, udp]}
EOF

start_xgate() {
	srv "$XGATE" serve -config "$WORK/config.yaml" >>"$WORK/xgate.log" 2>&1 &
	XGATE_PID=$!
	for _ in $(seq 50); do
		srv curl -sf $API/healthz >/dev/null && return
		sleep 0.1
	done
	cat "$WORK/xgate.log"
	echo "xgate did not become healthy" >&2
	exit 1
}

api() { srv curl -s -X "$1" "$API$2" ${3:+-d "$3"} -H 'X-Xgate-Actor: integration'; }

# --- 断言工具 ---------------------------------------------------------------
PASS=0 FAIL=0
tcp_probe() { cli timeout 3 socat -T2 - "TCP:$1:$2,bind=$3,connect-timeout=2" </dev/null 2>/dev/null; }
udp_probe() { echo hi | cli timeout 3 socat -T2 - "UDP:$1:$2,bind=$3" 2>/dev/null; }

check() { # check <描述> <期望输出或空表示应失败> <命令...>
	local desc=$1 want=$2 got
	shift 2
	got=$("$@" || true)
	if [[ $got == "$want" ]]; then
		echo "ok   - $desc"
		PASS=$((PASS + 1))
	else
		echo "FAIL - $desc (want '${want:-<no response>}', got '${got:-<no response>}')"
		FAIL=$((FAIL + 1))
	fi
}

# --- 用例 -------------------------------------------------------------------
start_xgate

check "not allowlisted: tcp blocked" "" tcp_probe $SRV4 35353 $CLI4
check "not allowlisted: udp blocked" "" udp_probe $SRV4 35353 $CLI4

api POST /v1/allowlist "{\"cidr\":\"$CLI4/32\",\"comment\":\"client\"}" >/dev/null
check "allowlisted: tcp forwarded" "tcp-ok" tcp_probe $SRV4 35353 $CLI4
check "allowlisted: udp forwarded" "udp-ok" udp_probe $SRV4 35353 $CLI4
check "other source still blocked" "" tcp_probe $SRV4 35353 $CLI4B
check "direct access to target port blocked" "" tcp_probe $SRV4 8080 $CLI4

api POST /v1/allowlist "{\"cidr\":\"$CLI6\"}" >/dev/null
check "ipv6 allowlisted: tcp forwarded" "tcp-ok" tcp_probe "[$SRV6]" 35353 "[$CLI6]"

srv nft flush ruleset
check "after nft flush ruleset: blocked" "" tcp_probe $SRV4 35353 $CLI4
sleep 3
check "reconcile restored rules" "tcp-ok" tcp_probe $SRV4 35353 $CLI4

api POST /v1/allowlist "{\"cidr\":\"$CLI4B/32\",\"ttl\":\"3s\"}" >/dev/null
check "ttl entry: allowed before expiry" "tcp-ok" tcp_probe $SRV4 35353 $CLI4B
sleep 4
check "ttl entry: blocked after expiry" "" tcp_probe $SRV4 35353 $CLI4B

kill "$XGATE_PID"
wait "$XGATE_PID" 2>/dev/null || true
XGATE_PID=
check "control plane stopped: forwarding continues" "tcp-ok" tcp_probe $SRV4 35353 $CLI4
start_xgate
check "control plane restarted: allowlist restored" "tcp-ok" tcp_probe $SRV4 35353 $CLI4

udp_probe $SRV4 35353 $CLI4 >/dev/null
ct_tracked() { # 输出 yes/no：是否存在来自 CLI4、目的端口 35353 的 udp 连接记录
	if srv conntrack -L -p udp -s $CLI4 --orig-port-dst 35353 2>/dev/null | grep -q .; then echo yes; else echo no; fi
}
check "udp flow tracked before delete" "yes" ct_tracked
api DELETE "/v1/allowlist/$CLI4%2F32?kill=true" >/dev/null
check "delete with kill: conntrack entries removed" "no" ct_tracked
check "deleted: tcp blocked" "" tcp_probe $SRV4 35353 $CLI4

audit_deletes() { api GET "/v1/audit?limit=100" | grep -c '"action": "delete"'; }
check "audit log recorded the delete" "1" audit_deletes

echo
echo "passed: $PASS, failed: $FAIL"
if [[ $FAIL -ne 0 ]]; then
	echo "--- xgate log ---"
	cat "$WORK/xgate.log"
	exit 1
fi
