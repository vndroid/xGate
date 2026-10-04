#!/usr/bin/env bash
# SSH 场景测试：在 Alpine 3.23 上编译 xgate，部署到带 systemd 的 Debian 容器，
# 由 xgate 把 2222 转发到 sshd:22，验证连接、吞吐和长连接行为。
#
# 在任意 Docker 主机上运行（不会改动宿主机的网络规则）：
#   test/ssh/run.sh
# 可调参数：LONG_SECONDS（活跃长连接时长，默认 240）、IDLE_SECONDS（空闲连接时长，默认 300）
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$PWD
NET=xgate-ssh-test SUBNET=172.30.99.0/24
SRV_IP=172.30.99.10 CLI_IP=172.30.99.20 CLI2_IP=172.30.99.21
SRV=xg-ssh-server CLI=xg-ssh-client CLI2=xg-ssh-client2
IMAGE=xgate-ssh-server:test
LONG=${LONG_SECONDS:-240}
IDLE=${IDLE_SECONDS:-300}
VERSION=${VERSION:-ssh-test}

remove_env() { docker rm -f $SRV $CLI $CLI2 >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
remove_env
WORK=$(mktemp -d)
cleanup() {
	set +e
	if [[ ${FAIL:-0} -ne 0 ]]; then
		echo "--- xgate journal ---"
		docker exec $SRV journalctl -u xgate --no-pager -n 50
	fi
	remove_env
	rm -rf "$WORK"
}
trap cleanup EXIT

log() { echo "[$(date +%T)] $*"; }

# --- 编译与镜像 -------------------------------------------------------------
log "build xgate on alpine"
docker run --rm -v "$ROOT":/src -v xgate-gomod:/go/pkg/mod -w /src -e CGO_ENABLED=0 golang:1.26-alpine3.23 \
	sh -c "echo \"alpine \$(cat /etc/alpine-release), \$(go version)\" && go build -buildvcs=false -trimpath -ldflags '-s -w -X main.version=$VERSION' -o out/xgate ./cmd/xgate && chown -R $(id -u):$(id -g) out"
file out/xgate 2>/dev/null || true
log "build debian server image"
docker build -q -f test/ssh/server.Dockerfile -t $IMAGE . >/dev/null

# --- 环境 -------------------------------------------------------------------
docker network create --subnet $SUBNET $NET >/dev/null
docker run -d --name $SRV --hostname $SRV --privileged --cgroupns=private \
	--tmpfs /run --tmpfs /run/lock --network $NET --ip $SRV_IP $IMAGE >/dev/null
for c in $CLI:$CLI_IP $CLI2:$CLI2_IP; do
	docker run -d --name "${c%%:*}" --network $NET --ip "${c##*:}" alpine:3.23 sleep infinity >/dev/null
	docker exec "${c%%:*}" sh -c "apk add -q openssh-client coreutils && ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519"
	docker exec "${c%%:*}" cat /root/.ssh/id_ed25519.pub | docker exec -i $SRV sh -c 'cat >> /root/.ssh/authorized_keys'
done

log "wait for systemd, sshd and xgate"
for _ in $(seq 60); do
	if docker exec $SRV systemctl is-active -q ssh xgate 2>/dev/null &&
		docker exec $SRV curl -sf http://127.0.0.1:7070/healthz >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
docker exec $SRV sh -c 'grep PRETTY_NAME /etc/os-release; xgate version; systemctl is-active ssh xgate'

# --- 工具 -------------------------------------------------------------------
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5"
# ssh_to <客户端容器> <端口> [额外 ssh 选项...] -- <远程命令>
ssh_to() {
	local c=$1 port=$2
	shift 2
	local extra=()
	while [[ $# -gt 0 && $1 != -- ]]; do extra+=("$1"); shift; done
	shift
	# shellcheck disable=SC2086
	docker exec "$c" ssh $SSH_OPTS "${extra[@]}" -p "$port" root@$SRV_IP "$*"
}
api() { docker exec $SRV curl -s -X "$1" "http://127.0.0.1:7070$2" ${3:+-d "$3"} -H 'X-Xgate-Actor: ssh-test'; }
wait_ready() {
	for _ in $(seq 30); do
		docker exec $SRV curl -sf http://127.0.0.1:7070/healthz >/dev/null 2>&1 && return
		sleep 1
	done
	return 1
}

PASS=0 FAIL=0
declare -A BG=()
check() { # check <描述> <期望输出> <命令...>
	local desc=$1 want=$2 got
	shift 2
	got=$("$@" 2>/dev/null || true)
	if [[ $got == "$want" ]]; then
		log "ok   - $desc"
		PASS=$((PASS + 1))
	else
		log "FAIL - $desc (want '${want:-<none>}', got '${got:-<none>}')"
		FAIL=$((FAIL + 1))
	fi
}
# bg_session <名字> <客户端> <端口> [ssh 选项...] -- <命令>：后台会话，输出与退出码写入 $WORK
bg_session() {
	local name=$1
	shift
	# 子 shell 会继承 set -e，这里显式捕获退出码，避免 ssh 失败时漏写 .rc。
	( rc=0; ssh_to "$@" >"$WORK/$name.out" 2>"$WORK/$name.err" || rc=$?; echo $rc >"$WORK/$name.rc" ) &
	BG[$name]=$!
}
rc_of() { cat "$WORK/$1.rc"; }
last_line() { tail -n1 "$WORK/$1.out"; }
loop_cmd() { echo "i=0; while [ \$i -lt $1 ]; do i=\$((i+1)); echo \$i; sleep $2; done; echo done"; }

# --- 基本连接 ---------------------------------------------------------------
check "not allowlisted: ssh via 2222 blocked" "" ssh_to $CLI 2222 -- echo ok
api POST /v1/allowlist "{\"cidr\":\"$CLI_IP\",\"comment\":\"ssh client\"}" >/dev/null
check "allowlisted: ssh via 2222 works" "ok" ssh_to $CLI 2222 -- echo ok
# shellcheck disable=SC2016
check "sshd sees the real client ip" "$CLI_IP" ssh_to $CLI 2222 -- 'echo ${SSH_CLIENT%% *}'
check "direct ssh to 22 blocked (protect_target)" "" ssh_to $CLI 22 -- echo ok
check "other client blocked" "" ssh_to $CLI2 2222 -- echo ok

log "throughput: 512 MiB through the forwarded ssh session"
start=$(date +%s.%N)
bytes=$(docker exec $CLI sh -c "head -c 536870912 /dev/zero | ssh $SSH_OPTS -p 2222 root@$SRV_IP 'wc -c'" || true)
secs=$(awk -v a="$start" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')
check "512 MiB transferred intact" "536870912" echo "$bytes"
log "     ${secs}s, $(awk -v s="$secs" 'BEGIN { printf "%.0f", 512 / s }') MiB/s (includes ssh encryption)"

# --- 长连接 -----------------------------------------------------------------
log "long sessions: active ${LONG}s (output every 5s), idle ${IDLE}s (no traffic, no keepalive)"
bg_session active $CLI 2222 -o ServerAliveInterval=10 -- "$(loop_cmd $((LONG / 5)) 5)"
bg_session idle $CLI 2222 -o ServerAliveInterval=0 -o TCPKeepAlive=no -- "sleep $IDLE; echo alive"
sleep 3
log "     conntrack: $(docker exec $SRV conntrack -L -p tcp --orig-port-dst 2222 2>/dev/null | grep -c ESTABLISHED) established flows via :2222"

sleep 20
log "disturb: systemctl restart xgate"
docker exec $SRV systemctl restart xgate && wait_ready
check "new ssh works after restart" "ok" ssh_to $CLI 2222 -- echo ok
sleep 20
log "disturb: 20 forced syncs (each rebuilds the whole table)"
for _ in $(seq 20); do api POST /v1/allowlist:sync >/dev/null; done
sleep 20
log "disturb: systemctl stop xgate for 20s, then start"
docker exec $SRV systemctl stop xgate
sleep 20
check "new ssh works while control plane is stopped" "ok" ssh_to $CLI 2222 -- echo ok
docker exec $SRV systemctl start xgate && wait_ready

wait "${BG[active]}" "${BG[idle]}"
check "active session survived restarts and syncs" "0 done" echo "$(rc_of active) $(last_line active)"
check "active session lost no output" "$((LONG / 5))" sh -c "grep -c '^[0-9]' $WORK/active.out"
check "idle session survived ${IDLE}s without traffic" "0 alive" echo "$(rc_of idle) $(last_line idle)"

# flush ruleset 会删掉所有 nat 链，内核随之注销 NAT hook，这段时间内活跃连接的包
# 得不到地址转换、会被 RST（已知限制，见 README），所以放在长连接结束后单独验证恢复。
log "disturb: nft flush ruleset (reconcile should restore within 5s)"
docker exec $SRV nft flush ruleset
sleep 8
check "rules restored by reconcile after flush" "ok" ssh_to $CLI 2222 -- echo ok

# --- 删除与 TTL 对已有连接的影响 --------------------------------------------
log "delete without kill: existing session should continue"
bg_session keep $CLI 2222 -o ServerAliveInterval=5 -- "$(loop_cmd 6 5)"
sleep 5
api DELETE "/v1/allowlist/$CLI_IP%2F32" >/dev/null
check "new ssh blocked after delete" "" ssh_to $CLI 2222 -- echo ok
wait "${BG[keep]}"
check "existing session continued after delete" "0 done" echo "$(rc_of keep) $(last_line keep)"

# 关闭客户端心跳：断开必须来自 xgate 主动发出的 RST，而不是客户端自己超时。
NO_ALIVE=(-o ServerAliveInterval=0 -o TCPKeepAlive=no)
sshd_conns() { docker exec $SRV ss -Htn state established dst $CLI_IP "( sport = :22 )" | grep -c . || true; }
ended_within() { # ended_within <名字> <秒>
	for _ in $(seq $(($2 * 10))); do [[ -f $WORK/$1.rc ]] && { echo ended; return; }; sleep 0.1; done
	echo "still open"
}
for kind in idle active; do
	log "delete with kill=true: $kind session should be reset on both ends"
	api POST /v1/allowlist "{\"cidr\":\"$CLI_IP\"}" >/dev/null
	if [[ $kind == idle ]]; then
		bg_session "kill_$kind" $CLI 2222 "${NO_ALIVE[@]}" -- "sleep 120"
	else
		bg_session "kill_$kind" $CLI 2222 "${NO_ALIVE[@]}" -- "$(loop_cmd 120 1)"
	fi
	sleep 3
	check "$kind: sshd connection established" "1" sshd_conns
	api DELETE "/v1/allowlist/$CLI_IP%2F32?kill=true" >"$WORK/kill.json"
	log "     $(tr -d '\n ' <"$WORK/kill.json" | grep -oE '"(reset_sockets|killed_connections)":[0-9]+' | tr '\n' ' ')"
	check "$kind: client disconnected within 3s" "ended" ended_within "kill_$kind" 3
	check "$kind: ssh exited with connection reset" "255" rc_of "kill_$kind"
	check "$kind: sshd connection closed" "0" sshd_conns
	wait "${BG[kill_$kind]}"
done

log "ttl: entry expires while a session is open"
api POST /v1/allowlist "{\"cidr\":\"$CLI_IP\",\"ttl\":\"15s\"}" >/dev/null
bg_session ttl $CLI 2222 -o ServerAliveInterval=5 -- "$(loop_cmd 8 5)"
sleep 20
check "new ssh blocked after ttl expiry" "" ssh_to $CLI 2222 -- echo ok
wait "${BG[ttl]}"
check "existing session outlived ttl" "0 done" echo "$(rc_of ttl) $(last_line ttl)"

echo
log "passed: $PASS, failed: $FAIL"
[[ $FAIL -eq 0 ]]
