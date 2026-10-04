# xGate

基于 CIDR 白名单的四层（TCP/UDP）端口转发工具。转发由内核 nftables 完成，Go 控制面提供 HTTP API，可以动态增删白名单。

典型场景：服务器 `:35353` 收到请求后，如果来源 IP 在白名单网段内，就转发到本机 `:8080`，否则丢弃。

```
           ┌──────────── 控制面（可随时重启）────────────┐
 运维/系统 → │ HTTP API → SQLite → 对账器                   │ ──nft -f -──┐
           └─────────────────────────────────────────────┘              ▼
 客户端 ──:35353──▶ nftables prerouting: saddr ∈ @allow → redirect :8080 ──▶ 服务
```

- **内核转发**：使用 `redirect` 加 interval set，后端能看到真实客户端 IP，性能与 UDP PPS 不受用户态限制。
- **平滑重启**：控制面不在转发路径上，`systemctl restart xgate` 不影响已有连接和新连接。
- **SQLite 是唯一的事实来源**：每次同步都在一个 nft 事务里重建 `inet xgate` 表并写入全部白名单，失败时整体回滚；之后每 30 秒对账一次，有人手动 `nft flush ruleset` 也会被自动纠正。
- **TTL**：内核 set 元素带 `timeout`，控制面停止时也会按时过期；控制面在到期时刻清理 SQLite 并写审计。
- **重叠网段**：入库前规范化（主机位清零，IPv4-mapped 转为 IPv4）；写入内核前展开成互不重叠的区间，每个地址归属于覆盖它的记录中存活最久的那条。

## 要求

- Linux ≥ 5.2（`inet` 表中的 NAT），`nft`；删除时如需断开已有连接，还需要 conntrack-tools ≥ 1.4.5、iproute2 的 `ss`，以及内核开启 `CONFIG_INET_DIAG_DESTROY`（Debian、Ubuntu 默认开启）
- 运行权限：root 或 `CAP_NET_ADMIN`；容器部署需要 host 网络

## 可移植性

- `CGO_ENABLED=0` 编译出的是完全静态的二进制，不依赖 libc：在 Alpine（musl）上编译，可以直接在 Debian/Ubuntu/RHEL 等 glibc 发行版上运行，反过来也一样。SQLite 用的是纯 Go 驱动 `modernc.org/sqlite`。
- 发行版本身没有限制，真正的运行时依赖只有两个：
  - **内核** ≥ 5.2，并启用 nf_tables、nft_nat/nft_redir、nf_conntrack；
  - **用户态命令** `nft`，以及删除时带 `?kill=true` 才会用到的 `conntrack`（≥ 1.4.5）和 `ss`。
- 支持 amd64、arm64 等 Go 支持的架构，交叉编译即可，例如 `GOARCH=arm64`。
- `deploy/xgate.service` 适用于 systemd 发行版；Alpine 等使用 OpenRC 的系统需要自己编写服务脚本，启动命令同样是 `xgate serve -config …`。

## 安装

[Releases](https://github.com/vndroid/xGate/releases) 页面提供 linux/amd64 和 linux/arm64 的静态二进制，以及 `SHA256SUMS`。推送 `vX.Y.Z` tag 会自动触发 [release workflow](.github/workflows/release.yml)：先跑测试，再编译并上传。也可以自己编译：

```bash
CGO_ENABLED=0 go build -ldflags "-X main.version=$(git describe --always)" -o xgate ./cmd/xgate
install -m 0755 xgate /usr/local/bin/xgate
install -D -m 0640 deploy/config.example.yaml /etc/xgate/config.yaml
install -m 0644 deploy/xgate.service /etc/systemd/system/xgate.service
systemctl daemon-reload && systemctl enable --now xgate
```

`xgate render -config /etc/xgate/config.yaml` 打印当前会写入内核的完整 nft 事务。

## 配置

完整示例见 [deploy/config.example.yaml](deploy/config.example.yaml)，默认路径是 `/etc/xgate/config.yaml`。

### 转发规则

转发端口完全可配置。`forwards` 可以写多条规则，它们共用同一份白名单：

```yaml
forwards:
  - name: default           # 规则名，会写进 nft 规则的 comment
    listen_port: 35353      # 对外端口：白名单内的来源会被转发
    target_port: 8080       # 本机目标端口：后端服务需要监听 0.0.0.0 或 ::
    protocols: [tcp, udp]   # 可选，默认 tcp + udp
    protect_target: true    # 可选，默认 true：丢弃从外部直接访问 target_port 的流量
  - name: ssh
    listen_port: 2222
    target_port: 22
    protocols: [tcp]
```

| 字段 | 说明 |
| --- | --- |
| `name` | 规则名，不能重复；省略时自动生成 `forward0`、`forward1`… |
| `listen_port` | 客户端连接的端口。不在白名单内的来源发到这个端口的流量会被丢弃 |
| `target_port` | 本机后端端口。不能与 `listen_port` 相同 |
| `protocols` | `tcp`、`udp` 或两者都选 |
| `protect_target` | 开启时只放行经过 redirect 的连接和来自 `lo` 的连接，外部无法绕过白名单直连后端 |

> **注意**：`protect_target` 开启时，外部直连 `target_port` 的流量会被丢弃。上例中所有人都只能通过 2222 端口、并且来源在白名单内才能 SSH 登录，**直连 22 端口不再可用**。在远程服务器上首次启用前，请确认自己的 IP 已经在白名单里，或者先把 `protect_target` 设为 `false`，避免把自己锁在服务器外面。

启动时会校验：同一协议的监听端口不能重复；一条规则的监听端口不能是另一条规则受保护的目标端口。

修改配置后执行 `systemctl restart xgate` 即可生效。重启只影响控制面，新规则在一个 nft 事务里原子替换旧规则，已有连接不会中断。改之前可以先用 `xgate render -config /etc/xgate/config.yaml` 看一下会生成哪些规则。

### 其它配置

- `api.listen`：API 监听地址，见下文。
- `reconcile_interval`：定期对账间隔，默认 `30s`。
- `min_prefix_len`：不加 `force` 时允许的最短前缀，默认 IPv4 `/8`、IPv6 `/32`。
- `db`：SQLite 路径，默认 `/var/lib/xgate/xgate.db`。

## API

### 怎么访问

白名单 API **不复用转发端口**。转发端口由内核 nftables 处理，没有程序在上面监听；API 是 xgate 控制面单独启动的 HTTP 服务，监听地址由 `api.listen` 决定：

| `api.listen` | 访问方式 |
| --- | --- |
| `127.0.0.1:7070`（默认） | 只能在服务器本机访问：`curl localhost:7070/...` |
| `unix:/run/xgate/api.sock` | 本机通过 unix socket 访问：`curl --unix-socket /run/xgate/api.sock http://x/...` |
| `0.0.0.0:7070` 等非回环地址 | 可以远程访问，但必须配置 `token`/`token_file` 或 mTLS（`tls.client_ca`），否则拒绝启动；建议同时配置 TLS |

需要从其它机器调用时，推荐让 API 继续只监听本机，通过 SSH 隧道访问：

```bash
ssh -N -L 7070:127.0.0.1:7070 user@server
```

隧道建立后，在本地请求 `localhost:7070` 即可。

### 请求头

- `Authorization: Bearer <token>`：配置了 token 时必填（`/healthz` 除外）。
- `X-Xgate-Actor: <name>`：可选，会和来源地址一起记入审计日志，例如 `kane@127.0.0.1:56161`。

### 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/v1/allowlist` | 新增或更新 |
| `DELETE` | `/v1/allowlist/{cidr}` | 删除；加 `?kill=true` 同时断开已有连接 |
| `GET` | `/v1/allowlist` | 列出有效条目 |
| `POST` | `/v1/allowlist:sync` | 立即与内核对账 |
| `GET` | `/v1/audit?limit=100` | 最近的审计记录（add / update / delete / expire），`limit` 取 1–1000 |
| `GET` | `/healthz` | 最近一次同步成功返回 200，否则返回 503；不需要鉴权 |

出错时返回 `{"error": "..."}`：参数错误为 400，鉴权失败为 401，条目不存在为 404，内核同步失败为 500。

### 新增或更新

```bash
curl -s localhost:7070/v1/allowlist -H 'X-Xgate-Actor: kane' \
  -d '{"cidr":"198.51.100.7/24","comment":"office","ttl":"24h"}'
```

| 字段 | 说明 |
| --- | --- |
| `cidr` | 必填。网段或单个 IP（视为 `/32`、`/128`）；主机位会被清零，`198.51.100.7/24` 存为 `198.51.100.0/24`；IPv4-mapped IPv6 会转成 IPv4 |
| `comment` | 可选，最长 256 字节 |
| `ttl` | 可选，不填表示永久。支持 `30m`、`24h`、`7d` 等，至少 `1s` |
| `force` | 可选。比 `min_prefix_len` 更宽的网段（如 `0.0.0.0/0`）需要设为 `true` |

已存在的网段会被更新（comment、ttl），返回 200；新增返回 201：

```json
{
  "entry": {
    "cidr": "198.51.100.0/24",
    "comment": "office",
    "created_at": "2026-10-04T07:14:20.00479Z",
    "updated_at": "2026-10-04T07:14:20.00479Z",
    "created_by": "kane@127.0.0.1:56161",
    "expires_at": "2026-10-05T07:14:20.00479Z",
    "ttl_seconds": 86400
  },
  "sync": { "last_success": "...", "entries": 1, "elements": 1 }
}
```

重叠的网段可以同时存在。写入内核前会展开成互不重叠的区间，每个地址按覆盖它、且存活最久的那条记录生效。

### 删除

网段里的 `/` 要写成 `%2F`；直接写 `/` 也可以：

```bash
curl -s -X DELETE 'localhost:7070/v1/allowlist/198.51.100.0%2F24'
curl -s -X DELETE 'localhost:7070/v1/allowlist/198.51.100.0%2F24?kill=true'
```

```json
{
  "deleted": { "cidr": "198.51.100.0/24", "comment": "office", "...": "..." },
  "killed_connections": 2,
  "reset_sockets": 1,
  "sync": { "last_success": "...", "entries": 0, "elements": 0 }
}
```

`killed_connections`、`reset_sockets` 只在带 `kill` 时出现，含义见下一节。

### 查询、对账与审计

```bash
curl -s localhost:7070/v1/allowlist          # {"entries": [...]}，字段同上
curl -s -X POST localhost:7070/v1/allowlist:sync
curl -s 'localhost:7070/v1/audit?limit=20'
curl -s localhost:7070/healthz
```

审计记录示例：

```json
{
  "records": [
    { "id": 2, "time": "2026-10-04T07:14:20.057Z", "actor": "api@127.0.0.1:56167",
      "action": "delete", "cidr": "198.51.100.0/24", "detail": "kill=true" },
    { "id": 1, "time": "2026-10-04T07:14:20.004Z", "actor": "kane@127.0.0.1:56161",
      "action": "add", "cidr": "198.51.100.0/24",
      "detail": "comment=\"office\" expires_at=2026-10-05T07:14:20Z" }
  ]
}
```

开启 token 后的远程调用：

```bash
curl -s -H "Authorization: Bearer $(cat /etc/xgate/token)" https://server:7070/v1/allowlist
```

### 删除时断开已有连接（`?kill=true`）

不带 kill 时，删除只会拦截新连接；已建立的连接靠 conntrack 里的 NAT 映射继续工作。带上 kill 后：

1. 先用 `ss -K` 销毁本机后端上来自这些地址的 TCP socket，内核会向客户端和后端**各发一个 RST**，空闲连接也会立即断开。这一步必须在清理 conntrack 之前做，RST 才能被转换回监听端口、被客户端识别。
2. 再清理 conntrack 记录，覆盖 UDP 和剩余连接，使它们的后续报文不再被转发。UDP 没有连接的概念，后端程序本身不会收到通知。

响应中的 `reset_sockets` 是被重置的 TCP 连接数，`killed_connections` 是被删除的 conntrack 记录数。如果内核没有开启 `CONFIG_INET_DIAG_DESTROY`，第 1 步不会生效：连接只会停止转发，两端不会收到通知，响应里会带上 `warnings`。

变更会先写入 SQLite，然后立即同步到内核。如果同步失败，API 返回 500 并说明"已保存"，后台对账会继续重试。

## 注意事项

- `redirect` 会把目标地址改成入口网卡的主地址，所以后端要监听 `0.0.0.0` 或 `::`。
- 本机发起的连接不经过 prerouting，不会被转发。
- **不要对运行中的机器执行 `nft flush ruleset`。** 新连接的转发最多一个对账周期后会自动恢复，但**正在传输数据的已建立连接会被断开**：已有连接的 NAT 映射保存在 conntrack 里，但内核只在本网络命名空间里还存在 nat 类型链时才会做地址转换。flush 删除所有 nat 链之后，直到对账恢复规则之前，这些连接的包得不到转换，会收到 RST。空闲连接如果在这段时间里没有收发数据，则不受影响。手动 `nft delete table inet xgate` 也一样，除非本机还有其它 nat 链（例如 Docker）。xgate 自己的同步是原子替换，不会出现这个空窗。
  - Debian 默认的 `/etc/nftables.conf` 第一行就是 `flush ruleset`，`systemctl reload/restart nftables` 会触发上述问题。建议改成只清理自己的表，例如把 `flush ruleset` 换成 `table inet filter {}` 加 `flush table inet filter`。
- 高并发 UDP 时注意 `nf_conntrack_max` 和 UDP 超时设置。
- 停止 xgate 不会删除内核规则；要彻底移除，执行 `nft delete table inet xgate`。

## 开发

```bash
go test ./...                  # 单元测试，macOS 上可跑（nft、conntrack 都通过接口 mock）
sudo test/integration.sh       # Linux 端到端测试（netns），需要 nft、conntrack、socat、curl
```
