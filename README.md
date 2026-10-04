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

- Linux ≥ 5.2（`inet` 表中的 NAT），`nft`；删除时如需断开已有连接，还需要 conntrack-tools ≥ 1.4.5
- 运行权限：root 或 `CAP_NET_ADMIN`；容器部署需要 host 网络

## 可移植性

- `CGO_ENABLED=0` 编译出的是完全静态的二进制，不依赖 libc：在 Alpine（musl）上编译，可以直接在 Debian/Ubuntu/RHEL 等 glibc 发行版上运行，反过来也一样。SQLite 用的是纯 Go 驱动 `modernc.org/sqlite`。
- 发行版本身没有限制，真正的运行时依赖只有两个：
  - **内核** ≥ 5.2，并启用 nf_tables、nft_nat/nft_redir、nf_conntrack；
  - **用户态命令** `nft`，以及删除时带 `?kill=true` 才会用到的 `conntrack`（≥ 1.4.5）。
- 支持 amd64、arm64 等 Go 支持的架构，交叉编译即可，例如 `GOARCH=arm64`。
- `deploy/xgate.service` 适用于 systemd 发行版；Alpine 等使用 OpenRC 的系统需要自己编写服务脚本，启动命令同样是 `xgate serve -config …`。

## 安装

```bash
CGO_ENABLED=0 go build -ldflags "-X main.version=$(git describe --always)" -o xgate ./cmd/xgate
install -m 0755 xgate /usr/local/bin/xgate
install -D -m 0640 deploy/config.example.yaml /etc/xgate/config.yaml
install -m 0644 deploy/xgate.service /etc/systemd/system/xgate.service
systemctl daemon-reload && systemctl enable --now xgate
```

`xgate render -config /etc/xgate/config.yaml` 打印当前会写入内核的完整 nft 事务。

## 配置

见 [deploy/config.example.yaml](deploy/config.example.yaml)。要点：

- `forwards` 可以配置多条转发规则，它们共用同一份白名单。
- `protect_target`（默认 true）：丢弃从外部直接访问目标端口的流量，只放行经 redirect 的连接和来自 `lo` 的连接。
- API 默认只监听 `127.0.0.1:7070`，也可以用 `unix:/run/xgate/api.sock`。监听非回环地址时，必须配置 `token`/`token_file` 或 mTLS（`tls.client_ca`），否则拒绝启动。

## API

请求头 `Authorization: Bearer <token>`（配置了 token 时必填）。可选的 `X-Xgate-Actor: <name>` 会和来源地址一起记入审计日志。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/v1/allowlist` | 新增或更新：`{"cidr":"198.51.100.0/24","comment":"office","ttl":"24h","force":false}`。`ttl` 支持 Go duration 和 `7d`；比 `min_prefix_len` 更宽的网段需要 `"force": true` |
| `DELETE` | `/v1/allowlist/{cidr}` | 删除，`/` 可以写成 `%2F`。加 `?kill=true` 会同时清理仍未被其它白名单覆盖的地址上的 conntrack 记录，立即断开已有连接 |
| `GET` | `/v1/allowlist` | 列出有效条目 |
| `POST` | `/v1/allowlist:sync` | 立即与内核对账 |
| `GET` | `/v1/audit?limit=100` | 最近的审计记录（add / update / delete / expire） |
| `GET` | `/healthz` | 最近一次同步成功返回 200，否则返回 503；不需要鉴权 |

```bash
curl -s localhost:7070/v1/allowlist -d '{"cidr":"198.51.100.0/24","comment":"office","ttl":"24h"}'
curl -s -X DELETE 'localhost:7070/v1/allowlist/198.51.100.0%2F24?kill=true'
```

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
