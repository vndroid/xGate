// Package nft 渲染 xgate 的 nftables 规则，并通过 `nft -f -` 原子地应用。
//
// 每次同步都在同一个事务里重建整张表（确保存在 → 删除 → 按配置和白名单重新定义），
// 因此手动 flush、改动链或 set 都会在下一次对账时被完整纠正，失败时内核整体回滚。
// 已建立连接的 NAT 映射保存在 conntrack 里，不受重建表影响。
package nft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/vndroid/xGate/internal/cidr"
	"github.com/vndroid/xGate/internal/config"
)

// Executor 执行一段 nft 脚本。抽象成接口便于在 macOS 上做单元测试。
type Executor interface {
	Apply(ctx context.Context, script string) error
}

// CmdExecutor 调用 nft 二进制，脚本通过 stdin 传入。
type CmdExecutor struct {
	Binary string
}

func (c CmdExecutor) Apply(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, c.Binary, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s -f -: %w: %s", c.Binary, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Ruleset 是渲染规则所需的静态部分。
type Ruleset struct {
	Table    string
	Forwards []config.Forward
}

// Render 生成完整的事务脚本。items 必须互不重叠（见 cidr.Flatten）。
func (r Ruleset) Render(items []cidr.Item, now time.Time) string {
	var v4, v6 []string
	for _, it := range items {
		el := it.Prefix.String()
		if !it.Expires.IsZero() {
			// 向上取整到秒，至少 1 秒；控制面会在精确的过期时刻再同步一次。
			left := it.Expires.Sub(now)
			secs := int64((left + time.Second - 1) / time.Second)
			if secs < 1 {
				secs = 1
			}
			el += fmt.Sprintf(" timeout %ds", secs)
		}
		if it.Prefix.Addr().Is4() {
			v4 = append(v4, el)
		} else {
			v6 = append(v6, el)
		}
	}

	var b strings.Builder
	t := r.Table
	fmt.Fprintf(&b, "table inet %s {}\n", t)
	fmt.Fprintf(&b, "delete table inet %s\n", t)
	fmt.Fprintf(&b, "table inet %s {\n", t)
	writeSet(&b, "allow_v4", "ipv4_addr", v4)
	writeSet(&b, "allow_v6", "ipv6_addr", v6)

	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	for _, f := range r.Forwards {
		proto := protoExpr(f.Protocols)
		for _, fam := range [][2]string{{"ip", "allow_v4"}, {"ip6", "allow_v6"}} {
			fmt.Fprintf(&b, "\t\t%s saddr @%s meta l4proto %s th dport %d redirect to :%d comment %q\n",
				fam[0], fam[1], proto, f.ListenPort, f.TargetPort, f.Name)
		}
	}
	b.WriteString("\t}\n")

	b.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n")
	for _, f := range r.Forwards {
		proto := protoExpr(f.Protocols)
		if f.Protected() {
			fmt.Fprintf(&b, "\t\tmeta l4proto %s th dport %d ct status dnat accept\n", proto, f.TargetPort)
			fmt.Fprintf(&b, "\t\tmeta l4proto %s th dport %d iifname != \"lo\" drop\n", proto, f.TargetPort)
		}
		// 不在白名单里的请求没有被 redirect，直接在监听端口上丢弃。
		fmt.Fprintf(&b, "\t\tmeta l4proto %s th dport %d drop\n", proto, f.ListenPort)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func writeSet(b *strings.Builder, name, typ string, elems []string) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s; flags interval, timeout;\n", name, typ)
	if len(elems) > 0 {
		b.WriteString("\t\telements = {\n")
		for i, e := range elems {
			sep := ","
			if i == len(elems)-1 {
				sep = ""
			}
			fmt.Fprintf(b, "\t\t\t%s%s\n", e, sep)
		}
		b.WriteString("\t\t}\n")
	}
	b.WriteString("\t}\n")
}

func protoExpr(protos []string) string {
	if len(protos) == 1 {
		return protos[0]
	}
	return "{ " + strings.Join(protos, ", ") + " }"
}
