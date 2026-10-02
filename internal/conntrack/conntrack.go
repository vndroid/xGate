// Package conntrack 在删除白名单时清理已建立连接的 conntrack 记录，
// 否则这些连接会依靠已有的 NAT 映射继续存活。
package conntrack

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
)

// Flow 描述要清理的一类连接：来源在 Src 内、原始目的端口为 DPort。
type Flow struct {
	Src   netip.Prefix
	Proto string // tcp 或 udp
	DPort uint16
}

type Killer interface {
	// Kill 删除匹配的 conntrack 记录，返回删除条数。
	Kill(ctx context.Context, f Flow) (int, error)
}

// CmdKiller 调用 conntrack-tools（需要 1.4.5+ 以支持 --mask-src）。
type CmdKiller struct {
	Binary string
}

var deletedRe = regexp.MustCompile(`(\d+) flow entries have been deleted`)

func (c CmdKiller) Kill(ctx context.Context, f Flow) (int, error) {
	cmd := exec.CommandContext(ctx, c.Binary, Args(f)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	// 没有匹配记录时 conntrack 以非零状态退出，但仍会输出 "0 flow entries ..."。
	if m := deletedRe.FindSubmatch(out.Bytes()); m != nil {
		n, _ := strconv.Atoi(string(m[1]))
		return n, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%s %v: %w: %s", c.Binary, Args(f), err, bytes.TrimSpace(out.Bytes()))
	}
	return 0, nil
}

// Args 返回 conntrack 命令行参数。
func Args(f Flow) []string {
	family, bits := "ipv4", 32
	if f.Src.Addr().Is6() {
		family, bits = "ipv6", 128
	}
	mask, _ := netip.AddrFromSlice(net.CIDRMask(f.Src.Bits(), bits))
	return []string{
		"-D", "-f", family, "-p", f.Proto,
		"-s", f.Src.Addr().String(), "--mask-src", mask.String(),
		"--orig-port-dst", strconv.Itoa(int(f.DPort)),
	}
}
