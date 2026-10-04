// Package sockets 在删除白名单时主动断开已建立的 TCP 连接。
//
// 只清理 conntrack 时，连接的后续报文不再做地址转换，两端都收不到任何通知：
// 客户端会一直挂着，后端的 socket 也要等 TCP 重传超时（约 15 分钟，空闲连接则永远不会）
// 才会释放。这里通过 SOCK_DESTROY（`ss -K`）销毁本机后端上对应的 socket，内核会向两端
// 各发一个 RST。必须在清理 conntrack 之前调用，RST 才能被反向转换回监听端口、到达客户端。
package sockets

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// Destroyer 销毁本机上源端口为 localPort、对端地址在 peer 内的 TCP socket。
type Destroyer interface {
	// Destroy 返回被销毁的 socket 数。内核不支持 SOCK_DESTROY
	// （未开启 CONFIG_INET_DIAG_DESTROY）时，socket 会残留，此时返回错误。
	Destroy(ctx context.Context, peer netip.Prefix, localPort uint16) (int, error)
}

// CmdDestroyer 调用 iproute2 的 ss。
type CmdDestroyer struct {
	Binary string
}

func (c CmdDestroyer) Destroy(ctx context.Context, peer netip.Prefix, localPort uint16) (int, error) {
	out, err := c.run(ctx, true, peer, localPort)
	if err != nil {
		return 0, err
	}
	killed := countLines(out)
	// ss -K 在内核不支持时不会报错，只是什么也不做，所以再查一次确认。
	out, err = c.run(ctx, false, peer, localPort)
	if err != nil {
		return killed, err
	}
	if left := countLines(out); left > 0 {
		return killed, fmt.Errorf("%d tcp sockets from %s on port %d were not destroyed (kernel without CONFIG_INET_DIAG_DESTROY?)", left, peer, localPort)
	}
	return killed, nil
}

func (c CmdDestroyer) run(ctx context.Context, kill bool, peer netip.Prefix, localPort uint16) ([]byte, error) {
	args := Args(kill, peer, localPort)
	cmd := exec.CommandContext(ctx, c.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", c.Binary, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Args 返回 ss 的命令行参数。TIME_WAIT 的 socket 已经没有连接可断，不在范围内。
func Args(kill bool, peer netip.Prefix, localPort uint16) []string {
	args := []string{"-H", "-t", "-n"}
	if kill {
		args = append(args, "-K")
	}
	return append(args, "exclude", "time-wait", "dst", peer.String(), "sport", "=", ":"+strconv.Itoa(int(localPort)))
}

func countLines(b []byte) int {
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}
