// Package cidr 负责网段的解析、规范化，以及把可能重叠的白名单
// 展开成互不重叠的区间（nft interval set 不接受重叠元素）。
package cidr

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Parse 解析 CIDR 或单个 IP（视为 /32 或 /128），并做规范化：
// 主机位清零，IPv4-mapped IPv6 地址转成 IPv4。
func Parse(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty cidr")
	}
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %q: %w", s, err)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %q: %w", s, err)
		}
		if a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %q: zones are not allowed", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("invalid cidr %q: ipv4-mapped prefix shorter than /96", s)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// Overlaps 判断两个网段是否有交集。
func Overlaps(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && a.Overlaps(b)
}

// Covers 判断 a 是否完整包含 b。
func Covers(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && a.Bits() <= b.Bits() && a.Contains(b.Addr())
}

// Subtract 返回 p 去掉所有 holes 后剩余部分，以最少的前缀表示。
func Subtract(p netip.Prefix, holes []netip.Prefix) []netip.Prefix {
	var rel []netip.Prefix
	for _, h := range holes {
		if Overlaps(p, h) {
			if Covers(h, p) {
				return nil
			}
			rel = append(rel, h)
		}
	}
	if len(rel) == 0 {
		return []netip.Prefix{p}
	}
	lo, hi := split(p)
	return append(Subtract(lo, rel), Subtract(hi, rel)...)
}

// split 把 p 平分成两个长度 +1 的子网段。调用方保证 p 不是主机路由。
func split(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	b := p.Addr().AsSlice()
	i := p.Bits() / 8
	b[i] |= 0x80 >> (p.Bits() % 8)
	hiAddr, _ := netip.AddrFromSlice(b)
	return lo, netip.PrefixFrom(hiAddr, bits)
}

// Item 是一个带过期时间的网段；Expires 为零值表示永久。
type Item struct {
	Prefix  netip.Prefix
	Expires time.Time
}

func outlives(a, b Item) bool {
	switch {
	case a.Expires.IsZero():
		return !b.Expires.IsZero()
	case b.Expires.IsZero():
		return false
	default:
		return a.Expires.After(b.Expires)
	}
}

// Flatten 把可能重叠的白名单展开成互不重叠的区间。
// 每个地址都归属于覆盖它、且存活最久的那条记录，因此即使控制面
// 停止运行，内核按各区间自身的 timeout 过期，结果仍与 SQLite 中的语义一致。
// 返回结果按地址排序。
func Flatten(items []Item) []Item {
	sorted := append([]Item(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if outlives(a, b) || outlives(b, a) {
			return outlives(a, b)
		}
		return a.Prefix.Bits() < b.Prefix.Bits()
	})
	var out []Item
	var taken []netip.Prefix
	for _, it := range sorted {
		for _, piece := range Subtract(it.Prefix, taken) {
			out = append(out, Item{Prefix: piece, Expires: it.Expires})
		}
		taken = append(taken, it.Prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Prefix, out[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	return out
}
