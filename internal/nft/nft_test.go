package nft

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vndroid/xGate/internal/cidr"
	"github.com/vndroid/xGate/internal/config"
)

func TestRender(t *testing.T) {
	no := false
	rs := Ruleset{
		Table: "xgate",
		Forwards: []config.Forward{
			{Name: "default", ListenPort: 35353, TargetPort: 8080, Protocols: []string{"tcp", "udp"}},
			{Name: "dns", ListenPort: 5353, TargetPort: 53, Protocols: []string{"udp"}, ProtectTarget: &no},
		},
	}
	now := time.Unix(1_700_000_000, 0)
	items := []cidr.Item{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24")},
		{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Expires: now.Add(90*time.Minute + 200*time.Millisecond)},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Expires: now.Add(-time.Second)},
	}
	want := `table inet xgate {}
delete table inet xgate
table inet xgate {
	set allow_v4 {
		type ipv4_addr; flags interval, timeout;
		elements = {
			198.51.100.0/24,
			203.0.113.7/32 timeout 5401s
		}
	}
	set allow_v6 {
		type ipv6_addr; flags interval, timeout;
		elements = {
			2001:db8::/32 timeout 1s
		}
	}
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip saddr @allow_v4 meta l4proto { tcp, udp } th dport 35353 redirect to :8080 comment "default"
		ip6 saddr @allow_v6 meta l4proto { tcp, udp } th dport 35353 redirect to :8080 comment "default"
		ip saddr @allow_v4 meta l4proto udp th dport 5353 redirect to :53 comment "dns"
		ip6 saddr @allow_v6 meta l4proto udp th dport 5353 redirect to :53 comment "dns"
	}
	chain input {
		type filter hook input priority filter; policy accept;
		meta l4proto { tcp, udp } th dport 8080 ct status dnat accept
		meta l4proto { tcp, udp } th dport 8080 iifname != "lo" drop
		meta l4proto { tcp, udp } th dport 35353 drop
		meta l4proto udp th dport 5353 drop
	}
}
`
	if got := rs.Render(items, now); got != want {
		t.Errorf("Render mismatch.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderEmptySets(t *testing.T) {
	rs := Ruleset{Table: "xgate", Forwards: []config.Forward{{Name: "a", ListenPort: 1, TargetPort: 2, Protocols: []string{"tcp"}}}}
	got := rs.Render(nil, time.Now())
	want := "\tset allow_v4 {\n\t\ttype ipv4_addr; flags interval, timeout;\n\t}\n"
	if !strings.Contains(got, want) {
		t.Errorf("empty set not rendered as expected:\n%s", got)
	}
}
