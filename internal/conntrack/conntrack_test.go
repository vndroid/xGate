package conntrack

import (
	"net/netip"
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	cases := []struct {
		f    Flow
		want string
	}{
		{
			f:    Flow{Src: netip.MustParsePrefix("198.51.100.0/24"), Proto: "tcp", DPort: 35353},
			want: "-D -f ipv4 -p tcp -s 198.51.100.0 --mask-src 255.255.255.0 --orig-port-dst 35353",
		},
		{
			f:    Flow{Src: netip.MustParsePrefix("2001:db8::/32"), Proto: "udp", DPort: 53},
			want: "-D -f ipv6 -p udp -s 2001:db8:: --mask-src ffff:ffff:: --orig-port-dst 53",
		},
	}
	for _, c := range cases {
		if got := strings.Join(Args(c.f), " "); got != c.want {
			t.Errorf("Args(%+v) = %s, want %s", c.f, got, c.want)
		}
	}
}
