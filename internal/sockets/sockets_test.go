package sockets

import (
	"net/netip"
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	cases := []struct {
		kill bool
		peer string
		port uint16
		want string
	}{
		{true, "198.51.100.0/24", 8080, "-H -t -n -K exclude time-wait dst 198.51.100.0/24 sport = :8080"},
		{false, "2001:db8::/32", 22, "-H -t -n exclude time-wait dst 2001:db8::/32 sport = :22"},
	}
	for _, c := range cases {
		got := strings.Join(Args(c.kill, netip.MustParsePrefix(c.peer), c.port), " ")
		if got != c.want {
			t.Errorf("Args(%v, %s, %d) = %s, want %s", c.kill, c.peer, c.port, got, c.want)
		}
	}
}

func TestCountLines(t *testing.T) {
	out := "ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000\n\nESTAB 0 0 10.0.0.1:22 10.0.0.2:5001\n"
	if n := countLines([]byte(out)); n != 2 {
		t.Errorf("countLines = %d, want 2", n)
	}
	if n := countLines(nil); n != 0 {
		t.Errorf("countLines(nil) = %d, want 0", n)
	}
}
