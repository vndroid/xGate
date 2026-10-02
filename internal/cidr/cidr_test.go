package cidr

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "198.51.100.7/24", want: "198.51.100.0/24"},
		{in: " 198.51.100.7 ", want: "198.51.100.7/32"},
		{in: "2001:db8::1/32", want: "2001:db8::/32"},
		{in: "2001:db8::1", want: "2001:db8::1/128"},
		{in: "::ffff:198.51.100.0/120", want: "198.51.100.0/24"},
		{in: "::ffff:198.51.100.9", want: "198.51.100.9/32"},
		{in: "0.0.0.0/0", want: "0.0.0.0/0"},
		{in: "", wantErr: true},
		{in: "198.51.100.0/33", wantErr: true},
		{in: "not-an-ip", wantErr: true},
		{in: "fe80::1%eth0", wantErr: true},
		{in: "::ffff:0:0/80", wantErr: true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil || got.String() != c.want {
			t.Errorf("Parse(%q) = %v, %v; want %s", c.in, got, err, c.want)
		}
	}
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestSubtract(t *testing.T) {
	cases := []struct {
		p     string
		holes []string
		want  []string
	}{
		{p: "10.0.0.0/24", holes: nil, want: []string{"10.0.0.0/24"}},
		{p: "10.0.0.0/24", holes: []string{"10.0.0.0/8"}, want: nil},
		{p: "10.0.0.0/24", holes: []string{"10.0.1.0/24", "2001:db8::/32"}, want: []string{"10.0.0.0/24"}},
		{p: "10.0.0.0/24", holes: []string{"10.0.0.0/25"}, want: []string{"10.0.0.128/25"}},
		{p: "10.0.0.0/24", holes: []string{"10.0.0.64/26"}, want: []string{"10.0.0.0/26", "10.0.0.128/25"}},
		{p: "10.0.0.0/30", holes: []string{"10.0.0.1/32", "10.0.0.2/32"}, want: []string{"10.0.0.0/32", "10.0.0.3/32"}},
		{p: "2001:db8::/126", holes: []string{"2001:db8::3/128"}, want: []string{"2001:db8::/127", "2001:db8::2/128"}},
	}
	for _, c := range cases {
		got := Subtract(netip.MustParsePrefix(c.p), prefixes(c.holes...))
		if !reflect.DeepEqual(got, prefixes(c.want...)) {
			t.Errorf("Subtract(%s, %v) = %v, want %v", c.p, c.holes, got, c.want)
		}
	}
}

func TestFlatten(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	soon, later := now.Add(time.Hour), now.Add(2*time.Hour)
	it := func(p string, exp time.Time) Item { return Item{Prefix: netip.MustParsePrefix(p), Expires: exp} }

	cases := []struct {
		name string
		in   []Item
		want []Item
	}{
		{
			name: "disjoint",
			in:   []Item{it("10.0.1.0/24", soon), it("10.0.0.0/24", time.Time{}), it("2001:db8::/32", later)},
			want: []Item{it("10.0.0.0/24", time.Time{}), it("10.0.1.0/24", soon), it("2001:db8::/32", later)},
		},
		{
			name: "permanent parent absorbs child",
			in:   []Item{it("10.1.0.0/16", soon), it("10.0.0.0/8", time.Time{})},
			want: []Item{it("10.0.0.0/8", time.Time{})},
		},
		{
			name: "longer-lived child carved out of parent",
			in:   []Item{it("10.0.0.0/24", soon), it("10.0.0.128/25", later)},
			want: []Item{it("10.0.0.0/25", soon), it("10.0.0.128/25", later)},
		},
		{
			name: "equal expiry keeps the wider prefix",
			in:   []Item{it("10.0.0.0/25", soon), it("10.0.0.0/24", soon)},
			want: []Item{it("10.0.0.0/24", soon)},
		},
	}
	for _, c := range cases {
		if got := Flatten(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Flatten = %v, want %v", c.name, got, c.want)
		}
	}
}
