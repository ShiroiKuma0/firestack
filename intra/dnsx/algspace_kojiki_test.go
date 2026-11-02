package dnsx

import (
	"net/netip"
	"testing"
)

func TestIsAlgSpace(t *testing.T) {
	cases := []struct {
		ip     string
		v4, ok bool
	}{
		{"64:ff9b:1:da19:100:ed49:cae5:bc60", false, true},
		{"64:ff9b:1:da19:100::1", true, true},
		{"64:ff9b::808:808", true, false},          // well-known nat64, not alg
		{"64:ff9b:1:da19:101::1", true, false},     // outside the /80
		{"100.74.49.249", true, true},
		{"100.74.49.249", false, false},            // alg off: a real cgnat peer
		{"100.128.0.1", true, false},
		{"::ffff:100.64.0.1", true, true},
		{"8.8.8.8", true, false},
	}
	for _, c := range cases {
		if got := IsAlgSpace(netip.MustParseAddr(c.ip), c.v4); got != c.ok {
			t.Errorf("IsAlgSpace(%s, %t) = %t, want %t", c.ip, c.v4, got, c.ok)
		}
	}
	// every ip gen6Locked mints must count as alg space
	for i := range 64 {
		if ip := gen6Locked("example.com", i); !IsAlgSpace(ip, false) {
			t.Errorf("gen6Locked minted %s outside alg space", ip)
		}
		if ip := gen4Locked("example.com", i); !IsAlgSpace(ip, true) {
			t.Errorf("gen4Locked minted %s outside alg space", ip)
		}
	}
}
