package specialuse

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestPermittedPublicIPv4(t *testing.T) {
	f, err := os.Open("../../contracts/v1/ipv4-special-use.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	registry, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		address string
		want    bool
	}{
		{"1.1.1.1", true}, {"8.8.8.8", true}, {"10.0.0.1", false},
		{"100.64.0.1", false}, {"127.0.0.1", false}, {"169.254.1.1", false},
		{"172.16.0.1", false}, {"192.0.0.9", true}, {"192.0.2.1", false},
		{"192.168.1.1", false}, {"198.18.0.1", false}, {"198.51.100.1", false},
		{"203.0.113.1", false}, {"224.0.0.1", false}, {"240.0.0.1", false},
		{"255.255.255.255", false},
	}
	for _, tt := range tests {
		address := netip.MustParseAddr(tt.address)
		if got := IsPermittedPublicIPv4(address, registry, nil, nil); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.address, got, tt.want)
		}
	}
	if IsPermittedPublicIPv4(netip.MustParseAddr("1.1.1.1"), registry, []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}, nil) {
		t.Error("docker subnet must deny")
	}
	if IsPermittedPublicIPv4(netip.MustParseAddr("8.8.8.8"), registry, nil, []netip.Addr{netip.MustParseAddr("8.8.8.8")}) {
		t.Error("management address must deny")
	}
}

func TestLoadParsesEveryPrefixInMultiPrefixRows(t *testing.T) {
	const registryCSV = `Address Block,Globally Reachable
"192.0.0.170/32, 192.0.0.171/32",False
`
	registry, err := Load(strings.NewReader(registryCSV))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, entry := range registry {
		got[entry.Prefix.String()] = true
	}
	for _, want := range []string{"192.0.0.170/32", "192.0.0.171/32"} {
		if !got[want] {
			t.Errorf("missing %s", want)
		}
	}
}
