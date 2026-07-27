package specialuse

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type Entry struct {
	Prefix            netip.Prefix
	GloballyReachable bool
}
type Registry []Entry

func Load(r io.Reader) (Registry, error) {
	records, err := csv.NewReader(r).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("special-use registry has no rows")
	}
	indices := map[string]int{}
	for i, name := range records[0] {
		indices[name] = i
	}
	block, ok := indices["Address Block"]
	if !ok {
		return nil, fmt.Errorf("missing Address Block header")
	}
	reachable, ok := indices["Globally Reachable"]
	if !ok {
		return nil, fmt.Errorf("missing Globally Reachable header")
	}
	entries := make(Registry, 0, len(records)-1)
	for _, row := range records[1:] {
		if len(row) <= reachable || len(row) <= block {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.Fields(row[block])[0])
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		entries = append(entries, Entry{Prefix: prefix, GloballyReachable: row[reachable] == "True"})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Prefix.Bits() > entries[j].Prefix.Bits() })
	return entries, nil
}

func IsPermittedPublicIPv4(address netip.Addr, registry Registry, deniedNetworks []netip.Prefix, deniedAddresses []netip.Addr) bool {
	if !address.Is4() || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") {
		return false
	}
	for _, network := range deniedNetworks {
		if network.Contains(address) {
			return false
		}
	}
	for _, denied := range deniedAddresses {
		if denied == address {
			return false
		}
	}
	for _, entry := range registry {
		if entry.Prefix.Contains(address) {
			return entry.GloballyReachable
		}
	}
	// No special-use match means the address is ordinary public IPv4.
	return true
}
