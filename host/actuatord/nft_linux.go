//go:build linux

package actuatord

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"agmind.local/sais/internal/contracts"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	nftRulesetHashDomain = "AGMIND_NFT_RULESET_V1\x00"
	nftIOTimeout         = 10 * time.Second
	nftaSetHandle        = uint16(0x10)
	nftaSetExpr          = uint16(0x11)
	nftaSetExpressions   = uint16(0x12)
	nftaSetType          = uint16(0x13)
	nftaSetCount         = uint16(0x14)
	nftaChainFlags       = uint16(0x0a)
	nftaChainID          = uint16(0x0b)
	nftaChainUserdata    = uint16(0x0c)
	nftaHookDevices      = uint16(0x04)
	nftChainBase         = uint32(1 << 0)
	nftaSetElemKeyEnd    = uint16(0x0a)
	nftaSetElemExprs     = uint16(0x0b)
)

type platformNftBackend struct{}

type linuxPreparedNftMutation struct {
	mutex        sync.Mutex
	conn         *nftables.Conn
	target       ApplyTargetHandle
	spec         NftApplySpec
	table        *nftables.Table
	chain        *nftables.Chain
	set          *nftables.Set
	expectedHash string
	flushed      bool
	closed       bool
}

type normalizedNftRuleset struct {
	SchemaVersion        string `json:"schema_version"`
	Owner                string `json:"owner"`
	Family               string `json:"family"`
	Table                string `json:"table"`
	Chain                string `json:"chain"`
	ChainType            string `json:"chain_type"`
	Hook                 string `json:"hook"`
	Priority             int32  `json:"priority"`
	Policy               string `json:"policy"`
	Set                  string `json:"set"`
	SetKeyType           string `json:"set_key_type"`
	SetTimeoutEnabled    bool   `json:"set_timeout_enabled"`
	Rule                 string `json:"rule"`
	DestinationIPv4      string `json:"destination_ipv4"`
	ElementTimeoutMillis uint64 `json:"element_timeout_ms"`
}

func NewPlatformNftBackend() NftBackend { return platformNftBackend{} }

func newBoundNftConn(netnsFD int) (*nftables.Conn, error) {
	if netnsFD < 3 {
		return nil, ErrTargetStale
	}
	deadline := time.Now().Add(nftIOTimeout)
	return nftables.New(
		nftables.WithNetNSFd(netnsFD),
		nftables.AsLasting(),
		nftables.WithSockOptions(func(conn *netlink.Conn) error {
			return conn.SetDeadline(deadline)
		}),
	)
}

func expectedNftRulesetSHA256(spec NftApplySpec) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	normalized := normalizedNftRuleset{
		SchemaVersion:        "agmind.nft-ruleset.v1",
		Owner:                nftOwnerMarker,
		Family:               "ip",
		Table:                nftTableName,
		Chain:                nftChainName,
		ChainType:            "filter",
		Hook:                 "output",
		Priority:             -10,
		Policy:               "accept",
		Set:                  nftSetName,
		SetKeyType:           "ipv4_addr",
		SetTimeoutEnabled:    true,
		Rule:                 "ip daddr @blocked_v4 counter drop",
		DestinationIPv4:      spec.DestinationIPv4,
		ElementTimeoutMillis: uint64(spec.TTL / time.Millisecond),
	}
	canonical, err := contracts.CanonicalJSON(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(nftRulesetHashDomain), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func canonicalNftObjects(
	spec NftApplySpec,
) (*nftables.Table, *nftables.Chain, *nftables.Set, nftables.SetElement, *nftables.Rule, error) {
	if err := spec.validate(); err != nil {
		return nil, nil, nil, nftables.SetElement{}, nil, err
	}
	destination, _ := netip.ParseAddr(spec.DestinationIPv4)
	key := destination.As4()
	hook := nftables.ChainHook(*nftables.ChainHookOutput)
	priority := nftables.ChainPriority(-10)
	policy := nftables.ChainPolicyAccept
	table := &nftables.Table{
		Name:   nftTableName,
		Family: nftables.TableFamilyIPv4,
	}
	chain := &nftables.Chain{
		Name:     nftChainName,
		Table:    table,
		Hooknum:  &hook,
		Priority: &priority,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policy,
	}
	set := &nftables.Set{
		Table:      table,
		ID:         1,
		Name:       nftSetName,
		HasTimeout: true,
		Timeout:    0,
		KeyType:    nftables.TypeIPAddr,
		Comment:    nftOwnerMarker,
	}
	element := nftables.SetElement{
		Key:     append([]byte(nil), key[:]...),
		Timeout: spec.TTL,
		Comment: nftOwnerMarker,
	}
	rule := &nftables.Rule{
		Table:    table,
		Chain:    chain,
		UserData: []byte(nftOwnerMarker),
		Exprs: []expr.Any{
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        nftSetName,
				SetID:          1,
			},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	}
	return table, chain, set, element, rule, nil
}

func matchingNftTables(conn *nftables.Conn) ([]*nftables.Table, error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	matching := make([]*nftables.Table, 0, 1)
	for _, table := range tables {
		if table != nil && table.Name == nftTableName {
			matching = append(matching, table)
		}
	}
	return matching, nil
}

func matchingNftChains(
	conn *nftables.Conn,
	table *nftables.Table,
) ([]*nftables.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}
	matching := make([]*nftables.Chain, 0, 1)
	for _, chain := range chains {
		if chain != nil && chain.Table != nil &&
			chain.Table.Name == table.Name && chain.Table.Family == table.Family {
			matching = append(matching, chain)
		}
	}
	return matching, nil
}

func exactNftChain(chain *nftables.Chain) bool {
	return chain != nil && chain.Table != nil && chain.Name == nftChainName &&
		chain.Table.Name == nftTableName &&
		chain.Table.Family == nftables.TableFamilyIPv4 &&
		chain.Hooknum != nil && *chain.Hooknum == *nftables.ChainHookOutput &&
		chain.Priority != nil && *chain.Priority == nftables.ChainPriority(-10) &&
		chain.Type == nftables.ChainTypeFilter && chain.Policy != nil &&
		*chain.Policy == nftables.ChainPolicyAccept && chain.Device == ""
}

func normalizeKernelUint32(value uint32) uint32 {
	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], value)
	return binary.BigEndian.Uint32(raw[:])
}

func exactNftSet(set *nftables.Set) bool {
	return set != nil && set.Table != nil && set.Name == nftSetName &&
		set.Table.Name == nftTableName &&
		set.Table.Family == nftables.TableFamilyIPv4 &&
		set.HasTimeout && set.Timeout == 0 &&
		set.KeyType.Name == nftables.TypeIPAddr.Name &&
		set.KeyType.Bytes == nftables.TypeIPAddr.Bytes &&
		!set.Anonymous && !set.Constant && !set.Interval && !set.AutoMerge &&
		!set.IsMap && !set.Counter && !set.Dynamic && !set.Concatenation &&
		set.Size == 0
}

func exactNftRule(
	rule *nftables.Rule,
	table *nftables.Table,
	chain *nftables.Chain,
) (*expr.Counter, bool) {
	if rule == nil || rule.Table == nil || rule.Chain == nil ||
		rule.Table.Name != table.Name || rule.Table.Family != table.Family ||
		rule.Chain.Name != chain.Name || rule.Flags != 0 ||
		!bytes.Equal(rule.UserData, []byte(nftOwnerMarker)) || len(rule.Exprs) != 4 {
		return nil, false
	}
	payload, payloadOK := rule.Exprs[0].(*expr.Payload)
	lookup, lookupOK := rule.Exprs[1].(*expr.Lookup)
	counter, counterOK := rule.Exprs[2].(*expr.Counter)
	verdict, verdictOK := rule.Exprs[3].(*expr.Verdict)
	if !payloadOK || payload.OperationType != expr.PayloadLoad ||
		payload.DestRegister != 1 || payload.SourceRegister != 0 ||
		payload.Base != expr.PayloadBaseNetworkHeader || payload.Offset != 16 ||
		payload.Len != 4 || payload.CsumType != expr.CsumTypeNone ||
		payload.CsumOffset != 0 || payload.CsumFlags != 0 ||
		!lookupOK || lookup.SourceRegister != 1 || lookup.IsDestRegSet ||
		lookup.DestRegister != 0 || lookup.SetName != nftSetName || lookup.Invert ||
		!counterOK || !verdictOK || verdict.Kind != expr.VerdictDrop ||
		verdict.Chain != "" {
		return nil, false
	}
	return counter, true
}

func safeGetSetElements(
	conn *nftables.Conn,
	set *nftables.Set,
) (elements []nftables.SetElement, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			elements = nil
			err = fmt.Errorf("malformed nft element userdata")
		}
	}()
	return conn.GetSetElements(set)
}

func safeGetSets(
	conn *nftables.Conn,
	table *nftables.Table,
) (sets []*nftables.Set, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			sets = nil
			err = fmt.Errorf("malformed nft set userdata")
		}
	}()
	return conn.GetSets(table)
}

func rawVerifyExactNftHook(raw []byte) error {
	decoder, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return err
	}
	decoder.ByteOrder = binary.BigEndian
	seen := make(map[uint16]bool)
	for decoder.Next() {
		attributeType := decoder.Type()
		if seen[attributeType] {
			return fmt.Errorf("%w: duplicate hook attribute %d", ErrForeignNftCollision, attributeType)
		}
		seen[attributeType] = true
		switch attributeType {
		case unix.NFTA_HOOK_HOOKNUM:
			if decoder.Uint32() != uint32(*nftables.ChainHookOutput) {
				return fmt.Errorf("%w: chain hook", ErrForeignNftCollision)
			}
		case unix.NFTA_HOOK_PRIORITY:
			if decoder.Uint32() != ^uint32(9) {
				return fmt.Errorf("%w: chain priority", ErrForeignNftCollision)
			}
		case unix.NFTA_HOOK_DEV, nftaHookDevices:
			return fmt.Errorf("%w: chain device binding", ErrForeignNftCollision)
		default:
			return fmt.Errorf("%w: unknown hook attribute %d", ErrForeignNftCollision, attributeType)
		}
	}
	if err := decoder.Err(); err != nil {
		return err
	}
	if !seen[unix.NFTA_HOOK_HOOKNUM] || !seen[unix.NFTA_HOOK_PRIORITY] {
		return fmt.Errorf("%w: incomplete chain hook", ErrForeignNftCollision)
	}
	return nil
}

func rawVerifyExactNftChain(netnsFD int) error {
	if netnsFD < 3 {
		return ErrTargetStale
	}
	conn, err := netlink.Dial(
		unix.NETLINK_NETFILTER,
		&netlink.Config{NetNS: netnsFD},
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(nftIOTimeout)); err != nil {
		return err
	}
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(nftTableName + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(nftChainName + "\x00")},
	})
	if err != nil {
		return err
	}
	replies, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type: netlink.HeaderType(
				(unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETCHAIN,
			),
			Flags: netlink.Request,
		},
		Data: append(
			[]byte{byte(nftables.TableFamilyIPv4), unix.NFNETLINK_V0, 0, 0},
			attributes...,
		),
	})
	if err != nil {
		return err
	}
	if len(replies) != 1 || len(replies[0].Data) < 4 ||
		replies[0].Data[0] != byte(nftables.TableFamilyIPv4) ||
		replies[0].Data[1] != unix.NFNETLINK_V0 {
		return fmt.Errorf("%w: invalid raw chain reply", ErrForeignNftCollision)
	}
	decoder, err := netlink.NewAttributeDecoder(replies[0].Data[4:])
	if err != nil {
		return err
	}
	decoder.ByteOrder = binary.BigEndian
	seen := make(map[uint16]bool)
	for decoder.Next() {
		attributeType := decoder.Type()
		if seen[attributeType] && attributeType != unix.NFTA_CHAIN_PAD {
			return fmt.Errorf("%w: duplicate chain attribute %d", ErrForeignNftCollision, attributeType)
		}
		seen[attributeType] = true
		switch attributeType {
		case unix.NFTA_CHAIN_TABLE:
			if decoder.String() != nftTableName {
				return fmt.Errorf("%w: chain table", ErrForeignNftCollision)
			}
		case unix.NFTA_CHAIN_HANDLE:
			value := decoder.Bytes()
			if len(value) != 8 || binary.BigEndian.Uint64(value) == 0 {
				return fmt.Errorf("%w: chain handle", ErrForeignNftCollision)
			}
		case unix.NFTA_CHAIN_NAME:
			if decoder.String() != nftChainName {
				return fmt.Errorf("%w: chain name", ErrForeignNftCollision)
			}
		case unix.NFTA_CHAIN_HOOK:
			if flags := decoder.TypeFlags(); flags != 0 && flags != unix.NLA_F_NESTED {
				return fmt.Errorf("%w: chain hook encoding", ErrForeignNftCollision)
			}
			if err := rawVerifyExactNftHook(decoder.Bytes()); err != nil {
				return err
			}
		case unix.NFTA_CHAIN_POLICY:
			if decoder.Uint32() != uint32(nftables.ChainPolicyAccept) {
				return fmt.Errorf("%w: chain policy", ErrForeignNftCollision)
			}
		case unix.NFTA_CHAIN_USE:
			if decoder.Uint32() != 1 {
				return fmt.Errorf("%w: chain use", ErrForeignNftCollision)
			}
		case unix.NFTA_CHAIN_TYPE:
			if decoder.String() != string(nftables.ChainTypeFilter) {
				return fmt.Errorf("%w: chain type", ErrForeignNftCollision)
			}
		case nftaChainFlags:
			if decoder.Uint32() != nftChainBase {
				return fmt.Errorf("%w: chain flags", ErrForeignNftCollision)
			}
		case unix.NFTA_CHAIN_PAD:
			for _, value := range decoder.Bytes() {
				if value != 0 {
					return fmt.Errorf("%w: chain padding", ErrForeignNftCollision)
				}
			}
		case unix.NFTA_CHAIN_COUNTERS, nftaChainID, nftaChainUserdata:
			return fmt.Errorf("%w: forbidden chain attribute %d", ErrForeignNftCollision, attributeType)
		default:
			return fmt.Errorf("%w: unknown chain attribute %d", ErrForeignNftCollision, attributeType)
		}
	}
	if err := decoder.Err(); err != nil {
		return err
	}
	for _, required := range []uint16{
		unix.NFTA_CHAIN_TABLE,
		unix.NFTA_CHAIN_HANDLE,
		unix.NFTA_CHAIN_NAME,
		unix.NFTA_CHAIN_HOOK,
		unix.NFTA_CHAIN_POLICY,
		unix.NFTA_CHAIN_USE,
		unix.NFTA_CHAIN_TYPE,
		nftaChainFlags,
	} {
		if !seen[required] {
			return fmt.Errorf("%w: missing chain attribute %d", ErrForeignNftCollision, required)
		}
	}
	return nil
}

func validNftBackendType(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '.' || character == '+' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func rawVerifyExactNftSet(netnsFD int, expectedElementCount uint32) error {
	if netnsFD < 3 {
		return ErrTargetStale
	}
	conn, err := netlink.Dial(
		unix.NETLINK_NETFILTER,
		&netlink.Config{NetNS: netnsFD},
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(nftIOTimeout)); err != nil {
		return err
	}
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_SET_TABLE, Data: []byte(nftTableName + "\x00")},
		{Type: unix.NFTA_SET_NAME, Data: []byte(nftSetName + "\x00")},
	})
	if err != nil {
		return err
	}
	message := netlink.Message{
		Header: netlink.Header{
			Type: netlink.HeaderType(
				(unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETSET,
			),
			Flags: netlink.Request,
		},
		Data: append(
			[]byte{byte(nftables.TableFamilyIPv4), unix.NFNETLINK_V0, 0, 0},
			attributes...,
		),
	}
	replies, err := conn.Execute(message)
	if err != nil {
		return err
	}
	if len(replies) != 1 || len(replies[0].Data) < 4 ||
		replies[0].Data[0] != byte(nftables.TableFamilyIPv4) ||
		replies[0].Data[1] != unix.NFNETLINK_V0 {
		return fmt.Errorf("%w: invalid raw set reply", ErrForeignNftCollision)
	}
	decoder, err := netlink.NewAttributeDecoder(replies[0].Data[4:])
	if err != nil {
		return err
	}
	decoder.ByteOrder = binary.BigEndian
	seen := make(map[uint16]bool)
	expectedUserdata := userdata.AppendString(
		nil,
		userdata.NFTNL_UDATA_SET_COMMENT,
		nftOwnerMarker,
	)
	for decoder.Next() {
		attributeType := decoder.Type()
		if seen[attributeType] && attributeType != unix.NFTA_SET_PAD {
			return fmt.Errorf("%w: duplicate set attribute %d", ErrForeignNftCollision, attributeType)
		}
		seen[attributeType] = true
		switch attributeType {
		case unix.NFTA_SET_TABLE:
			if decoder.String() != nftTableName {
				return fmt.Errorf("%w: set table", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_NAME:
			if decoder.String() != nftSetName {
				return fmt.Errorf("%w: set name", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_FLAGS:
			if decoder.Uint32() != uint32(unix.NFT_SET_TIMEOUT) {
				return fmt.Errorf("%w: set flags", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_KEY_TYPE:
			if decoder.Uint32() != nftables.TypeIPAddr.GetNFTMagic() {
				return fmt.Errorf("%w: set key type", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_KEY_LEN:
			if decoder.Uint32() != nftables.TypeIPAddr.Bytes {
				return fmt.Errorf("%w: set key length", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_USERDATA:
			if !bytes.Equal(decoder.Bytes(), expectedUserdata) {
				return fmt.Errorf("%w: set ownership userdata", ErrForeignNftCollision)
			}
		case nftaSetHandle:
			value := decoder.Bytes()
			if len(value) != 8 || binary.BigEndian.Uint64(value) == 0 {
				return fmt.Errorf("%w: set handle", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_PAD:
			for _, value := range decoder.Bytes() {
				if value != 0 {
					return fmt.Errorf("%w: set padding", ErrForeignNftCollision)
				}
			}
		case unix.NFTA_SET_DATA_TYPE,
			unix.NFTA_SET_DATA_LEN,
			unix.NFTA_SET_POLICY,
			unix.NFTA_SET_ID,
			unix.NFTA_SET_TIMEOUT,
			unix.NFTA_SET_GC_INTERVAL,
			unix.NFTA_SET_OBJ_TYPE,
			nftaSetExpr,
			nftaSetExpressions:
			return fmt.Errorf("%w: forbidden set attribute %d", ErrForeignNftCollision, attributeType)
		case unix.NFTA_SET_DESC:
			value := decoder.Bytes()
			if len(value) != 0 || decoder.TypeFlags() != 0 {
				return fmt.Errorf(
					"%w: set description length=%d flags=%d",
					ErrForeignNftCollision,
					len(value),
					decoder.TypeFlags(),
				)
			}
		case nftaSetType:
			if value := decoder.String(); !validNftBackendType(value) {
				return fmt.Errorf("%w: invalid set backend type", ErrForeignNftCollision)
			}
		case nftaSetCount:
			if decoder.Uint32() != expectedElementCount {
				return fmt.Errorf("%w: set element count", ErrForeignNftCollision)
			}
		default:
			return fmt.Errorf("%w: unknown set attribute %d", ErrForeignNftCollision, attributeType)
		}
	}
	if err := decoder.Err(); err != nil {
		return err
	}
	for _, required := range []uint16{
		unix.NFTA_SET_TABLE,
		unix.NFTA_SET_NAME,
		unix.NFTA_SET_FLAGS,
		unix.NFTA_SET_KEY_TYPE,
		unix.NFTA_SET_KEY_LEN,
		unix.NFTA_SET_USERDATA,
	} {
		if !seen[required] {
			return fmt.Errorf("%w: missing set attribute %d", ErrForeignNftCollision, required)
		}
	}
	return nil
}

func rawVerifyExactNftElementKey(raw []byte, expected []byte) error {
	decoder, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return err
	}
	seen := false
	for decoder.Next() {
		if seen || decoder.Type() != unix.NFTA_DATA_VALUE || decoder.TypeFlags() != 0 ||
			!bytes.Equal(decoder.Bytes(), expected) {
			return fmt.Errorf("%w: set element key", ErrForeignNftCollision)
		}
		seen = true
	}
	if err := decoder.Err(); err != nil {
		return err
	}
	if !seen {
		return fmt.Errorf("%w: missing set element key", ErrForeignNftCollision)
	}
	return nil
}

func rawVerifyExactNftElement(raw []byte, spec NftApplySpec) error {
	decoder, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		return err
	}
	decoder.ByteOrder = binary.BigEndian
	seen := make(map[uint16]bool)
	destination, _ := netip.ParseAddr(spec.DestinationIPv4)
	key := destination.As4()
	expectedUserdata := userdata.AppendString(
		nil,
		userdata.NFTNL_UDATA_SET_ELEM_COMMENT,
		nftOwnerMarker,
	)
	configuredTimeout := uint64(spec.TTL / time.Millisecond)
	for decoder.Next() {
		attributeType := decoder.Type()
		if seen[attributeType] && attributeType != unix.NFTA_SET_ELEM_PAD {
			return fmt.Errorf("%w: duplicate set element attribute %d", ErrForeignNftCollision, attributeType)
		}
		seen[attributeType] = true
		switch attributeType {
		case unix.NFTA_SET_ELEM_KEY:
			if flags := decoder.TypeFlags(); flags != 0 && flags != unix.NLA_F_NESTED {
				return fmt.Errorf("%w: set element key encoding", ErrForeignNftCollision)
			}
			if err := rawVerifyExactNftElementKey(decoder.Bytes(), key[:]); err != nil {
				return err
			}
		case unix.NFTA_SET_ELEM_FLAGS:
			if decoder.TypeFlags() != 0 || decoder.Uint32() != 0 {
				return fmt.Errorf("%w: set element flags", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_ELEM_TIMEOUT:
			if decoder.TypeFlags() != 0 || decoder.Uint64() != configuredTimeout {
				return fmt.Errorf("%w: set element timeout", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_ELEM_EXPIRATION:
			remaining := decoder.Uint64()
			if decoder.TypeFlags() != 0 || remaining == 0 || remaining > configuredTimeout {
				return fmt.Errorf("%w: set element expiration", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_ELEM_USERDATA:
			if decoder.TypeFlags() != 0 || !bytes.Equal(decoder.Bytes(), expectedUserdata) {
				return fmt.Errorf("%w: set element ownership userdata", ErrForeignNftCollision)
			}
		case unix.NFTA_SET_ELEM_PAD:
			for _, value := range decoder.Bytes() {
				if value != 0 {
					return fmt.Errorf("%w: set element padding", ErrForeignNftCollision)
				}
			}
		case unix.NFTA_SET_ELEM_DATA,
			unix.NFTA_SET_ELEM_EXPR,
			unix.NFTA_SET_ELEM_OBJREF,
			nftaSetElemKeyEnd,
			nftaSetElemExprs:
			return fmt.Errorf("%w: forbidden set element attribute %d", ErrForeignNftCollision, attributeType)
		default:
			return fmt.Errorf("%w: unknown set element attribute %d", ErrForeignNftCollision, attributeType)
		}
	}
	if err := decoder.Err(); err != nil {
		return err
	}
	for _, required := range []uint16{
		unix.NFTA_SET_ELEM_KEY,
		unix.NFTA_SET_ELEM_TIMEOUT,
		unix.NFTA_SET_ELEM_EXPIRATION,
		unix.NFTA_SET_ELEM_USERDATA,
	} {
		if !seen[required] {
			return fmt.Errorf("%w: missing set element attribute %d", ErrForeignNftCollision, required)
		}
	}
	return nil
}

func rawVerifyExactNftElements(
	netnsFD int,
	spec NftApplySpec,
	expectedCount int,
) error {
	if netnsFD < 3 || expectedCount < 0 || expectedCount > 1 {
		return ErrTargetStale
	}
	conn, err := netlink.Dial(
		unix.NETLINK_NETFILTER,
		&netlink.Config{NetNS: netnsFD},
	)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(nftIOTimeout)); err != nil {
		return err
	}
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_SET_ELEM_LIST_TABLE, Data: []byte(nftTableName + "\x00")},
		{Type: unix.NFTA_SET_ELEM_LIST_SET, Data: []byte(nftSetName + "\x00")},
	})
	if err != nil {
		return err
	}
	replies, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type: netlink.HeaderType(
				(unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETSETELEM,
			),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: append(
			[]byte{byte(nftables.TableFamilyIPv4), unix.NFNETLINK_V0, 0, 0},
			attributes...,
		),
	})
	if err != nil {
		return err
	}
	count := 0
	for _, reply := range replies {
		if len(reply.Data) < 4 || reply.Data[0] != byte(nftables.TableFamilyIPv4) ||
			reply.Data[1] != unix.NFNETLINK_V0 {
			return fmt.Errorf("%w: invalid raw element reply", ErrForeignNftCollision)
		}
		decoder, decodeErr := netlink.NewAttributeDecoder(reply.Data[4:])
		if decodeErr != nil {
			return decodeErr
		}
		seen := make(map[uint16]bool)
		for decoder.Next() {
			attributeType := decoder.Type()
			if seen[attributeType] {
				return fmt.Errorf("%w: duplicate element-list attribute %d", ErrForeignNftCollision, attributeType)
			}
			seen[attributeType] = true
			switch attributeType {
			case unix.NFTA_SET_ELEM_LIST_TABLE:
				if decoder.String() != nftTableName {
					return fmt.Errorf("%w: element-list table", ErrForeignNftCollision)
				}
			case unix.NFTA_SET_ELEM_LIST_SET:
				if decoder.String() != nftSetName {
					return fmt.Errorf("%w: element-list set", ErrForeignNftCollision)
				}
			case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
				if flags := decoder.TypeFlags(); flags != 0 && flags != unix.NLA_F_NESTED {
					return fmt.Errorf("%w: element-list encoding", ErrForeignNftCollision)
				}
				items, nestedErr := netlink.NewAttributeDecoder(decoder.Bytes())
				if nestedErr != nil {
					return nestedErr
				}
				for items.Next() {
					if items.Type() != unix.NFTA_LIST_ELEM {
						return fmt.Errorf("%w: unknown element-list item", ErrForeignNftCollision)
					}
					if flags := items.TypeFlags(); flags != 0 && flags != unix.NLA_F_NESTED {
						return fmt.Errorf("%w: element item encoding", ErrForeignNftCollision)
					}
					if count >= expectedCount {
						return fmt.Errorf("%w: excess set element", ErrForeignNftCollision)
					}
					if err := rawVerifyExactNftElement(items.Bytes(), spec); err != nil {
						return err
					}
					count++
				}
				if err := items.Err(); err != nil {
					return err
				}
			case unix.NFTA_SET_ELEM_LIST_SET_ID:
				return fmt.Errorf("%w: transaction set ID in element dump", ErrForeignNftCollision)
			default:
				return fmt.Errorf("%w: unknown element-list attribute %d", ErrForeignNftCollision, attributeType)
			}
		}
		if err := decoder.Err(); err != nil {
			return err
		}
		for _, required := range []uint16{
			unix.NFTA_SET_ELEM_LIST_TABLE,
			unix.NFTA_SET_ELEM_LIST_SET,
			unix.NFTA_SET_ELEM_LIST_ELEMENTS,
		} {
			if !seen[required] {
				return fmt.Errorf("%w: missing element-list attribute %d", ErrForeignNftCollision, required)
			}
		}
	}
	if count != expectedCount {
		return fmt.Errorf("%w: raw set element count=%d", ErrForeignNftCollision, count)
	}
	return nil
}

type nftInspection struct {
	table       *nftables.Table
	chain       *nftables.Chain
	set         *nftables.Set
	counter     *expr.Counter
	element     *nftables.SetElement
	structureOK bool
}

func inspectExactNftState(
	conn *nftables.Conn,
	netnsFD int,
	spec NftApplySpec,
) (nftInspection, error) {
	tables, err := matchingNftTables(conn)
	if err != nil {
		return nftInspection{}, err
	}
	if len(tables) != 1 {
		return nftInspection{}, fmt.Errorf(
			"%w: table count=%d",
			ErrForeignNftCollision,
			len(tables),
		)
	}
	if tables[0].Family != nftables.TableFamilyIPv4 ||
		tables[0].Flags != 0 || normalizeKernelUint32(tables[0].Use) != 2 {
		return nftInspection{}, fmt.Errorf(
			"%w: table count=%d family=%d flags=%d use=%d",
			ErrForeignNftCollision,
			len(tables),
			tables[0].Family,
			tables[0].Flags,
			normalizeKernelUint32(tables[0].Use),
		)
	}
	table := tables[0]
	chains, err := matchingNftChains(conn, table)
	if err != nil {
		return nftInspection{}, err
	}
	if len(chains) != 1 || !exactNftChain(chains[0]) {
		return nftInspection{}, fmt.Errorf("%w: chain shape count=%d", ErrForeignNftCollision, len(chains))
	}
	chain := chains[0]
	if err := rawVerifyExactNftChain(netnsFD); err != nil {
		return nftInspection{}, err
	}
	sets, err := safeGetSets(conn, table)
	if err != nil {
		return nftInspection{}, err
	}
	if len(sets) != 1 || !exactNftSet(sets[0]) {
		return nftInspection{}, fmt.Errorf("%w: set shape count=%d", ErrForeignNftCollision, len(sets))
	}
	set := sets[0]
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return nftInspection{}, err
	}
	if len(rules) != 1 {
		return nftInspection{}, ErrForeignNftCollision
	}
	counter, ok := exactNftRule(rules[0], table, chain)
	if !ok {
		return nftInspection{}, ErrForeignNftCollision
	}
	elements, err := safeGetSetElements(conn, set)
	if err != nil {
		return nftInspection{}, err
	}
	if len(elements) > 1 {
		return nftInspection{}, ErrForeignNftCollision
	}
	if err := rawVerifyExactNftSet(netnsFD, uint32(len(elements))); err != nil {
		return nftInspection{}, err
	}
	if err := rawVerifyExactNftElements(netnsFD, spec, len(elements)); err != nil {
		return nftInspection{}, err
	}
	inspection := nftInspection{
		table:       table,
		chain:       chain,
		set:         set,
		counter:     counter,
		structureOK: true,
	}
	if len(elements) == 0 {
		return inspection, nil
	}
	destination, _ := netip.ParseAddr(spec.DestinationIPv4)
	key := destination.As4()
	element := &elements[0]
	if !bytes.Equal(element.Key, key[:]) || len(element.Val) != 0 ||
		len(element.KeyEnd) != 0 || element.IntervalEnd || element.VerdictData != nil ||
		element.Counter != nil || element.Comment != nftOwnerMarker ||
		element.Timeout != spec.TTL || element.Expires <= 0 ||
		element.Expires > spec.TTL {
		return nftInspection{}, ErrForeignNftCollision
	}
	inspection.element = element
	return inspection, nil
}

func (platformNftBackend) Prepare(
	ctx context.Context,
	target ApplyTargetHandle,
	spec NftApplySpec,
) (PreparedNftMutation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target == nil || target.NetNSFD() < 3 ||
		target.Snapshot().NetworkNamespaceInode != spec.TargetNetNSInode {
		return nil, ErrTargetStale
	}
	expectedHash, err := expectedNftRulesetSHA256(spec)
	if err != nil {
		return nil, err
	}
	conn, err := newBoundNftConn(target.NetNSFD())
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (PreparedNftMutation, error) {
		return nil, errors.Join(cause, conn.CloseLasting())
	}
	table, chain, set, element, rule, err := canonicalNftObjects(spec)
	if err != nil {
		return fail(err)
	}
	tables, err := matchingNftTables(conn)
	if err != nil {
		return fail(err)
	}
	switch len(tables) {
	case 0:
		conn.AddTable(table)
		conn.AddChain(chain)
		if err := conn.AddSet(set, []nftables.SetElement{element}); err != nil {
			return fail(err)
		}
		conn.AddRule(rule)
	case 1:
		inspection, inspectErr := inspectExactNftState(conn, target.NetNSFD(), spec)
		if inspectErr != nil {
			return fail(inspectErr)
		}
		if inspection.element != nil {
			return fail(ErrForeignNftCollision)
		}
		table, chain, set = inspection.table, inspection.chain, inspection.set
		if err := conn.SetAddElements(set, []nftables.SetElement{element}); err != nil {
			return fail(err)
		}
	default:
		return fail(ErrForeignNftCollision)
	}
	return &linuxPreparedNftMutation{
		conn:         conn,
		target:       target,
		spec:         spec,
		table:        table,
		chain:        chain,
		set:          set,
		expectedHash: expectedHash,
	}, nil
}

func (mutation *linuxPreparedNftMutation) ExpectedRulesetSHA256() string {
	if mutation == nil {
		return ""
	}
	return mutation.expectedHash
}

func (mutation *linuxPreparedNftMutation) FlushOnceAndVerify(
	ctx context.Context,
) (ApplyObservation, error) {
	if mutation == nil {
		return ApplyObservation{}, ErrNftMutationUncertain
	}
	mutation.mutex.Lock()
	defer mutation.mutex.Unlock()
	if mutation.closed || mutation.flushed {
		return ApplyObservation{}, ErrNftMutationUncertain
	}
	mutation.flushed = true
	if err := ctx.Err(); err != nil {
		return ApplyObservation{}, errors.Join(ErrNftNotApplied, err)
	}
	hostBefore := mutation.target.HostNetworkNamespaceInode()
	flushErr := mutation.conn.Flush()
	inspection, inspectErr := inspectExactNftState(
		mutation.conn,
		mutation.target.NetNSFD(),
		mutation.spec,
	)
	hostAfter, hostErr := platformHostNetworkNamespaceInode()
	if inspectErr == nil && inspection.structureOK && inspection.element == nil {
		return ApplyObservation{}, errors.Join(
			ErrNftMutationUncertain,
			flushErr,
			hostErr,
		)
	}
	if inspectErr != nil || !inspection.structureOK || inspection.element == nil ||
		hostErr != nil || hostBefore == 0 || hostBefore != hostAfter {
		return ApplyObservation{}, errors.Join(
			ErrNftMutationUncertain,
			flushErr,
			inspectErr,
			hostErr,
		)
	}
	configured := uint64(inspection.element.Timeout / time.Millisecond)
	remaining := uint64(inspection.element.Expires / time.Millisecond)
	observation := ApplyObservation{
		TargetNetNSInode:              mutation.spec.TargetNetNSInode,
		RulesetSHA256:                 mutation.expectedHash,
		ConfiguredTimeoutMilliseconds: configured,
		RemainingTimeoutMilliseconds:  remaining,
		CounterPackets:                inspection.counter.Packets,
		CounterBytes:                  inspection.counter.Bytes,
		HostNetNSBefore:               hostBefore,
		HostNetNSAfter:                hostAfter,
	}
	if err := observation.validate(mutation.spec); err != nil {
		return ApplyObservation{}, errors.Join(ErrNftMutationUncertain, flushErr, err)
	}
	return observation, nil
}

func (mutation *linuxPreparedNftMutation) Close() error {
	if mutation == nil {
		return nil
	}
	mutation.mutex.Lock()
	defer mutation.mutex.Unlock()
	if mutation.closed {
		return nil
	}
	mutation.closed = true
	return mutation.conn.CloseLasting()
}

func (platformNftBackend) InspectExpiry(
	ctx context.Context,
	target ApplyTargetHandle,
	spec NftApplySpec,
) (ExpiryObservation, error) {
	if err := ctx.Err(); err != nil {
		return ExpiryObservation{}, err
	}
	if target == nil || target.NetNSFD() < 3 ||
		target.Snapshot().NetworkNamespaceInode != spec.TargetNetNSInode {
		return ExpiryObservation{}, ErrTargetStale
	}
	expectedHash, err := expectedNftRulesetSHA256(spec)
	if err != nil {
		return ExpiryObservation{}, err
	}
	hostBefore := target.HostNetworkNamespaceInode()
	conn, err := newBoundNftConn(target.NetNSFD())
	if err != nil {
		return ExpiryObservation{}, err
	}
	defer conn.CloseLasting()
	tables, err := matchingNftTables(conn)
	if err != nil {
		return ExpiryObservation{}, err
	}
	present := false
	switch len(tables) {
	case 0:
		// Removing the complete owned table proves that the exact element is
		// absent. The auditor records expiry but never recreates the table.
	case 1:
		inspection, inspectErr := inspectExactNftState(conn, target.NetNSFD(), spec)
		if inspectErr != nil {
			return ExpiryObservation{}, inspectErr
		}
		present = inspection.element != nil
	default:
		return ExpiryObservation{}, ErrForeignNftCollision
	}
	hostAfter, err := platformHostNetworkNamespaceInode()
	if err != nil || hostBefore == 0 || hostBefore != hostAfter {
		return ExpiryObservation{}, errors.Join(ErrNftMutationUncertain, err)
	}
	observation := ExpiryObservation{
		TargetNetNSInode: spec.TargetNetNSInode,
		RulesetSHA256:    expectedHash,
		ElementPresent:   present,
		HostNetNSBefore:  hostBefore,
		HostNetNSAfter:   hostAfter,
	}
	if err := observation.validate(spec); err != nil {
		return ExpiryObservation{}, err
	}
	return observation, nil
}

func (platformNftBackend) InspectApplied(
	ctx context.Context,
	target ApplyTargetHandle,
	spec NftApplySpec,
) (ApplyObservation, bool, error) {
	if err := ctx.Err(); err != nil {
		return ApplyObservation{}, false, err
	}
	if target == nil || target.NetNSFD() < 3 ||
		target.Snapshot().NetworkNamespaceInode != spec.TargetNetNSInode {
		return ApplyObservation{}, false, ErrTargetStale
	}
	expectedHash, err := expectedNftRulesetSHA256(spec)
	if err != nil {
		return ApplyObservation{}, false, err
	}
	hostBefore := target.HostNetworkNamespaceInode()
	conn, err := newBoundNftConn(target.NetNSFD())
	if err != nil {
		return ApplyObservation{}, false, err
	}
	defer conn.CloseLasting()
	tables, err := matchingNftTables(conn)
	if err != nil {
		return ApplyObservation{}, false, err
	}
	var inspection nftInspection
	switch len(tables) {
	case 0:
		// No owned table proves no exact element in this held namespace.
	case 1:
		inspection, err = inspectExactNftState(conn, target.NetNSFD(), spec)
		if err != nil {
			return ApplyObservation{}, false, err
		}
	default:
		return ApplyObservation{}, false, ErrForeignNftCollision
	}
	hostAfter, err := platformHostNetworkNamespaceInode()
	if err != nil || hostBefore == 0 || hostBefore != hostAfter {
		return ApplyObservation{}, false, errors.Join(ErrNftMutationUncertain, err)
	}
	base := ApplyObservation{
		TargetNetNSInode:              spec.TargetNetNSInode,
		RulesetSHA256:                 expectedHash,
		ConfiguredTimeoutMilliseconds: uint64(spec.TTL / time.Millisecond),
		HostNetNSBefore:               hostBefore,
		HostNetNSAfter:                hostAfter,
	}
	if inspection.element == nil {
		return base, false, nil
	}
	base.ConfiguredTimeoutMilliseconds = uint64(inspection.element.Timeout / time.Millisecond)
	base.RemainingTimeoutMilliseconds = uint64(inspection.element.Expires / time.Millisecond)
	base.CounterPackets = inspection.counter.Packets
	base.CounterBytes = inspection.counter.Bytes
	if err := base.validate(spec); err != nil {
		return ApplyObservation{}, false, err
	}
	return base, true, nil
}
