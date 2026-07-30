package observerd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"agmind.local/sais/internal/durablefile"
)

const pccTestPinMaxBytes = int64(65_536)

func pccTestSpecialUseRegistry(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/v1/ipv4-special-use.csv")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pccTestValidInputs(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		pccDetectorRulesPath:      []byte("- rule: outbound\n"),
		pccSpecialUseRegistryPath: pccTestSpecialUseRegistry(t),
		pccOperatorDenylistPath: []byte(
			`{"denied_addresses":["203.0.113.2","10.0.0.2"],` +
				`"denied_networks":["203.0.113.0/24","10.0.0.0/8"]}`,
		),
		pccManagementDestinationsPath: []byte(
			`{"denied_addresses":["198.51.100.9","172.16.0.2"],` +
				`"denied_networks":["198.51.100.0/24","172.16.0.0/12"]}`,
		),
	}
}

func pccTestReader(
	inputs map[string][]byte,
	calls *[]string,
) func(string, int64) ([]byte, error) {
	return func(path string, maxBytes int64) ([]byte, error) {
		*calls = append(*calls, path)
		raw, ok := inputs[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		if maxBytes != pccTestPinMaxBytes {
			return nil, fmt.Errorf("unexpected max bytes: %d", maxBytes)
		}
		if int64(len(raw)) > maxBytes {
			return nil, durablefile.ErrUnsafePath
		}
		return bytes.Clone(raw), nil
	}
}

func TestPCCSafetyPinSnapshotReadsEveryFixedPathOnce(t *testing.T) {
	inputs := pccTestValidInputs(t)
	var calls []string
	got, err := loadPCCSafetyPinSnapshot(pccTestReader(inputs, &calls), 0)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{
		pccDetectorRulesPath,
		pccSpecialUseRegistryPath,
		pccOperatorDenylistPath,
		pccManagementDestinationsPath,
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("fixed path reads:\n got %q\nwant %q", calls, wantCalls)
	}
	want := PCCSafetyPinSnapshot{
		DetectorBundleSHA256:     "f6189db90ea61fefe991672b20316f1693f723de28ab37800029a40545af7b15",
		SpecialUseRegistrySHA256: "e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73",
		OperatorDeniedNetworks: []string{
			"10.0.0.0/8",
			"203.0.113.0/24",
		},
		OperatorDeniedAddresses: []string{
			"10.0.0.2",
			"203.0.113.2",
		},
		OperatorDenylistSHA256: "249f8edf571afd14709a9f27d7ad46396c43be3f67991f21fbd82be2142030ca",
		ManagementDeniedNetworks: []string{
			"172.16.0.0/12",
			"198.51.100.0/24",
		},
		ManagementDeniedAddresses: []string{
			"172.16.0.2",
			"198.51.100.9",
		},
		ManagementDenylistSHA256: "198eaec23de7a321aecb226558e2cde19a43aa1858c2084943c3c4a902bd685f",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot:\n got %#v\nwant %#v", got, want)
	}
}

func TestPCCSafetyPinSnapshotRejectsUnsafeOrMalformedInput(t *testing.T) {
	type protectedPathCase struct {
		name    string
		path    string
		prepare func(string) error
	}
	root := t.TempDir()
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(regular, 0o600); err != nil {
		t.Fatal(err)
	}
	protectedPathCases := []protectedPathCase{
		{
			name: "symlink",
			path: filepath.Join(root, "symlink"),
			prepare: func(path string) error {
				return os.Symlink(regular, path)
			},
		},
		{
			name: "non-regular",
			path: filepath.Join(root, "directory"),
			prepare: func(path string) error {
				return os.Mkdir(path, 0o700)
			},
		},
		{
			name: "multi-link",
			path: filepath.Join(root, "hard-link"),
			prepare: func(path string) error {
				return os.Link(regular, path)
			},
		},
		{
			name: "mode-other-than-0600",
			path: filepath.Join(root, "wrong-mode"),
			prepare: func(path string) error {
				if err := os.WriteFile(path, []byte("unsafe"), 0o644); err != nil {
					return err
				}
				return os.Chmod(path, 0o644)
			},
		},
		{
			name: "missing",
			path: filepath.Join(root, "missing"),
			prepare: func(string) error {
				return nil
			},
		},
		{
			name: "size-overflow",
			path: filepath.Join(root, "too-large"),
			prepare: func(path string) error {
				if err := os.WriteFile(
					path,
					bytes.Repeat([]byte("x"), int(pccTestPinMaxBytes+1)),
					0o600,
				); err != nil {
					return err
				}
				return os.Chmod(path, 0o600)
			},
		},
	}
	for _, test := range protectedPathCases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.prepare(test.path); err != nil {
				t.Fatal(err)
			}
			inputs := pccTestValidInputs(t)
			reader := func(path string, maxBytes int64) ([]byte, error) {
				if path == pccDetectorRulesPath {
					return readSingleLinkRegular(test.path, maxBytes)
				}
				return bytes.Clone(inputs[path]), nil
			}
			got, err := loadPCCSafetyPinSnapshot(reader, 0)
			if err == nil {
				t.Fatal("unsafe protected-path input was accepted")
			}
			if !reflect.DeepEqual(got, PCCSafetyPinSnapshot{}) {
				t.Fatalf("partial snapshot escaped on error: %#v", got)
			}
		})
	}

	for _, test := range []struct {
		name string
		err  error
	}{
		{"non-root-owned", durablefile.ErrUnsafePath},
		{"unreadable", os.ErrPermission},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputs := pccTestValidInputs(t)
			reader := func(path string, maxBytes int64) ([]byte, error) {
				if path == pccDetectorRulesPath {
					return nil, test.err
				}
				return bytes.Clone(inputs[path]), nil
			}
			got, err := loadPCCSafetyPinSnapshot(reader, 0)
			if !errors.Is(err, test.err) {
				t.Fatalf("got error %v, want %v", err, test.err)
			}
			if !reflect.DeepEqual(got, PCCSafetyPinSnapshot{}) {
				t.Fatalf("partial snapshot escaped on error: %#v", got)
			}
		})
	}

	t.Run("non-root-process", func(t *testing.T) {
		inputs := pccTestValidInputs(t)
		var calls []string
		got, err := loadPCCSafetyPinSnapshot(
			pccTestReader(inputs, &calls),
			501,
		)
		if err == nil {
			t.Fatal("non-root process was allowed to load root-owned pins")
		}
		if len(calls) != 0 {
			t.Fatalf("non-root process read protected paths: %q", calls)
		}
		if !reflect.DeepEqual(got, PCCSafetyPinSnapshot{}) {
			t.Fatalf("partial snapshot escaped on error: %#v", got)
		}
	})

	tooManyNetworks := make([]string, 129)
	tooManyAddresses := make([]string, 129)
	for index := range tooManyNetworks {
		tooManyNetworks[index] = fmt.Sprintf("10.0.0.%d/32", index)
		tooManyAddresses[index] = fmt.Sprintf("10.0.0.%d", index)
	}
	marshalDenylist := func(addresses, networks []string) []byte {
		return []byte(fmt.Sprintf(
			`{"denied_addresses":[%s],"denied_networks":[%s]}`,
			quotePCCStrings(addresses),
			quotePCCStrings(networks),
		))
	}
	malformedCases := []struct {
		name string
		path string
		raw  []byte
	}{
		{"empty-detector", pccDetectorRulesPath, []byte{}},
		{"empty-special-use", pccSpecialUseRegistryPath, []byte{}},
		{"empty-operator-denylist", pccOperatorDenylistPath, []byte{}},
		{"empty-management-denylist", pccManagementDestinationsPath, []byte{}},
		{"invalid-json-shape", pccOperatorDenylistPath, []byte(`[]`)},
		{"missing-array", pccOperatorDenylistPath, []byte(`{"denied_addresses":[]}`)},
		{"unknown-property", pccOperatorDenylistPath, []byte(
			`{"denied_addresses":[],"denied_networks":[],"extra":true}`,
		)},
		{"duplicate-network", pccOperatorDenylistPath, marshalDenylist(
			[]string{},
			[]string{"10.0.0.0/8", "10.0.0.0/8"},
		)},
		{"duplicate-address", pccOperatorDenylistPath, marshalDenylist(
			[]string{"10.0.0.1", "10.0.0.1"},
			[]string{},
		)},
		{"noncanonical-network", pccOperatorDenylistPath, marshalDenylist(
			[]string{},
			[]string{"10.0.0.1/8"},
		)},
		{"noncanonical-address", pccOperatorDenylistPath, marshalDenylist(
			[]string{"010.0.0.1"},
			[]string{},
		)},
		{"malformed-network", pccOperatorDenylistPath, marshalDenylist(
			[]string{},
			[]string{"not-a-network"},
		)},
		{"malformed-address", pccOperatorDenylistPath, marshalDenylist(
			[]string{"not-an-address"},
			[]string{},
		)},
		{"ipv6-network", pccOperatorDenylistPath, marshalDenylist(
			[]string{},
			[]string{"2001:db8::/64"},
		)},
		{"ipv6-address", pccOperatorDenylistPath, marshalDenylist(
			[]string{"2001:db8::1"},
			[]string{},
		)},
		{"ipv4-mapped-network", pccOperatorDenylistPath, marshalDenylist(
			[]string{},
			[]string{"::ffff:192.0.2.0/120"},
		)},
		{"ipv4-mapped-address", pccOperatorDenylistPath, marshalDenylist(
			[]string{"::ffff:192.0.2.1"},
			[]string{},
		)},
		{"129-networks", pccOperatorDenylistPath, marshalDenylist(
			[]string{},
			tooManyNetworks,
		)},
		{"129-addresses", pccManagementDestinationsPath, marshalDenylist(
			tooManyAddresses,
			[]string{},
		)},
	}
	for _, test := range malformedCases {
		t.Run(test.name, func(t *testing.T) {
			inputs := pccTestValidInputs(t)
			inputs[test.path] = test.raw
			var calls []string
			got, err := loadPCCSafetyPinSnapshot(
				pccTestReader(inputs, &calls),
				0,
			)
			if err == nil {
				t.Fatal("malformed safety pin was accepted")
			}
			if !reflect.DeepEqual(got, PCCSafetyPinSnapshot{}) {
				t.Fatalf("partial snapshot escaped on error: %#v", got)
			}
		})
	}
}

func quotePCCStrings(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = fmt.Sprintf("%q", value)
	}
	return strings.Join(quoted, ",")
}

func TestPCCSafetyPinSnapshotCanonicalizesDenyLists(t *testing.T) {
	inputs := pccTestValidInputs(t)
	var calls []string
	got, err := loadPCCSafetyPinSnapshot(pccTestReader(inputs, &calls), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.OperatorDeniedNetworks, []string{
		"10.0.0.0/8",
		"203.0.113.0/24",
	}) || !slices.Equal(got.OperatorDeniedAddresses, []string{
		"10.0.0.2",
		"203.0.113.2",
	}) {
		t.Fatalf("operator denylist was not canonicalized: %#v", got)
	}
	if !slices.Equal(got.ManagementDeniedNetworks, []string{
		"172.16.0.0/12",
		"198.51.100.0/24",
	}) || !slices.Equal(got.ManagementDeniedAddresses, []string{
		"172.16.0.2",
		"198.51.100.9",
	}) {
		t.Fatalf("management denylist was not canonicalized: %#v", got)
	}
}

func TestPCCSafetyPinSnapshotRejectsWrongSpecialUseDigest(t *testing.T) {
	inputs := pccTestValidInputs(t)
	inputs[pccSpecialUseRegistryPath] = append(
		bytes.Clone(inputs[pccSpecialUseRegistryPath]),
		'\n',
	)
	var calls []string
	got, err := loadPCCSafetyPinSnapshot(pccTestReader(inputs, &calls), 0)
	if err == nil {
		t.Fatal("wrong special-use digest was accepted")
	}
	if !reflect.DeepEqual(got, PCCSafetyPinSnapshot{}) {
		t.Fatalf("partial snapshot escaped on digest mismatch: %#v", got)
	}
}

func TestPCCSafetyPinSnapshotIsDeeplyCloned(t *testing.T) {
	inputs := pccTestValidInputs(t)
	var firstCalls []string
	first, err := loadPCCSafetyPinSnapshot(
		pccTestReader(inputs, &firstCalls),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	var secondCalls []string
	second, err := loadPCCSafetyPinSnapshot(
		pccTestReader(inputs, &secondCalls),
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range inputs {
		for index := range raw {
			raw[index] = 'x'
		}
	}
	first.OperatorDeniedNetworks[0] = "192.0.2.0/24"
	first.OperatorDeniedAddresses[0] = "192.0.2.1"
	first.ManagementDeniedNetworks[0] = "192.0.2.0/24"
	first.ManagementDeniedAddresses[0] = "192.0.2.1"

	if slices.Equal(first.OperatorDeniedNetworks, second.OperatorDeniedNetworks) ||
		slices.Equal(first.OperatorDeniedAddresses, second.OperatorDeniedAddresses) ||
		slices.Equal(first.ManagementDeniedNetworks, second.ManagementDeniedNetworks) ||
		slices.Equal(first.ManagementDeniedAddresses, second.ManagementDeniedAddresses) {
		t.Fatalf("mutating one snapshot did not remain isolated:\nfirst %#v\nsecond %#v", first, second)
	}
	if !slices.Equal(second.OperatorDeniedNetworks, []string{
		"10.0.0.0/8",
		"203.0.113.0/24",
	}) || !slices.Equal(second.ManagementDeniedAddresses, []string{
		"172.16.0.2",
		"198.51.100.9",
	}) {
		t.Fatalf("source or sibling mutation reached cloned snapshot: %#v", second)
	}
}
