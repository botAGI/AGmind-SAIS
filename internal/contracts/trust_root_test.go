package contracts

import (
	"bytes"
	"os"
	"testing"
)

func TestObserverTrustRootFixtureBindsExactInitialKey(t *testing.T) {
	raw, err := os.ReadFile(
		"../../contracts/fixtures/v1/observer-trust-root.valid.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := DecodeStrict[ObserverTrustRootV1](
		bytes.NewReader(raw),
		4_096,
	)
	if err != nil {
		t.Fatal(err)
	}
	if root.KeyID != "24f6ed6acbfe1009c030d7ca567c33ca" ||
		root.PublicKey !=
			"29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7" {
		t.Fatalf("unexpected trust root=%+v", root)
	}
}

func TestObserverTrustRootRejectsMismatchedKeyID(t *testing.T) {
	raw := []byte(`{
		"schema_version":"agmind.observer-trust-root.v1",
		"host_id":"123e4567-e89b-42d3-a456-426614174000",
		"key_id":"00000000000000000000000000000000",
		"key_epoch":1,
		"public_key":"29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
	}`)
	if _, err := DecodeStrict[ObserverTrustRootV1](
		bytes.NewReader(raw),
		4_096,
	); err == nil {
		t.Fatal("mismatched trust-root key_id was accepted")
	}
}
