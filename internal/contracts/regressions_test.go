package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type probeContract struct {
	X any `json:"x"`
}

func (probeContract) Validate() error { return nil }

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/fixtures/v1/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPreparedPlanUsesStandaloneVersionAndLockedHash(t *testing.T) {
	plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(fixtureBytes(t, "plan.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(plan.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	gotID, err := PlanID(plan.IntentID, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != plan.PlanID {
		t.Fatalf("plan id %q != %q", gotID, plan.PlanID)
	}
	gotHash, err := PlanHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != plan.PlanHashValue {
		t.Fatalf("plan hash %q != %q", gotHash, plan.PlanHashValue)
	}
}

func TestPlanNonceIsExactly32BytesOfLowercaseHex(t *testing.T) {
	plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(fixtureBytes(t, "plan.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{
		string(bytes.Repeat([]byte{'0'}, 62)),
		string(bytes.Repeat([]byte{'0'}, 66)),
		string(bytes.Repeat([]byte{'A'}, 64)),
		string(bytes.Repeat([]byte{'g'}, 64)),
	} {
		changed := plan
		changed.Nonce = nonce
		if err := changed.Validate(); err == nil {
			t.Errorf("accepted invalid nonce %q", nonce)
		}
	}
}

func TestEveryRuntimeContractFamilyAcceptsPositiveFixture(t *testing.T) {
	tests := []struct {
		name   string
		decode func([]byte) error
	}{
		{"event", func(raw []byte) error {
			_, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"falco-candidate", func(raw []byte) error {
			_, err := DecodeStrict[FalcoConnectV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"falco-investigation", func(raw []byte) error {
			_, err := DecodeStrict[FalcoConnectV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"coverage", func(raw []byte) error {
			_, err := DecodeStrict[CoverageEventV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"intent", func(raw []byte) error {
			_, err := DecodeStrict[TemporaryEgressDenyIntentV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"plan", func(raw []byte) error {
			_, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"hunter", func(raw []byte) error {
			_, err := DecodeStrict[HunterOutputV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"action", func(raw []byte) error {
			_, err := DecodeStrict[ActionRecordV1](bytes.NewReader(raw), 65536)
			return err
		}},
		{"transition", func(raw []byte) error {
			_, err := DecodeStrict[KeyTransitionV1](bytes.NewReader(raw), 65536)
			return err
		}},
	}
	fixtures := []string{
		"envelope.valid.json",
		"falco.candidate.valid.json",
		"falco.investigation.valid.json",
		"coverage.valid.json",
		"intent.valid.json",
		"plan.valid.json",
		"hunter.valid.json",
		"action-record.valid.json",
		"key-transition.valid.json",
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(fixtureBytes(t, fixtures[i])); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEveryRuntimeContractFamilyRejectsEmptyObject(t *testing.T) {
	tests := []struct {
		name   string
		decode func() error
	}{
		{"event", func() error {
			_, err := DecodeStrict[EventEnvelopeV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
		{"falco", func() error {
			_, err := DecodeStrict[FalcoConnectV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
		{"coverage", func() error {
			_, err := DecodeStrict[CoverageEventV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
		{"intent", func() error {
			_, err := DecodeStrict[TemporaryEgressDenyIntentV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
		{"plan", func() error {
			_, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
		{"hunter", func() error {
			_, err := DecodeStrict[HunterOutputV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
		{"action", func() error {
			_, err := DecodeStrict[ActionRecordV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
		{"transition", func() error {
			_, err := DecodeStrict[KeyTransitionV1](bytes.NewBufferString("{}"), 65536)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(); err == nil {
				t.Fatal("empty object decoded as a valid contract")
			}
		})
	}
}

func TestSharedJSONEdgeCorpus(t *testing.T) {
	var cases []struct {
		Name         string `json:"name"`
		InputHex     string `json:"input_hex"`
		Accepted     bool   `json:"accepted"`
		CanonicalHex string `json:"canonical_hex"`
	}
	if err := json.Unmarshal(fixtureBytes(t, "json-edge-vectors.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(test.InputHex)
			if err != nil {
				t.Fatal(err)
			}
			value, decodeErr := DecodeStrict[probeContract](bytes.NewReader(raw), 65536)
			if !test.Accepted {
				if decodeErr == nil {
					t.Fatal("invalid edge input was accepted")
				}
				return
			}
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			got, err := CanonicalJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(test.CanonicalHex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("canonical bytes %x != %x", got, want)
			}
		})
	}
}

func TestCanonicalJSONRejectsIntegralTypedFloat(t *testing.T) {
	if _, err := CanonicalJSON(map[string]any{"x": float64(1)}); err == nil {
		t.Fatal("integral typed float was accepted")
	}
}

func TestLockedDerivationsMatchIndependentSharedVectors(t *testing.T) {
	var vectors struct {
		Release struct {
			ImageID             string `json:"image_id"`
			ImmutableSpecSHA256 string `json:"immutable_spec_sha256"`
			Expected            string `json:"expected"`
		} `json:"release"`
		Candidate struct {
			EventID              string `json:"event_id"`
			DockerContainerID    string `json:"docker_container_id"`
			DockerStartedAt      string `json:"docker_started_at"`
			DestinationIPv4      string `json:"destination_ipv4"`
			DetectorBundleSHA256 string `json:"detector_bundle_sha256"`
			Expected             string `json:"expected"`
		} `json:"candidate"`
		Intent struct {
			CandidateID        string `json:"candidate_id"`
			PolicyBundleSHA256 string `json:"policy_bundle_sha256"`
			TTLSeconds         uint64 `json:"ttl_seconds"`
			Expected           string `json:"expected"`
		} `json:"intent"`
		Plan struct {
			IntentID string `json:"intent_id"`
			NonceHex string `json:"nonce_hex"`
			Expected string `json:"expected"`
		} `json:"plan"`
		Action struct {
			PlanHash string `json:"plan_hash"`
			Expected string `json:"expected"`
		} `json:"action"`
		Keys struct {
			EventPublicKeyHex    string `json:"event_public_key_hex"`
			EventKeyID           string `json:"event_key_id"`
			NewPublicKeyHex      string `json:"new_public_key_hex"`
			NewKeyID             string `json:"new_key_id"`
			ActuatorPublicKeyHex string `json:"actuator_public_key_hex"`
			ActuatorKeyID        string `json:"actuator_key_id"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(fixtureBytes(t, "derivation-vectors.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	check := func(name, got, want string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s: %q != %q", name, got, want)
		}
	}
	got, err := ReleaseID(vectors.Release.ImageID, vectors.Release.ImmutableSpecSHA256)
	check("release", got, vectors.Release.Expected, err)
	got, err = CandidateID(
		vectors.Candidate.EventID,
		vectors.Candidate.DockerContainerID,
		vectors.Candidate.DockerStartedAt,
		vectors.Candidate.DestinationIPv4,
		vectors.Candidate.DetectorBundleSHA256,
	)
	check("candidate", got, vectors.Candidate.Expected, err)
	got, err = IntentID(
		vectors.Intent.CandidateID,
		vectors.Intent.PolicyBundleSHA256,
		vectors.Intent.TTLSeconds,
	)
	check("intent", got, vectors.Intent.Expected, err)
	nonce, err := hex.DecodeString(vectors.Plan.NonceHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err = PlanID(vectors.Plan.IntentID, nonce)
	check("plan", got, vectors.Plan.Expected, err)
	got, err = ActionID(vectors.Action.PlanHash)
	check("action", got, vectors.Action.Expected, err)
	for _, key := range []struct {
		name      string
		publicHex string
		want      string
	}{
		{"event-key", vectors.Keys.EventPublicKeyHex, vectors.Keys.EventKeyID},
		{"new-key", vectors.Keys.NewPublicKeyHex, vectors.Keys.NewKeyID},
		{"actuator-key", vectors.Keys.ActuatorPublicKeyHex, vectors.Keys.ActuatorKeyID},
	} {
		public, err := hex.DecodeString(key.publicHex)
		if err != nil {
			t.Fatal(err)
		}
		got, err = KeyID(public)
		check(key.name, got, key.want, err)
	}
}

func TestSignaturesBindDeclaredKeysAndExactContent(t *testing.T) {
	var vectors struct {
		Keys struct {
			EventPublicKeyHex    string `json:"event_public_key_hex"`
			NewPublicKeyHex      string `json:"new_public_key_hex"`
			ActuatorPublicKeyHex string `json:"actuator_public_key_hex"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(fixtureBytes(t, "derivation-vectors.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	event, err := DecodeStrict[EventEnvelopeV1](
		bytes.NewReader(fixtureBytes(t, "envelope.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	eventPublic, _ := hex.DecodeString(vectors.Keys.EventPublicKeyHex)
	if err := VerifyEventSignature(event, ed25519.PublicKey(eventPublic)); err != nil {
		t.Fatal(err)
	}
	wrongPublic, _ := hex.DecodeString(vectors.Keys.NewPublicKeyHex)
	if err := VerifyEventSignature(event, ed25519.PublicKey(wrongPublic)); err == nil {
		t.Fatal("event signature accepted a public key not bound by key_id")
	}

	record, err := DecodeStrict[ActionRecordV1](
		bytes.NewReader(fixtureBytes(t, "action-record.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	actuatorPublic, _ := hex.DecodeString(vectors.Keys.ActuatorPublicKeyHex)
	if err := VerifyActionRecord(record, ed25519.PublicKey(actuatorPublic)); err != nil {
		t.Fatal(err)
	}
	mismatchedAction := record
	badActionID := "act_00000000000000000000000000000000"
	mismatchedAction.ActionID = &badActionID
	if err := mismatchedAction.Validate(); err == nil {
		t.Fatal("action record with mismatched action_id was accepted")
	}

	transition, err := DecodeStrict[KeyTransitionV1](
		bytes.NewReader(fixtureBytes(t, "key-transition.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyTransition(transition, ed25519.PublicKey(eventPublic)); err != nil {
		t.Fatal(err)
	}
}

func TestKeyTransitionRejectsMissingSignatureNonconsecutiveEpochAndTampering(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(fixtureBytes(t, "key-transition.valid.json"), &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "new_signature")
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStrict[KeyTransitionV1](bytes.NewReader(raw), 65536); err == nil {
		t.Fatal("transition with only the old signature was accepted")
	}

	transition, err := DecodeStrict[KeyTransitionV1](
		bytes.NewReader(fixtureBytes(t, "key-transition.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	nonconsecutive := transition
	nonconsecutive.NewEpoch = 3
	if err := nonconsecutive.Validate(); err == nil {
		t.Fatal("nonconsecutive transition was accepted")
	}
	mismatched := transition
	mismatched.NewKeyID = "00000000000000000000000000000000"
	if err := mismatched.Validate(); err == nil {
		t.Fatal("transition with mismatched new_key_id was accepted")
	}
	var vectors struct {
		Keys struct {
			EventPublicKeyHex string `json:"event_public_key_hex"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(fixtureBytes(t, "derivation-vectors.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	oldPublic, _ := hex.DecodeString(vectors.Keys.EventPublicKeyHex)
	tampered := transition
	tampered.OldSignature = string(bytes.Repeat([]byte{'0'}, 128))
	if err := VerifyKeyTransition(tampered, ed25519.PublicKey(oldPublic)); err == nil {
		t.Fatal("tampered old signature was accepted")
	}
}
