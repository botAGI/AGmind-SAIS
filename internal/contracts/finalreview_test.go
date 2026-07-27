package contracts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type namedBytes []byte
type namedByteArray [2]byte

type valueJSONMarshaler string

func (value valueJSONMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(value), nil
}

type pointerJSONMarshaler string

func (value *pointerJSONMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(*value), nil
}

type valueTextMarshaler string

func (value valueTextMarshaler) MarshalText() ([]byte, error) {
	return []byte(value), nil
}

type pointerTextMarshaler string

func (value *pointerTextMarshaler) MarshalText() ([]byte, error) {
	return []byte(*value), nil
}

var (
	_ json.Marshaler         = valueJSONMarshaler("")
	_ json.Marshaler         = (*pointerJSONMarshaler)(nil)
	_ encoding.TextMarshaler = valueTextMarshaler("")
	_ encoding.TextMarshaler = (*pointerTextMarshaler)(nil)
)

func TestCanonicalJSONRejectsHiddenProgrammaticCoercionsAtEveryNesting(t *testing.T) {
	rawSurrogate := json.RawMessage(`"\ud800"`)
	rawInvalidUTF8 := json.RawMessage{'"', 0xff, '"'}
	rawDuplicate := json.RawMessage(`{"x":1,"x":2}`)
	rawFloat := json.RawMessage(`1.5`)
	pointerJSONSurrogate := pointerJSONMarshaler(`"\ud800"`)
	pointerJSONInvalid := pointerJSONMarshaler(string([]byte{'"', 0xff, '"'}))
	pointerTextValid := pointerTextMarshaler("coerced")
	pointerTextInvalid := pointerTextMarshaler(string([]byte{0xff}))
	byteSlice := []byte{1, 2}
	tests := []struct {
		name  string
		value any
	}{
		{"raw-message-valid-direct", json.RawMessage(`{"x":1}`)},
		{"raw-message-surrogate-direct", rawSurrogate},
		{"raw-message-invalid-utf8-direct", rawInvalidUTF8},
		{"raw-message-duplicate-direct", rawDuplicate},
		{"raw-message-float-direct", rawFloat},
		{"raw-message-nested", map[string]any{"x": rawSurrogate}},
		{"raw-message-pointer", &rawSurrogate},
		{"json-marshaler-value-receiver-surrogate", valueJSONMarshaler(`"\ud800"`)},
		{
			"json-marshaler-value-receiver-nested",
			map[string]any{"x": valueJSONMarshaler(`{"x":1}`)},
		},
		{"json-marshaler-pointer-receiver-surrogate", &pointerJSONSurrogate},
		{"json-marshaler-pointer-receiver-invalid-utf8", &pointerJSONInvalid},
		{
			"json-marshaler-pointer-receiver-nested",
			[]any{&pointerJSONInvalid},
		},
		{"text-marshaler-value-receiver", valueTextMarshaler("coerced")},
		{
			"text-marshaler-value-receiver-nested",
			map[string]any{"x": valueTextMarshaler("coerced")},
		},
		{"text-marshaler-pointer-receiver-valid", &pointerTextValid},
		{"text-marshaler-pointer-receiver-invalid-utf8", &pointerTextInvalid},
		{
			"text-marshaler-pointer-receiver-nested",
			[]any{&pointerTextInvalid},
		},
		{"byte-slice-direct", byteSlice},
		{"byte-slice-pointer", &byteSlice},
		{"byte-slice-nested", map[string]any{"x": byteSlice}},
		{"named-byte-slice-direct", namedBytes{1, 2}},
		{"named-byte-slice-nested", []any{namedBytes{1, 2}}},
		{"unsupported-channel", make(chan int)},
		{"unsupported-function", func() {}},
		{"unsupported-complex", complex(1, 2)},
		{"unsupported-map-key", map[int]string{1: "x"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if encoded, err := CanonicalJSON(test.value); err == nil {
				t.Fatalf("forbidden value canonicalized as %s", encoded)
			}
		})
	}
}

func TestCanonicalJSONAllowsByteArraysAsPythonListIntegerParity(t *testing.T) {
	array := [2]byte{1, 2}
	named := namedByteArray{1, 2}
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"byte-array", array, `[1,2]`},
		{"byte-array-pointer", &array, `[1,2]`},
		{"named-byte-array", named, `[1,2]`},
		{"nested-byte-array", map[string]any{"x": array}, `{"x":[1,2]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CanonicalJSON(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != test.want {
				t.Fatalf("canonical bytes %q != %q", got, test.want)
			}
		})
	}
}

func TestCanonicalJSONPreservesOrdinaryStructTagsPointersAndNestedNull(t *testing.T) {
	type ordinary struct {
		B       string  `json:"b"`
		A       uint64  `json:"a"`
		Null    *string `json:"null"`
		Omitted string  `json:"omitted,omitempty"`
		Ignored []byte  `json:"-"`
		hidden  []byte
	}
	value := ordinary{
		B:       "value",
		A:       7,
		Null:    nil,
		Ignored: []byte{1, 2},
		hidden:  []byte{3, 4},
	}
	for _, candidate := range []any{value, &value, map[string]any{"nested": &value}} {
		if _, err := CanonicalJSON(candidate); err != nil {
			t.Fatalf("ordinary tagged struct was rejected: %v", err)
		}
	}
	got, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":7,"b":"value","null":null}` {
		t.Fatalf("unexpected ordinary struct canonical bytes: %s", got)
	}
}

func TestCanonicalJSONRejectsMapAndSliceCyclesButAllowsSharedAliases(t *testing.T) {
	mapCycle := map[string]any{}
	mapCycle["self"] = mapCycle
	sliceCycle := make([]any, 1)
	sliceCycle[0] = sliceCycle
	for _, test := range []struct {
		name  string
		value any
	}{
		{"map-direct", mapCycle},
		{"map-nested", map[string]any{"outer": mapCycle}},
		{"slice-direct", sliceCycle},
		{"slice-nested", []any{sliceCycle}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := CanonicalJSON(test.value)
			if err == nil || !strings.Contains(err.Error(), "cyclic") {
				t.Fatalf("cycle did not fail explicitly: %v", err)
			}
		})
	}

	sharedMap := map[string]any{"x": 1}
	sharedSlice := []any{1, 2}
	value := map[string]any{
		"map_a":   sharedMap,
		"map_b":   sharedMap,
		"slice_a": sharedSlice,
		"slice_b": sharedSlice,
	}
	if _, err := CanonicalJSON(value); err != nil {
		t.Fatalf("non-cyclic shared aliases were rejected: %v", err)
	}
}

func TestCanonicalJSONRejectsStringTagCoercion(t *testing.T) {
	type coercingStruct struct {
		Number int `json:"number,string"`
	}
	if encoded, err := CanonicalJSON(coercingStruct{Number: 7}); err == nil {
		t.Fatalf("json string tag coercion produced %s", encoded)
	}
}

func TestSigningAndHashHelpersRejectForbiddenProgrammaticValues(t *testing.T) {
	event, err := DecodeStrict[EventEnvelopeV1](
		bytes.NewReader(fixtureBytes(t, "envelope.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	event.NormalizedFields["raw"] = json.RawMessage(`"\ud800"`)
	if _, err := EventSigningMessage(event); err == nil {
		t.Fatal("event signing amplified json.RawMessage")
	}
	if _, err := EventID(event); err == nil {
		t.Fatal("event ID amplified json.RawMessage")
	}

	record, err := DecodeStrict[ActionRecordV1](
		bytes.NewReader(fixtureBytes(t, "action-record.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Details["custom"] = valueJSONMarshaler(`"\ud800"`)
	if _, err := ActionRecordHash(record); err == nil {
		t.Fatal("action hash amplified json.Marshaler")
	}
	if _, err := ActionRecordSigningMessage(record); err == nil {
		t.Fatal("action signing amplified json.Marshaler")
	}

	plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(fixtureBytes(t, "plan.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan.PolicyBundleVersion = string([]byte{0xff})
	if _, err := PlanHash(plan); err == nil {
		t.Fatal("plan hash repaired invalid UTF-8")
	}
}

func legacyCanonicalDocumentWithout(t *testing.T, value any, fields ...string) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		delete(document, field)
	}
	canonical, err := CanonicalJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func eventTestPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func actuatorTestPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
	)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func signLegacyEvent(t *testing.T, event EventEnvelopeV1) EventEnvelopeV1 {
	t.Helper()
	message := append(
		[]byte("AGMIND_EVENT_ENVELOPE_V1\x00"),
		legacyCanonicalDocumentWithout(t, event, "source_signature")...,
	)
	event.SourceSignature = hex.EncodeToString(ed25519.Sign(eventTestPrivateKey(t), message))
	return event
}

func legacyActionHash(t *testing.T, record ActionRecordV1) string {
	t.Helper()
	canonical := legacyCanonicalDocumentWithout(
		t,
		record,
		"record_id",
		"record_sha256",
		"actuator_signature",
	)
	digest := sha256Bytes(append([]byte("AGMIND_ACTION_RECORD_HASH_V1\x00"), canonical...))
	return hex.EncodeToString(digest)
}

func sha256Bytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func signLegacyAction(t *testing.T, record ActionRecordV1) ActionRecordV1 {
	t.Helper()
	record.RecordSHA256 = legacyActionHash(t, record)
	record.RecordID = "ar_" + record.RecordSHA256[:32]
	message := append(
		[]byte("AGMIND_ACTION_RECORD_V1\x00"),
		legacyCanonicalDocumentWithout(t, record, "actuator_signature")...,
	)
	record.ActuatorSignature = hex.EncodeToString(
		ed25519.Sign(actuatorTestPrivateKey(t), message),
	)
	return record
}

func TestDirectProducersRejectNilRequiredCollections(t *testing.T) {
	event, err := DecodeStrict[EventEnvelopeV1](
		bytes.NewReader(fixtureBytes(t, "envelope.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	eventMutations := []struct {
		name   string
		mutate func(*EventEnvelopeV1)
	}{
		{"normalized_fields", func(value *EventEnvelopeV1) {
			value.NormalizedFields = nil
			*value = rebindEvent(t, *value)
		}},
		{"redaction_flags", func(value *EventEnvelopeV1) { value.RedactionFlags = nil }},
		{"coverage_flags", func(value *EventEnvelopeV1) { value.CoverageFlags = nil }},
	}
	for _, mutation := range eventMutations {
		t.Run("event/"+mutation.name, func(t *testing.T) {
			changed := event
			mutation.mutate(&changed)
			changed = signLegacyEvent(t, changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("Validate accepted required nil collection")
			}
			public := eventTestPrivateKey(t).Public().(ed25519.PublicKey)
			if err := VerifyEventSignature(changed, public); err == nil {
				t.Fatal("VerifyEventSignature accepted required nil collection")
			}
		})
	}

	falco, err := DecodeStrict[FalcoConnectV1](
		bytes.NewReader(fixtureBytes(t, "falco.candidate.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name   string
		mutate func(*FalcoConnectV1)
	}{
		{"repo_digests", func(value *FalcoConnectV1) { value.RepoDigests = nil }},
		{
			"missing_required_fields",
			func(value *FalcoConnectV1) { value.MissingRequiredFields = nil },
		},
	} {
		t.Run("falco/"+mutation.name, func(t *testing.T) {
			changed := falco
			mutation.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("Validate accepted required nil collection")
			}
		})
	}

	intent, err := DecodeStrict[TemporaryEgressDenyIntentV1](
		bytes.NewReader(fixtureBytes(t, "intent.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	intent.RepoDigests = nil
	if err := intent.Validate(); err == nil {
		t.Fatal("intent Validate accepted nil repo_digests")
	}

	plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(fixtureBytes(t, "plan.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan.RepoDigests = nil
	plan.PlanHashValue, err = PlanHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err == nil {
		t.Fatal("plan Validate accepted nil repo_digests")
	}

	hunter, err := DecodeStrict[HunterOutputV1](
		bytes.NewReader(fixtureBytes(t, "hunter.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	hunterMutations := []struct {
		name   string
		mutate func(*HunterOutputV1)
	}{
		{"hypotheses", func(value *HunterOutputV1) { value.Hypotheses = nil }},
		{
			"supporting_evidence_ids",
			func(value *HunterOutputV1) { value.SupportingEvidenceIDs = nil },
		},
		{
			"refuting_questions",
			func(value *HunterOutputV1) { value.RefutingQuestions = nil },
		},
		{"limitations", func(value *HunterOutputV1) { value.Limitations = nil }},
	}
	for _, mutation := range hunterMutations {
		t.Run("hunter/"+mutation.name, func(t *testing.T) {
			changed := hunter
			mutation.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("Validate accepted required nil collection")
			}
		})
	}

	record, err := DecodeStrict[ActionRecordV1](
		bytes.NewReader(fixtureBytes(t, "action-record.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Details = nil
	record = signLegacyAction(t, record)
	if err := record.Validate(); err == nil {
		t.Fatal("action Validate accepted nil details")
	}
	public := actuatorTestPrivateKey(t).Public().(ed25519.PublicKey)
	if err := VerifyActionRecord(record, public); err == nil {
		t.Fatal("VerifyActionRecord accepted nil details")
	}
}

func TestDirectProducersAllowNonNilEmptyRequiredCollections(t *testing.T) {
	event, err := DecodeStrict[EventEnvelopeV1](
		bytes.NewReader(fixtureBytes(t, "envelope.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	event.NormalizedFields = map[string]any{}
	event.RedactionFlags = []string{}
	event.CoverageFlags = []string{}
	event = rebindEvent(t, event)
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}

	falco, err := DecodeStrict[FalcoConnectV1](
		bytes.NewReader(fixtureBytes(t, "falco.candidate.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	falco.RepoDigests = []string{}
	falco.MissingRequiredFields = []string{}
	if err := falco.Validate(); err != nil {
		t.Fatal(err)
	}

	intent, err := DecodeStrict[TemporaryEgressDenyIntentV1](
		bytes.NewReader(fixtureBytes(t, "intent.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	intent.RepoDigests = []string{}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}

	plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(fixtureBytes(t, "plan.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan.RepoDigests = []string{}
	plan.PlanHashValue, err = PlanHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}

	hunter, err := DecodeStrict[HunterOutputV1](
		bytes.NewReader(fixtureBytes(t, "hunter.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	hunter.Hypotheses = []string{}
	hunter.SupportingEvidenceIDs = []string{}
	hunter.RefutingQuestions = []string{}
	hunter.Limitations = []string{}
	if err := hunter.Validate(); err != nil {
		t.Fatal(err)
	}

	record, err := DecodeStrict[ActionRecordV1](
		bytes.NewReader(fixtureBytes(t, "action-record.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.Details = map[string]any{}
	record = rebindAction(t, record)
	if err := record.Validate(); err != nil {
		t.Fatal(err)
	}
}

func timestampVectors(t *testing.T) []struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Accepted bool   `json:"accepted"`
} {
	t.Helper()
	var vectors []struct {
		Name     string `json:"name"`
		Value    string `json:"value"`
		Accepted bool   `json:"accepted"`
	}
	if err := json.Unmarshal(fixtureBytes(t, "timestamp-vectors.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func shiftedTimestamp(t *testing.T, value string, delta time.Duration) string {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Add(delta).Format(time.RFC3339Nano)
}

func TestSharedTimestampMatrixAcrossEveryGoContractProperty(t *testing.T) {
	type target struct {
		name     string
		validate func(*testing.T, string, bool) error
	}
	targets := []target{
		{"event/event_time", func(t *testing.T, value string, _ bool) error {
			event, err := DecodeStrict[EventEnvelopeV1](
				bytes.NewReader(fixtureBytes(t, "envelope.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			event.EventTime = value
			return event.Validate()
		}},
		{"event/ingest_time", func(t *testing.T, value string, _ bool) error {
			event, err := DecodeStrict[EventEnvelopeV1](
				bytes.NewReader(fixtureBytes(t, "envelope.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			event.IngestTime = value
			return event.Validate()
		}},
		{"event/container_start_time", func(t *testing.T, value string, _ bool) error {
			event, err := DecodeStrict[EventEnvelopeV1](
				bytes.NewReader(fixtureBytes(t, "envelope.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			event.ContainerStartTime = &value
			return event.Validate()
		}},
		{"falco/docker_started_at", func(t *testing.T, value string, _ bool) error {
			event, err := DecodeStrict[FalcoConnectV1](
				bytes.NewReader(fixtureBytes(t, "falco.candidate.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			event.DockerStartedAt = &value
			return event.Validate()
		}},
		{"coverage/opened_at", func(t *testing.T, value string, accepted bool) error {
			event, err := DecodeStrict[CoverageEventV1](
				bytes.NewReader(fixtureBytes(t, "coverage.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			event.OpenedAt = value
			if accepted {
				event.ClosedAt = nil
			}
			return event.Validate()
		}},
		{"coverage/closed_at", func(t *testing.T, value string, _ bool) error {
			event, err := DecodeStrict[CoverageEventV1](
				bytes.NewReader(fixtureBytes(t, "coverage.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			event.ClosedAt = &value
			event.OpenedAt = value
			return event.Validate()
		}},
		{"intent/docker_started_at", func(t *testing.T, value string, _ bool) error {
			intent, err := DecodeStrict[TemporaryEgressDenyIntentV1](
				bytes.NewReader(fixtureBytes(t, "intent.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			intent.DockerStartedAt = value
			return intent.Validate()
		}},
		{"intent/created_at", func(t *testing.T, value string, _ bool) error {
			intent, err := DecodeStrict[TemporaryEgressDenyIntentV1](
				bytes.NewReader(fixtureBytes(t, "intent.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			intent.CreatedAt = value
			return intent.Validate()
		}},
		{"plan/docker_started_at", func(t *testing.T, value string, _ bool) error {
			plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
				bytes.NewReader(fixtureBytes(t, "plan.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			plan.DockerStartedAt = value
			plan.PlanHashValue, err = PlanHash(plan)
			if err != nil {
				return err
			}
			return plan.Validate()
		}},
		{"plan/created_at", func(t *testing.T, value string, _ bool) error {
			plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
				bytes.NewReader(fixtureBytes(t, "plan.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			plan.CreatedAt = value
			plan.PlanHashValue, err = PlanHash(plan)
			if err != nil {
				return err
			}
			return plan.Validate()
		}},
		{"plan/prepared_at", func(t *testing.T, value string, _ bool) error {
			plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
				bytes.NewReader(fixtureBytes(t, "plan.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			plan.PreparedAt = value
			if _, parseErr := time.Parse(time.RFC3339Nano, value); parseErr == nil {
				plan.ApprovalExpiresAt = shiftedTimestamp(t, value, 5*time.Minute)
			}
			plan.PlanHashValue, err = PlanHash(plan)
			if err != nil {
				return err
			}
			return plan.Validate()
		}},
		{"plan/approval_expires_at", func(t *testing.T, value string, _ bool) error {
			plan, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
				bytes.NewReader(fixtureBytes(t, "plan.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			plan.ApprovalExpiresAt = value
			if _, parseErr := time.Parse(time.RFC3339Nano, value); parseErr == nil {
				plan.PreparedAt = shiftedTimestamp(t, value, -5*time.Minute)
			}
			plan.PlanHashValue, err = PlanHash(plan)
			if err != nil {
				return err
			}
			return plan.Validate()
		}},
		{"action/observed_at", func(t *testing.T, value string, _ bool) error {
			record, err := DecodeStrict[ActionRecordV1](
				bytes.NewReader(fixtureBytes(t, "action-record.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			record.ObservedAt = value
			record = rebindAction(t, record)
			return record.Validate()
		}},
		{"transition/occurred_at", func(t *testing.T, value string, _ bool) error {
			transition, err := DecodeStrict[KeyTransitionV1](
				bytes.NewReader(fixtureBytes(t, "key-transition.valid.json")), 65536,
			)
			if err != nil {
				return err
			}
			transition.OccurredAt = value
			return transition.Validate()
		}},
	}
	for _, target := range targets {
		for _, vector := range timestampVectors(t) {
			t.Run(target.name+"/"+vector.Name, func(t *testing.T) {
				err := target.validate(t, vector.Value, vector.Accepted)
				if (err == nil) != vector.Accepted {
					t.Fatalf("accepted=%v err=%v", vector.Accepted, err)
				}
			})
		}
	}
}

func TestExactIdentifierHelperPreconditions(t *testing.T) {
	intentID := "int_875f0f15c0ddb3aed2ad402b38423b6b"
	for _, nonce := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := PlanID(intentID, nonce); err == nil {
			t.Fatalf("PlanID accepted %d-byte nonce", len(nonce))
		}
	}
	if _, err := PlanID(intentID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{
		"",
		"0",
		strings.Repeat("0", 63),
		strings.Repeat("0", 65),
		"A" + string(bytes.Repeat([]byte{'0'}, 63)),
		"g" + string(bytes.Repeat([]byte{'0'}, 63)),
	} {
		if got := ActionRecordID(digest); got != "" {
			t.Fatalf("ActionRecordID accepted %q as %q", digest, got)
		}
	}
	if got := ActionRecordID(string(bytes.Repeat([]byte{'0'}, 64))); got != "ar_"+string(bytes.Repeat([]byte{'0'}, 32)) {
		t.Fatalf("unexpected valid action record ID: %q", got)
	}
}
