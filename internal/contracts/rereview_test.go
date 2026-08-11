package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func mutateFixture(t *testing.T, fixture string, mutate func(map[string]any)) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(fixtureBytes(t, fixture)))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testJSONFields(contractType reflect.Type, optional bool) []string {
	for contractType.Kind() == reflect.Pointer {
		contractType = contractType.Elem()
	}
	var fields []string
	for i := 0; i < contractType.NumField(); i++ {
		field := contractType.Field(i)
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		if field.Anonymous && (tag == "" || parts[0] == "") {
			fields = append(fields, testJSONFields(field.Type, optional)...)
			continue
		}
		if parts[0] == "" || parts[0] == "-" {
			continue
		}
		hasOmitEmpty := false
		for _, option := range parts[1:] {
			hasOmitEmpty = hasOmitEmpty || option == "omitempty"
		}
		if hasOmitEmpty == optional {
			fields = append(fields, parts[0])
		}
	}
	return fields
}

func assertRequiredDeletions[T Contract](t *testing.T, fixture string) {
	t.Helper()
	var zero T
	fields := testJSONFields(reflect.TypeOf(zero), false)
	if len(fields) == 0 {
		t.Fatal("contract exposed no required fields")
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			raw := mutateFixture(t, fixture, func(document map[string]any) {
				delete(document, field)
			})
			if _, err := DecodeStrict[T](bytes.NewReader(raw), 65536); err == nil {
				t.Fatalf("missing required property %q was accepted", field)
			}
		})
	}
}

func assertOptionalNulls[T Contract](
	t *testing.T,
	fixture string,
	rebind func(map[string]any),
) {
	t.Helper()
	var zero T
	for _, field := range testJSONFields(reflect.TypeOf(zero), true) {
		t.Run(field, func(t *testing.T) {
			omitted := mutateFixture(t, fixture, func(document map[string]any) {
				delete(document, field)
				if _, sensor := FalcoSensorRequiredFields[field]; sensor {
					// Dropping a sensor fact is permitted ONLY when the omission is
					// declared: the validator requires missing_required_fields to equal
					// the set of absent sensor facts, so a blind spot can never be
					// silently indistinguishable from an observation. Declaring it keeps
					// this document coherent, which is what makes this test about
					// OPTIONALITY. The undeclared case has its own test below.
					document["missing_required_fields"] = declaredMissing(document, field)
				}
				if rebind != nil {
					rebind(document)
				}
			})
			if _, err := DecodeStrict[T](bytes.NewReader(omitted), 65536); err != nil {
				t.Fatalf("omitted optional property %q: %v", field, err)
			}
			explicitNull := mutateFixture(t, fixture, func(document map[string]any) {
				document[field] = nil
			})
			if _, err := DecodeStrict[T](bytes.NewReader(explicitNull), 65536); err == nil {
				t.Fatalf("explicit null optional property %q was accepted", field)
			}
		})
	}
}

func TestEveryRequiredPropertyIsCheckedBeforeTypedUnmarshal(t *testing.T) {
	t.Run("event", func(t *testing.T) {
		assertRequiredDeletions[EventEnvelopeV1](t, "envelope.valid.json")
	})
	t.Run("falco-candidate", func(t *testing.T) {
		assertRequiredDeletions[FalcoConnectV1](t, "falco.candidate.valid.json")
	})
	t.Run("falco-investigation", func(t *testing.T) {
		assertRequiredDeletions[FalcoConnectV1](t, "falco.investigation.valid.json")
	})
	t.Run("coverage", func(t *testing.T) {
		assertRequiredDeletions[CoverageEventV1](t, "coverage.valid.json")
	})
	t.Run("intent", func(t *testing.T) {
		assertRequiredDeletions[TemporaryEgressDenyIntentV1](t, "intent.valid.json")
	})
	t.Run("plan", func(t *testing.T) {
		assertRequiredDeletions[PreparedTemporaryEgressDenyPlanV1](t, "plan.valid.json")
	})
	t.Run("hunter", func(t *testing.T) {
		assertRequiredDeletions[HunterOutputV1](t, "hunter.valid.json")
	})
	t.Run("action", func(t *testing.T) {
		assertRequiredDeletions[ActionRecordV1](t, "action-record.valid.json")
	})
	t.Run("key-transition", func(t *testing.T) {
		assertRequiredDeletions[KeyTransitionV1](t, "key-transition.valid.json")
	})
}

func TestOptionalPropertiesRejectExplicitNullButAllowOmission(t *testing.T) {
	t.Run("event", func(t *testing.T) {
		assertOptionalNulls[EventEnvelopeV1](t, "envelope.valid.json", nil)
	})
	t.Run("falco-investigation", func(t *testing.T) {
		assertOptionalNulls[FalcoConnectV1](t, "falco.investigation.valid.json", nil)
	})
	t.Run("coverage", func(t *testing.T) {
		assertOptionalNulls[CoverageEventV1](t, "coverage.valid.json", nil)
	})
	t.Run("action", func(t *testing.T) {
		assertOptionalNulls[ActionRecordV1](
			t,
			"action-record.valid.json",
			func(document map[string]any) {
				raw, err := json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				var record ActionRecordV1
				decoder := json.NewDecoder(bytes.NewReader(raw))
				decoder.UseNumber()
				if err := decoder.Decode(&record); err != nil {
					t.Fatal(err)
				}
				digest, err := ActionRecordHash(record)
				if err != nil {
					t.Fatal(err)
				}
				document["record_sha256"] = digest
				document["record_id"] = ActionRecordID(digest)
			},
		)
	})
}

func TestSharedContradictoryFalcoResultIsRejected(t *testing.T) {
	if _, err := DecodeStrict[FalcoConnectV1](
		bytes.NewReader(fixtureBytes(t, "falco.contradictory.invalid.json")),
		65536,
	); err == nil {
		t.Fatal("contradictory hard-error Falco tuple was accepted")
	}
}

func TestFalcoResultTupleMatrixIsExact(t *testing.T) {
	rawres := func(value int64) *int64 { return &value }
	tests := []struct {
		name       string
		rawres     *int64
		result     string
		successful bool
		accepted   bool
	}{
		{"completed-zero", rawres(0), "SUCCESS", true, true},
		{"completed-positive", rawres(1), "SUCCESS", true, true},
		{"success-negative", rawres(-1), "SUCCESS", false, false},
		{"success-absent", nil, "SUCCESS", false, false},
		{"in-progress-negative", rawres(-115), "EINPROGRESS", true, true},
		{"in-progress-absent", nil, "EINPROGRESS(115)", true, true},
		{"in-progress-nonnegative", rawres(0), "EINPROGRESS", true, false},
		{"hard-error-negative", rawres(-111), "ECONNREFUSED", false, true},
		{"hard-error-absent", nil, "ECONNREFUSED", false, true},
		{"hard-error-nonnegative", rawres(0), "ECONNREFUSED", false, false},
		{"hard-error-success", rawres(-111), "ECONNREFUSED", true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := DecodeStrict[FalcoConnectV1](
				bytes.NewReader(fixtureBytes(t, "falco.investigation.valid.json")),
				65536,
			)
			if err != nil {
				t.Fatal(err)
			}
			event.EvtRawres = test.rawres
			event.EvtRes = test.result
			event.SuccessfulConnect = test.successful
			event.InvestigationOnly = true
			err = event.Validate()
			if (err == nil) != test.accepted {
				t.Fatalf("accepted=%v, error=%v", test.accepted, err)
			}
		})
	}
}

func TestStrictDecoderAndCanonicalWriterEnforceIntegerDomain(t *testing.T) {
	tests := []struct {
		token    string
		accepted bool
	}{
		{"-9223372036854775808", true},
		{"18446744073709551615", true},
		{"-9223372036854775809", false},
		{"18446744073709551616", false},
		{"-0", false},
	}
	for _, test := range tests {
		t.Run(test.token, func(t *testing.T) {
			raw := []byte(`{"x":` + test.token + `}`)
			_, decodeErr := DecodeStrict[probeContract](bytes.NewReader(raw), 65536)
			_, canonicalErr := CanonicalJSON(map[string]any{"x": json.Number(test.token)})
			if (decodeErr == nil) != test.accepted {
				t.Fatalf("decode accepted=%v, error=%v", test.accepted, decodeErr)
			}
			if (canonicalErr == nil) != test.accepted {
				t.Fatalf("canonical accepted=%v, error=%v", test.accepted, canonicalErr)
			}
		})
	}
}

func nestedArrays(containerDepth int) any {
	var value any
	for range containerDepth {
		value = []any{value}
	}
	return value
}

func TestNestingDepth64AcceptedAnd65CleanlyRejected(t *testing.T) {
	atLimit := map[string]any{"x": nestedArrays(63)}
	overLimit := map[string]any{"x": nestedArrays(64)}
	raw, _ := json.Marshal(atLimit)
	if _, err := DecodeStrict[probeContract](bytes.NewReader(raw), 65536); err != nil {
		t.Fatal(err)
	}
	if _, err := CanonicalJSON(atLimit); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(overLimit)
	if _, err := DecodeStrict[probeContract](bytes.NewReader(raw), 65536); err == nil {
		t.Fatal("depth 65 decoded")
	}
	if _, err := CanonicalJSON(overLimit); err == nil {
		t.Fatal("depth 65 canonicalized")
	}
	muchTooDeep := `{"x":` + strings.Repeat("[", 1500) + `null` +
		strings.Repeat("]", 1500) + `}`
	if _, err := DecodeStrict[probeContract](
		bytes.NewBufferString(muchTooDeep),
		65536,
	); err == nil {
		t.Fatal("deep input did not produce a validation error")
	}
}

func rebindEvent(t *testing.T, event EventEnvelopeV1) EventEnvelopeV1 {
	t.Helper()
	canonical, err := CanonicalJSON(event.NormalizedFields)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	event.NormalizedFieldsSHA256 = hex.EncodeToString(digest[:])
	preimage := []byte("AGMIND_EVENT_ID_V1\x00" + event.HostID + "\x00" + event.BootID + "\x00")
	var numbers [16]byte
	binary.BigEndian.PutUint64(numbers[:8], event.KeyEpoch)
	binary.BigEndian.PutUint64(numbers[8:], event.SourceSequence)
	preimage = append(preimage, numbers[:]...)
	preimage = append(preimage, digest[:]...)
	id := sha256.Sum256(preimage)
	event.EventID = "evt_" + hex.EncodeToString(id[:])
	return event
}

func TestEventNormalizedFieldsRecursiveBoundsAndTotalSize(t *testing.T) {
	base, err := DecodeStrict[EventEnvelopeV1](
		bytes.NewReader(fixtureBytes(t, "envelope.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	object := func(size int) map[string]any {
		value := make(map[string]any, size)
		for i := range size {
			value[fmt.Sprintf("k%d", i)] = nil
		}
		return value
	}
	valid := []map[string]any{
		{"x": strings.Repeat("a", 8192)},
		{"x": make([]any, 128)},
		object(128),
		{strings.Repeat("k", 512): nil},
		{"x": json.Number("-9223372036854775808")},
		{"x": json.Number("18446744073709551615")},
		{"x": []any{
			strings.Repeat("a", 8192),
			strings.Repeat("a", 8192),
			strings.Repeat("a", 8192),
			strings.Repeat("a", 8173),
		}},
		{"x": nil},
	}
	invalid := []map[string]any{
		{"x": strings.Repeat("a", 8193)},
		{"x": make([]any, 129)},
		object(129),
		{strings.Repeat("k", 513): nil},
		{"x": json.Number("-9223372036854775809")},
		{"x": json.Number("18446744073709551616")},
		{"x": []any{
			strings.Repeat("a", 8192),
			strings.Repeat("a", 8192),
			strings.Repeat("a", 8192),
			strings.Repeat("a", 8174),
		}},
	}
	for i, value := range valid {
		event := base
		event.NormalizedFields = value
		event = rebindEvent(t, event)
		if err := event.Validate(); err != nil {
			t.Fatalf("valid boundary %d: %v", i, err)
		}
	}
	for i, value := range invalid {
		event := base
		event.NormalizedFields = value
		if i != 4 && i != 5 {
			event = rebindEvent(t, event)
		}
		if err := event.Validate(); err == nil {
			t.Fatalf("invalid boundary %d accepted", i)
		}
	}
}

func rebindAction(t *testing.T, record ActionRecordV1) ActionRecordV1 {
	t.Helper()
	digest, err := ActionRecordHash(record)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordSHA256 = digest
	record.RecordID = ActionRecordID(digest)
	return record
}

func TestActionDetailsRecursiveBoundsAndTotalSize(t *testing.T) {
	base, err := DecodeStrict[ActionRecordV1](
		bytes.NewReader(fixtureBytes(t, "action-record.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	object := func(size int) map[string]any {
		value := make(map[string]any, size)
		for i := range size {
			value[fmt.Sprintf("k%d", i)] = nil
		}
		return value
	}
	total := func(last int) []any {
		value := make([]any, 0, 32)
		for range 31 {
			value = append(value, strings.Repeat("a", 1024))
		}
		return append(value, strings.Repeat("a", last))
	}
	valid := []map[string]any{
		{"x": strings.Repeat("a", 1024)},
		{"x": make([]any, 64)},
		object(64),
		{strings.Repeat("k", 64): nil},
		{"x": json.Number("-9223372036854775808")},
		{"x": json.Number("18446744073709551615")},
		{"x": total(921)},
		{"x": nil},
	}
	invalid := []map[string]any{
		{"x": strings.Repeat("a", 1025)},
		{"x": make([]any, 65)},
		object(65),
		{strings.Repeat("k", 65): nil},
		{"x": json.Number("-9223372036854775809")},
		{"x": json.Number("18446744073709551616")},
		{"x": total(922)},
	}
	for i, value := range valid {
		record := base
		record.Details = value
		record = rebindAction(t, record)
		if err := record.Validate(); err != nil {
			t.Fatalf("valid boundary %d: %v", i, err)
		}
	}
	for i, value := range invalid {
		record := base
		record.Details = value
		if i != 4 && i != 5 {
			record = rebindAction(t, record)
		}
		if err := record.Validate(); err == nil {
			t.Fatalf("invalid boundary %d accepted", i)
		}
	}
}

func TestPrintableASCIIAndEventContentBindings(t *testing.T) {
	event, err := DecodeStrict[EventEnvelopeV1](
		bytes.NewReader(fixtureBytes(t, "envelope.valid.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	control := event
	control.EventType = "bad\nvalue"
	if err := control.Validate(); err == nil {
		t.Fatal("ASCII control character was accepted")
	}
	content := event
	content.NormalizedFields = map[string]any{
		"destination_ipv4": "1.1.1.2",
		"evt_type":         "connect",
	}
	if err := content.Validate(); err == nil {
		t.Fatal("changed normalized content with stale digest was accepted")
	}
	digest := event
	digest.NormalizedFieldsSHA256 = strings.Repeat("0", 64)
	if err := digest.Validate(); err == nil {
		t.Fatal("changed normalized digest was accepted")
	}
	id := event
	id.EventID = "evt_" + strings.Repeat("0", 64)
	if err := id.Validate(); err == nil {
		t.Fatal("changed event ID was accepted")
	}
}

func TestBadSignatureFixtureRemainsContentValidButCryptographicallyInvalid(t *testing.T) {
	event, err := DecodeStrict[EventEnvelopeV1](
		bytes.NewReader(fixtureBytes(t, "envelope.bad-signature.json")),
		65536,
	)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := hex.DecodeString(
		"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
	)
	if err := VerifyEventSignature(event, public); err == nil {
		t.Fatal("bad signature fixture verified")
	}
}

func TestStructuredNearValidMutationsForEveryPositiveFixture(t *testing.T) {
	type mutation func(map[string]any)
	tests := []struct {
		name      string
		fixture   string
		decode    func([]byte) error
		wrongType mutation
		oneOver   mutation
		semantic  mutation
	}{
		{
			"event",
			"envelope.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[EventEnvelopeV1](bytes.NewReader(raw), 65536)
				return err
			},
			func(value map[string]any) { value["source_sequence"] = "7" },
			func(value map[string]any) {
				value["normalized_fields"] = map[string]any{
					"x": strings.Repeat("a", 8193),
				}
			},
			func(value map[string]any) {
				value["normalized_fields"] = map[string]any{
					"destination_ipv4": "1.1.1.2",
					"evt_type":         "connect",
				}
			},
		},
		{
			"falco-candidate",
			"falco.candidate.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[FalcoConnectV1](bytes.NewReader(raw), 65536)
				return err
			},
			func(value map[string]any) { value["destination_port"] = "443" },
			func(value map[string]any) { value["destination_port"] = json.Number("65536") },
			func(value map[string]any) { value["evt_res"] = "ECONNREFUSED" },
		},
		{
			"falco-investigation",
			"falco.investigation.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[FalcoConnectV1](bytes.NewReader(raw), 65536)
				return err
			},
			func(value map[string]any) { value["destination_port"] = "443" },
			func(value map[string]any) {
				fields := make([]any, 33)
				for i := range fields {
					fields[i] = fmt.Sprintf("field_%02d", i)
				}
				value["missing_required_fields"] = fields
			},
			func(value map[string]any) { value["evt_rawres"] = json.Number("0") },
		},
		{
			"coverage",
			"coverage.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[CoverageEventV1](bytes.NewReader(raw), 65536)
				return err
			},
			func(value map[string]any) { value["dropped_count"] = "2" },
			func(value map[string]any) { value["component"] = strings.Repeat("a", 65) },
			func(value map[string]any) {
				value["closed_at"] = "2026-07-27T11:59:59Z"
			},
		},
		{
			"intent",
			"intent.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[TemporaryEgressDenyIntentV1](
					bytes.NewReader(raw),
					65536,
				)
				return err
			},
			func(value map[string]any) { value["ttl_seconds"] = "120" },
			func(value map[string]any) { value["ttl_seconds"] = json.Number("301") },
			func(value map[string]any) { value["repo_digests"] = []any{"z", "a"} },
		},
		{
			"plan",
			"plan.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[PreparedTemporaryEgressDenyPlanV1](
					bytes.NewReader(raw),
					65536,
				)
				return err
			},
			func(value map[string]any) { value["init_pid"] = "123" },
			func(value map[string]any) { value["ttl_seconds"] = json.Number("301") },
			func(value map[string]any) {
				value["approval_expires_at"] = "2026-07-27T12:05:03Z"
			},
		},
		{
			"hunter",
			"hunter.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[HunterOutputV1](bytes.NewReader(raw), 65536)
				return err
			},
			func(value map[string]any) { value["narrative"] = json.Number("7") },
			func(value map[string]any) {
				value["hypotheses"] = []any{"x", "x", "x", "x", "x", "x", "x", "x", "x"}
			},
			func(value map[string]any) {
				value["supporting_evidence_ids"] = []any{
					"evt_" + strings.Repeat("f", 64),
					"evt_" + strings.Repeat("0", 64),
				}
			},
		},
		{
			"action",
			"action-record.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[ActionRecordV1](bytes.NewReader(raw), 65536)
				return err
			},
			func(value map[string]any) { value["details"] = []any{} },
			func(value map[string]any) {
				details := make(map[string]any, 65)
				for i := range 65 {
					details[fmt.Sprintf("k%d", i)] = nil
				}
				value["details"] = details
			},
			func(value map[string]any) {
				value["record_sha256"] = strings.Repeat("0", 64)
			},
		},
		{
			"key-transition",
			"key-transition.valid.json",
			func(raw []byte) error {
				_, err := DecodeStrict[KeyTransitionV1](bytes.NewReader(raw), 65536)
				return err
			},
			func(value map[string]any) { value["old_epoch"] = "1" },
			func(value map[string]any) {
				value["old_epoch"] = json.Number("18446744073709551616")
			},
			func(value map[string]any) { value["new_epoch"] = json.Number("3") },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, mutate := range map[string]mutation{
				"wrong-type": test.wrongType,
				"one-over":   test.oneOver,
				"semantic":   test.semantic,
			} {
				t.Run(name, func(t *testing.T) {
					raw := mutateFixture(t, test.fixture, mutate)
					if err := test.decode(raw); err == nil {
						t.Fatal("near-valid mutation was accepted")
					}
				})
			}
		})
	}
}

// declaredMissing returns missing_required_fields with field added, kept sorted and unique as the
// contract requires.
func declaredMissing(document map[string]any, field string) []string {
	seen := map[string]struct{}{field: {}}
	if existing, ok := document["missing_required_fields"].([]any); ok {
		for _, value := range existing {
			if name, isString := value.(string); isString {
				seen[name] = struct{}{}
			}
		}
	}
	declared := make([]string, 0, len(seen))
	for name := range seen {
		declared = append(declared, name)
	}
	sort.Strings(declared)
	return declared
}

// TestUndeclaredSensorOmissionIsRejected is the security-relevant half of the rule the test above
// deliberately keeps coherent: an absent sensor fact that is NOT declared must be refused, or an
// event that observed nothing would be accepted as an event that observed everything.
func TestUndeclaredSensorOmissionIsRejected(t *testing.T) {
	var document map[string]any
	if err := json.Unmarshal(fixtureBytes(t, "falco.investigation.valid.json"), &document); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	checked := 0
	for field := range FalcoSensorRequiredFields {
		if _, present := document[field]; !present {
			continue
		}
		raw := mutateFixture(t, "falco.investigation.valid.json", func(mutated map[string]any) {
			delete(mutated, field)
			mutated["missing_required_fields"] = []string{}
		})
		if _, err := DecodeStrict[FalcoConnectV1](bytes.NewReader(raw), 65536); err == nil {
			t.Fatalf("undeclared omission of sensor fact %q was accepted", field)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("the fixture carries no sensor facts, so this proved nothing; fix the fixture")
	}
}
