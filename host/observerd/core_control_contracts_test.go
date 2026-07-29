package observerd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
)

const (
	coreControlRepairID  = "11111111-1111-4111-8111-111111111111"
	coreControlSegmentID = "22222222-2222-4222-8222-222222222222"
)

func coreControlAuthorizeFixture() EvidenceRepairAuthorizeV1 {
	return EvidenceRepairAuthorizeV1{
		SchemaVersion:           "agmind.evidence-repair-authorize.v1",
		RepairID:                coreControlRepairID,
		SegmentID:               coreControlSegmentID,
		VerifiedBytes:           1_024,
		DiscardedBytes:          512,
		DiscardedSHA256:         strings.Repeat("1", 64),
		LastVerifiedFrameSHA256: strings.Repeat("2", 64),
		CurrentChainHeadSHA256:  strings.Repeat("3", 64),
		Reason:                  "torn_open_tail",
	}
}

func coreControlCompleteFixture() EvidenceRepairCompleteV1 {
	return EvidenceRepairCompleteV1{
		SchemaVersion:              "agmind.evidence-repair-complete.v1",
		RepairID:                   coreControlRepairID,
		AuthorizationEventID:       "evt_" + strings.Repeat("1", 64),
		AuthorizationContentSHA256: strings.Repeat("2", 64),
		SegmentID:                  coreControlSegmentID,
		VerifiedBytes:              1_024,
		PostRepairPrefixSHA256:     strings.Repeat("3", 64),
		LastVerifiedFrameSHA256:    strings.Repeat("4", 64),
		CurrentChainHeadSHA256:     strings.Repeat("5", 64),
		Reason:                     "torn_open_tail_completed",
	}
}

func coreControlTombstoneFixture() RetentionTombstoneV2 {
	return RetentionTombstoneV2{
		SchemaVersion: "agmind.retention-tombstone.v2",
		TombstoneID:   "33333333-3333-4333-8333-333333333333",
		RemovedManifestHashes: []string{
			strings.Repeat("1", 64),
			strings.Repeat("2", 64),
		},
		FirstRemovedManifestSHA256:  strings.Repeat("1", 64),
		LastRemovedManifestSHA256:   strings.Repeat("2", 64),
		FirstRetainedManifestSHA256: strings.Repeat("3", 64),
		RemovedBytes:                1_048_576,
		Reason:                      "retention_age_limit",
		PolicyVersion:               "agmind-retention-v1",
		CurrentChainHeadSHA256:      strings.Repeat("4", 64),
		ManifestRunSHA256: "d0712673656a35e23d25c06b3932ce72" +
			"e9d9b38d7331ccdfdd0772f9f074ece0",
	}
}

func coreControlBlockedFixture() RetentionBlockedV1 {
	return RetentionBlockedV1{
		SchemaVersion:          "agmind.retention-blocked.v1",
		BlockedID:              "44444444-4444-4444-8444-444444444444",
		TargetBytes:            1_000,
		RoutineBytes:           800,
		ProtectedBytes:         700,
		BlockedBytes:           500,
		Reason:                 "protected_evidence",
		CurrentChainHeadSHA256: strings.Repeat("5", 64),
	}
}

func testRetentionRunSHA256(t *testing.T, hashes []string) string {
	t.Helper()
	raw, err := contracts.CanonicalJSON(hashes)
	if err != nil {
		t.Fatal(err)
	}
	preimage := append([]byte("AGMIND_RETENTION_RUN_V2\x00"), raw...)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:])
}

func assertCoreControlDescriptor(
	t *testing.T,
	request CoreControlRequest,
	eventType string,
	operationKey string,
	maxBytes int64,
) {
	t.Helper()
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	if request.EventType() != eventType {
		t.Fatalf("event type=%q want=%q", request.EventType(), eventType)
	}
	if request.OperationKey() != operationKey {
		t.Fatalf("operation key=%q want=%q", request.OperationKey(), operationKey)
	}
	if request.RequestMaxBytes() != maxBytes {
		t.Fatalf("max bytes=%d want=%d", request.RequestMaxBytes(), maxBytes)
	}
	requestRaw, err := CanonicalCoreControlRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	fieldsRaw, err := contracts.CanonicalJSON(request.NormalizedFields())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestRaw, fieldsRaw) {
		t.Fatalf("normalized fields differ:\nrequest=%s\nfields=%s", requestRaw, fieldsRaw)
	}
	sum := sha256.Sum256(requestRaw)
	gotSHA256, err := CoreControlRequestSHA256(request)
	if err != nil {
		t.Fatal(err)
	}
	if gotSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("request sha256=%q", gotSHA256)
	}
}

func TestCoreControlContracts(t *testing.T) {
	t.Run("shared golden requests decode in Go", func(t *testing.T) {
		tests := []struct {
			name   string
			path   string
			decode func(*testing.T, []byte)
		}{
			{
				name: "repair authorize",
				path: "../../contracts/fixtures/v1/evidence-repair-authorize.valid.json",
				decode: func(t *testing.T, raw []byte) {
					got, err := DecodeCoreControlRequest[EvidenceRepairAuthorizeV1](
						bytes.NewReader(raw),
					)
					if err != nil {
						t.Fatal(err)
					}
					want := EvidenceRepairAuthorizeV1{
						SchemaVersion:           "agmind.evidence-repair-authorize.v1",
						RepairID:                coreControlRepairID,
						SegmentID:               coreControlSegmentID,
						VerifiedBytes:           4_096,
						DiscardedBytes:          512,
						DiscardedSHA256:         strings.Repeat("1", 64),
						LastVerifiedFrameSHA256: strings.Repeat("2", 64),
						CurrentChainHeadSHA256:  strings.Repeat("3", 64),
						Reason:                  "torn_open_tail",
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("decoded=%+v want=%+v", got, want)
					}
				},
			},
			{
				name: "repair complete",
				path: "../../contracts/fixtures/v1/evidence-repair-complete.valid.json",
				decode: func(t *testing.T, raw []byte) {
					got, err := DecodeCoreControlRequest[EvidenceRepairCompleteV1](
						bytes.NewReader(raw),
					)
					if err != nil {
						t.Fatal(err)
					}
					want := EvidenceRepairCompleteV1{
						SchemaVersion:              "agmind.evidence-repair-complete.v1",
						RepairID:                   coreControlRepairID,
						AuthorizationEventID:       "evt_" + strings.Repeat("5", 64),
						AuthorizationContentSHA256: strings.Repeat("6", 64),
						SegmentID:                  coreControlSegmentID,
						VerifiedBytes:              4_096,
						PostRepairPrefixSHA256:     strings.Repeat("4", 64),
						LastVerifiedFrameSHA256:    strings.Repeat("2", 64),
						CurrentChainHeadSHA256:     strings.Repeat("3", 64),
						Reason:                     "torn_open_tail_completed",
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("decoded=%+v want=%+v", got, want)
					}
				},
			},
			{
				name: "retention tombstone",
				path: "../../contracts/fixtures/v2/retention-tombstone.valid.json",
				decode: func(t *testing.T, raw []byte) {
					got, err := DecodeCoreControlRequest[RetentionTombstoneV2](
						bytes.NewReader(raw),
					)
					if err != nil {
						t.Fatal(err)
					}
					want := RetentionTombstoneV2{
						SchemaVersion: "agmind.retention-tombstone.v2",
						TombstoneID:   "33333333-3333-4333-8333-333333333333",
						RemovedManifestHashes: []string{
							strings.Repeat("a", 64),
							strings.Repeat("b", 64),
						},
						FirstRemovedManifestSHA256:  strings.Repeat("a", 64),
						LastRemovedManifestSHA256:   strings.Repeat("b", 64),
						FirstRetainedManifestSHA256: strings.Repeat("c", 64),
						RemovedBytes:                8_192,
						Reason:                      "retention_size_limit",
						PolicyVersion:               "agmind-retention-v1",
						CurrentChainHeadSHA256:      strings.Repeat("d", 64),
						ManifestRunSHA256: "7e0afece42c9fc551689444dec3b5143" +
							"9fa84bc50fe06cecfc5677174e8ec165",
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("decoded=%+v want=%+v", got, want)
					}
					hashesJSON, err := contracts.CanonicalJSON(
						want.RemovedManifestHashes,
					)
					if err != nil {
						t.Fatal(err)
					}
					preimage := append(
						[]byte("AGMIND_RETENTION_RUN_V2"),
						byte(0),
					)
					preimage = append(preimage, hashesJSON...)
					sum := sha256.Sum256(preimage)
					derived := hex.EncodeToString(sum[:])
					if derived != want.ManifestRunSHA256 ||
						got.ManifestRunSHA256 != derived {
						t.Fatalf(
							"locked manifest hash=%q decoded=%q derived=%q",
							want.ManifestRunSHA256,
							got.ManifestRunSHA256,
							derived,
						)
					}
				},
			},
			{
				name: "retention blocked",
				path: "../../contracts/fixtures/v1/retention-blocked.valid.json",
				decode: func(t *testing.T, raw []byte) {
					got, err := DecodeCoreControlRequest[RetentionBlockedV1](
						bytes.NewReader(raw),
					)
					if err != nil {
						t.Fatal(err)
					}
					want := RetentionBlockedV1{
						SchemaVersion:          "agmind.retention-blocked.v1",
						BlockedID:              "44444444-4444-4444-8444-444444444444",
						TargetBytes:            100,
						RoutineBytes:           40,
						ProtectedBytes:         75,
						BlockedBytes:           15,
						Reason:                 "protected_evidence",
						CurrentChainHeadSHA256: strings.Repeat("e", 64),
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("decoded=%+v want=%+v", got, want)
					}
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				raw, err := os.ReadFile(test.path)
				if err != nil {
					t.Fatal(err)
				}
				test.decode(t, raw)
			})
		}
	})

	t.Run("valid strict bodies expose exact producer descriptors", func(t *testing.T) {
		authorize := coreControlAuthorizeFixture()
		authorizeRaw, err := contracts.CanonicalJSON(authorize)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeCoreControlRequest[EvidenceRepairAuthorizeV1](
			bytes.NewReader(authorizeRaw),
		); err != nil {
			t.Fatal(err)
		}
		assertCoreControlDescriptor(
			t,
			authorize,
			"evidence_repair_authorized",
			"evidence_repair_authorized:"+authorize.RepairID,
			4_096,
		)

		complete := coreControlCompleteFixture()
		completeRaw, err := contracts.CanonicalJSON(complete)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeCoreControlRequest[EvidenceRepairCompleteV1](
			bytes.NewReader(completeRaw),
		); err != nil {
			t.Fatal(err)
		}
		assertCoreControlDescriptor(
			t,
			complete,
			"evidence_repair_completed",
			"evidence_repair_completed:"+complete.RepairID,
			4_096,
		)

		tombstone := coreControlTombstoneFixture()
		tombstoneRaw, err := contracts.CanonicalJSON(tombstone)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeCoreControlRequest[RetentionTombstoneV2](
			bytes.NewReader(tombstoneRaw),
		); err != nil {
			t.Fatal(err)
		}
		assertCoreControlDescriptor(
			t,
			tombstone,
			"retention_tombstone",
			"retention_tombstone:"+tombstone.TombstoneID,
			16_384,
		)

		blocked := coreControlBlockedFixture()
		blockedRaw, err := contracts.CanonicalJSON(blocked)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeCoreControlRequest[RetentionBlockedV1](
			bytes.NewReader(blockedRaw),
		); err != nil {
			t.Fatal(err)
		}
		assertCoreControlDescriptor(
			t,
			blocked,
			"retention_blocked_priority_evidence",
			"retention_blocked_priority_evidence:"+blocked.BlockedID,
			4_096,
		)
	})

	t.Run("authorize enforces the exact torn-tail bounds and sentinel", func(t *testing.T) {
		zero := coreControlAuthorizeFixture()
		zero.VerifiedBytes = 0
		zero.LastVerifiedFrameSHA256 = strings.Repeat("0", 64)
		if err := zero.Validate(); err != nil {
			t.Fatalf("zero-prefix authorization rejected: %v", err)
		}
		cases := map[string]func(*EvidenceRepairAuthorizeV1){
			"schema": func(value *EvidenceRepairAuthorizeV1) {
				value.SchemaVersion = "agmind.evidence-repair-authorize.v2"
			},
			"uppercase uuid": func(value *EvidenceRepairAuthorizeV1) {
				value.RepairID = "AAAAAAAA-1111-4111-8111-111111111111"
			},
			"verified over segment": func(value *EvidenceRepairAuthorizeV1) {
				value.VerifiedBytes = maxEvidenceSegmentBytes + 1
			},
			"discarded zero": func(value *EvidenceRepairAuthorizeV1) {
				value.DiscardedBytes = 0
			},
			"sum over segment": func(value *EvidenceRepairAuthorizeV1) {
				value.VerifiedBytes = maxEvidenceSegmentBytes
				value.DiscardedBytes = 1
			},
			"zero sentinel with verified bytes": func(value *EvidenceRepairAuthorizeV1) {
				value.LastVerifiedFrameSHA256 = strings.Repeat("0", 64)
			},
			"nonzero sentinel at zero bytes": func(value *EvidenceRepairAuthorizeV1) {
				value.VerifiedBytes = 0
			},
			"uppercase hash": func(value *EvidenceRepairAuthorizeV1) {
				value.DiscardedSHA256 = strings.Repeat("A", 64)
			},
			"reason": func(value *EvidenceRepairAuthorizeV1) {
				value.Reason = "tail"
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				value := coreControlAuthorizeFixture()
				mutate(&value)
				if err := value.Validate(); err == nil {
					t.Fatal("expected validation error")
				}
			})
		}
	})

	t.Run("complete enforces authorization identity and zero-prefix hash", func(t *testing.T) {
		zero := coreControlCompleteFixture()
		zero.VerifiedBytes = 0
		zero.PostRepairPrefixSHA256 = emptySHA256
		zero.LastVerifiedFrameSHA256 = strings.Repeat("0", 64)
		if err := zero.Validate(); err != nil {
			t.Fatalf("zero-prefix completion rejected: %v", err)
		}
		cases := map[string]func(*EvidenceRepairCompleteV1){
			"schema": func(value *EvidenceRepairCompleteV1) {
				value.SchemaVersion = "agmind.evidence-repair-complete.v2"
			},
			"authorization event": func(value *EvidenceRepairCompleteV1) {
				value.AuthorizationEventID = strings.Repeat("1", 64)
			},
			"authorization content": func(value *EvidenceRepairCompleteV1) {
				value.AuthorizationContentSHA256 = strings.Repeat("A", 64)
			},
			"verified over segment": func(value *EvidenceRepairCompleteV1) {
				value.VerifiedBytes = maxEvidenceSegmentBytes + 1
			},
			"zero prefix mismatch": func(value *EvidenceRepairCompleteV1) {
				value.VerifiedBytes = 0
				value.LastVerifiedFrameSHA256 = strings.Repeat("0", 64)
			},
			"zero sentinel with verified bytes": func(value *EvidenceRepairCompleteV1) {
				value.LastVerifiedFrameSHA256 = strings.Repeat("0", 64)
			},
			"reason": func(value *EvidenceRepairCompleteV1) {
				value.Reason = "torn_open_tail"
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				value := coreControlCompleteFixture()
				mutate(&value)
				if err := value.Validate(); err == nil {
					t.Fatal("expected validation error")
				}
			})
		}
	})

	t.Run("tombstone binds an ordered unique run of at most 128 manifests", func(t *testing.T) {
		fixture := coreControlTombstoneFixture()
		got, err := RetentionManifestRunSHA256(fixture.RemovedManifestHashes)
		if err != nil {
			t.Fatal(err)
		}
		const wantActualNULDomain = "d0712673656a35e23d25c06b3932ce72" +
			"e9d9b38d7331ccdfdd0772f9f074ece0"
		if got != wantActualNULDomain {
			t.Fatalf("manifest run sha256=%q want=%q", got, wantActualNULDomain)
		}

		descending := fixture
		descending.RemovedManifestHashes = []string{
			strings.Repeat("2", 64),
			strings.Repeat("1", 64),
		}
		descending.FirstRemovedManifestSHA256 = descending.RemovedManifestHashes[0]
		descending.LastRemovedManifestSHA256 = descending.RemovedManifestHashes[1]
		descending.ManifestRunSHA256 = testRetentionRunSHA256(
			t,
			descending.RemovedManifestHashes,
		)
		if err := descending.Validate(); err != nil {
			t.Fatalf("manifest order was incorrectly lexicalized: %v", err)
		}

		atLimit := fixture
		atLimit.RemovedManifestHashes = make([]string, maxRetentionManifestRun)
		for index := range atLimit.RemovedManifestHashes {
			atLimit.RemovedManifestHashes[index] = fmt.Sprintf("%064x", index+1)
		}
		atLimit.FirstRemovedManifestSHA256 = atLimit.RemovedManifestHashes[0]
		atLimit.LastRemovedManifestSHA256 = atLimit.RemovedManifestHashes[len(
			atLimit.RemovedManifestHashes,
		)-1]
		atLimit.ManifestRunSHA256 = testRetentionRunSHA256(
			t,
			atLimit.RemovedManifestHashes,
		)
		if err := atLimit.Validate(); err != nil {
			t.Fatalf("128-manifest run rejected: %v", err)
		}

		cases := map[string]func(*RetentionTombstoneV2){
			"empty": func(value *RetentionTombstoneV2) {
				value.RemovedManifestHashes = []string{}
			},
			"129": func(value *RetentionTombstoneV2) {
				value.RemovedManifestHashes = append(
					append([]string{}, atLimit.RemovedManifestHashes...),
					fmt.Sprintf("%064x", maxRetentionManifestRun+1),
				)
			},
			"duplicate": func(value *RetentionTombstoneV2) {
				value.RemovedManifestHashes[1] = value.RemovedManifestHashes[0]
			},
			"first mismatch": func(value *RetentionTombstoneV2) {
				value.FirstRemovedManifestSHA256 = strings.Repeat("9", 64)
			},
			"last mismatch": func(value *RetentionTombstoneV2) {
				value.LastRemovedManifestSHA256 = strings.Repeat("9", 64)
			},
			"removed bytes": func(value *RetentionTombstoneV2) {
				value.RemovedBytes = 0
			},
			"reason": func(value *RetentionTombstoneV2) {
				value.Reason = "retention_manual"
			},
			"policy": func(value *RetentionTombstoneV2) {
				value.PolicyVersion = "agmind-retention-v2"
			},
			"run hash": func(value *RetentionTombstoneV2) {
				value.ManifestRunSHA256 = strings.Repeat("0", 64)
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				value := coreControlTombstoneFixture()
				value.RemovedManifestHashes = append(
					[]string{},
					value.RemovedManifestHashes...,
				)
				mutate(&value)
				if err := value.Validate(); err == nil {
					t.Fatal("expected validation error")
				}
			})
		}
	})

	t.Run("blocked event requires overflow-safe exact byte arithmetic", func(t *testing.T) {
		keyProof := coreControlBlockedFixture()
		keyProof.Reason = "required_key_proof"
		if err := keyProof.Validate(); err != nil {
			t.Fatalf("required-key-proof blocked event rejected: %v", err)
		}
		cases := map[string]func(*RetentionBlockedV1){
			"target zero": func(value *RetentionBlockedV1) {
				value.TargetBytes = 0
			},
			"sum overflow": func(value *RetentionBlockedV1) {
				value.RoutineBytes = math.MaxUint64
				value.ProtectedBytes = 1
				value.BlockedBytes = math.MaxUint64
			},
			"sum equals target": func(value *RetentionBlockedV1) {
				value.TargetBytes = value.RoutineBytes + value.ProtectedBytes
				value.BlockedBytes = 1
			},
			"blocked zero": func(value *RetentionBlockedV1) {
				value.BlockedBytes = 0
			},
			"blocked mismatch": func(value *RetentionBlockedV1) {
				value.BlockedBytes++
			},
			"reason": func(value *RetentionBlockedV1) {
				value.Reason = "priority"
			},
			"uppercase id": func(value *RetentionBlockedV1) {
				value.BlockedID = "AAAAAAAA-4444-4444-8444-444444444444"
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				value := coreControlBlockedFixture()
				mutate(&value)
				if err := value.Validate(); err == nil {
					t.Fatal("expected validation error")
				}
			})
		}
	})

	t.Run("wire decoding rejects malformed and coerced values", func(t *testing.T) {
		fixture := coreControlAuthorizeFixture()
		valid, err := contracts.CanonicalJSON(fixture)
		if err != nil {
			t.Fatal(err)
		}
		replace := func(oldValue, newValue string) []byte {
			t.Helper()
			changed := bytes.Replace(valid, []byte(oldValue), []byte(newValue), 1)
			if bytes.Equal(changed, valid) {
				t.Fatalf("fixture replacement %q did not match", oldValue)
			}
			return changed
		}
		cases := map[string][]byte{
			"missing": bytes.Replace(
				valid,
				[]byte(`"reason":"torn_open_tail",`),
				nil,
				1,
			),
			"extra": append(
				append([]byte{}, valid[:len(valid)-1]...),
				[]byte(`,"extra":true}`)...,
			),
			"duplicate": append(
				[]byte(`{"reason":"torn_open_tail",`),
				valid[1:]...,
			),
			"null": replace(
				`"repair_id":"`+fixture.RepairID+`"`,
				`"repair_id":null`,
			),
			"coerced string": replace(
				`"verified_bytes":1024`,
				`"verified_bytes":"1024"`,
			),
			"negative": replace(`"verified_bytes":1024`, `"verified_bytes":-1`),
			"float":    replace(`"verified_bytes":1024`, `"verified_bytes":1.0`),
			"boolean":  replace(`"verified_bytes":1024`, `"verified_bytes":true`),
			"overflow": replace(
				`"verified_bytes":1024`,
				`"verified_bytes":18446744073709551616`,
			),
		}
		for name, raw := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := DecodeCoreControlRequest[EvidenceRepairAuthorizeV1](
					bytes.NewReader(raw),
				); err == nil {
					t.Fatal("expected strict decoding error")
				}
			})
		}
	})

	t.Run("request byte limits are enforced by the typed decoder", func(t *testing.T) {
		authorizeRaw, err := contracts.CanonicalJSON(coreControlAuthorizeFixture())
		if err != nil {
			t.Fatal(err)
		}
		authorizeAtLimit := append(
			append([]byte{}, authorizeRaw...),
			bytes.Repeat(
				[]byte(" "),
				int(evidenceRepairAuthorizeRequestMaxBytes)-len(authorizeRaw),
			)...,
		)
		if _, err := DecodeCoreControlRequest[EvidenceRepairAuthorizeV1](
			bytes.NewReader(authorizeAtLimit),
		); err != nil {
			t.Fatalf("4 KiB request rejected: %v", err)
		}
		if _, err := DecodeCoreControlRequest[EvidenceRepairAuthorizeV1](
			bytes.NewReader(append(authorizeAtLimit, ' ')),
		); err == nil {
			t.Fatal("request over 4 KiB accepted")
		}

		tombstoneRaw, err := contracts.CanonicalJSON(coreControlTombstoneFixture())
		if err != nil {
			t.Fatal(err)
		}
		tombstoneAtLimit := append(
			append([]byte{}, tombstoneRaw...),
			bytes.Repeat(
				[]byte(" "),
				int(retentionTombstoneRequestMaxBytes)-len(tombstoneRaw),
			)...,
		)
		if _, err := DecodeCoreControlRequest[RetentionTombstoneV2](
			bytes.NewReader(tombstoneAtLimit),
		); err != nil {
			t.Fatalf("16 KiB request rejected: %v", err)
		}
		if _, err := DecodeCoreControlRequest[RetentionTombstoneV2](
			bytes.NewReader(append(tombstoneAtLimit, ' ')),
		); err == nil {
			t.Fatal("request over 16 KiB accepted")
		}
	})
}
