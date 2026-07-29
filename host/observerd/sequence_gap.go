package observerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"agmind.local/sais/internal/contracts"
)

type sequenceGapOpen struct {
	SourceSequence uint64
	Start          uint64
	End            uint64
	OpenedAt       string
}

type sequenceGapClose struct {
	SourceSequence uint64
	Start          uint64
	End            uint64
	OpenedAt       string
	ClosedAt       string
	Generation     uint64
}

type dockerReconcileReceipt struct {
	SourceSequence uint64
	Generation     uint64
	ClosedAt       string
	openedAt       string
}

type dockerReconcileOpen struct {
	SourceSequence uint64
	Generation     uint64
	OpenedAt       string
}

type sequenceGapProofScan struct {
	Opens      []sequenceGapOpen
	Closes     []sequenceGapClose
	Unpaired   []sequenceGapOpen
	recoveries []dockerReconcileReceipt
}

func uint64Field(fields map[string]any, name string) (uint64, bool) {
	value, ok := fields[name]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case uint64:
		return typed, true
	case json.Number:
		parsed, err := strconv.ParseUint(typed.String(), 10, 64)
		return parsed, err == nil && strconv.FormatUint(parsed, 10) == typed.String()
	default:
		return 0, false
	}
}

func stringField(fields map[string]any, name string) (string, bool) {
	value, ok := fields[name].(string)
	return value, ok
}

func exactKeys(fields map[string]any, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func canonicalUTCTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func sequenceGapFlagsMatch(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func emptySequenceGapSecurityContext(event contracts.EventEnvelopeV1) bool {
	return event.EventType == "coverage" &&
		event.ContainerID == nil &&
		event.ContainerStartTime == nil &&
		event.ReleaseID == nil &&
		event.InventoryRevision == nil &&
		len(event.RedactionFlags) == 0 &&
		event.SourcePayloadHash == event.NormalizedFieldsSHA256 &&
		sequenceGapFlagsMatch(
			event.CoverageFlags,
			"reconcile_required",
			"sequence_gap",
		)
}

func classifySequenceGap(
	event contracts.EventEnvelopeV1,
) (*sequenceGapOpen, *sequenceGapClose, error) {
	fields := event.NormalizedFields
	if event.EventType != "coverage" ||
		fields["kind"] != "observer_sequence_gap" {
		return nil, nil, nil
	}
	component, componentOK := stringField(fields, "component")
	severity, severityOK := stringField(fields, "severity")
	openedAt, openedOK := stringField(fields, "opened_at")
	reason, reasonOK := stringField(fields, "reason_code")
	start, startOK := uint64Field(fields, "affected_source_sequence_start")
	end, endOK := uint64Field(fields, "affected_source_sequence_end")
	if !componentOK || component != "observer" ||
		!severityOK || !openedOK || !reasonOK ||
		!startOK || !endOK || start == 0 || end < start ||
		!canonicalUTCTimestamp(openedAt) ||
		!emptySequenceGapSecurityContext(event) {
		return nil, nil, ErrSpoolCorrupt
	}
	switch severity {
	case "CRITICAL":
		if !exactKeys(
			fields,
			"component",
			"kind",
			"severity",
			"opened_at",
			"affected_source_sequence_start",
			"affected_source_sequence_end",
			"reason_code",
		) ||
			reason != "reserved_sequence_not_published" ||
			event.EventTime != openedAt ||
			event.InventoryGeneration != 0 {
			return nil, nil, ErrSpoolCorrupt
		}
		return &sequenceGapOpen{
			SourceSequence: event.SourceSequence,
			Start:          start,
			End:            end,
			OpenedAt:       openedAt,
		}, nil, nil
	case "INFO":
		closedAt, closedOK := stringField(fields, "closed_at")
		generation, generationOK := uint64Field(fields, "reconcile_generation")
		openedTime, openedTimeErr := time.Parse(time.RFC3339Nano, openedAt)
		closedTime, closedTimeErr := time.Parse(time.RFC3339Nano, closedAt)
		if !exactKeys(
			fields,
			"component",
			"kind",
			"severity",
			"opened_at",
			"closed_at",
			"affected_source_sequence_start",
			"affected_source_sequence_end",
			"reason_code",
			"reconcile_generation",
		) ||
			reason != "reserved_sequence_reconciled" ||
			!closedOK || !generationOK || generation == 0 ||
			!canonicalUTCTimestamp(closedAt) ||
			openedTimeErr != nil || closedTimeErr != nil ||
			closedTime.Before(openedTime) ||
			event.EventTime != closedAt ||
			event.InventoryGeneration != generation {
			return nil, nil, ErrSpoolCorrupt
		}
		return nil, &sequenceGapClose{
			SourceSequence: event.SourceSequence,
			Start:          start,
			End:            end,
			OpenedAt:       openedAt,
			ClosedAt:       closedAt,
			Generation:     generation,
		}, nil
	default:
		return nil, nil, ErrSpoolCorrupt
	}
}

func classifyDockerReconcileOpen(
	event contracts.EventEnvelopeV1,
) (*dockerReconcileOpen, error) {
	fields := event.NormalizedFields
	if event.EventType != "coverage" ||
		fields["kind"] != "docker_reconcile_gap" {
		return nil, nil
	}
	component, componentOK := stringField(fields, "component")
	severity, severityOK := stringField(fields, "severity")
	openedAt, openedOK := stringField(fields, "opened_at")
	reason, reasonOK := stringField(fields, "reason_code")
	generation, generationOK := uint64Field(fields, "reconcile_generation")
	if !exactKeys(
		fields,
		"component",
		"kind",
		"severity",
		"opened_at",
		"reason_code",
		"reconcile_generation",
	) ||
		!componentOK || component != "observer" ||
		!severityOK || severity != "CRITICAL" ||
		!openedOK || !canonicalUTCTimestamp(openedAt) ||
		!reasonOK || !safeASCII(reason, 1, 64) ||
		!generationOK || generation == 0 ||
		event.EventTime != openedAt ||
		event.InventoryGeneration != generation ||
		event.ContainerID != nil ||
		event.ContainerStartTime != nil ||
		event.ReleaseID != nil ||
		event.InventoryRevision != nil ||
		len(event.RedactionFlags) != 0 ||
		!sequenceGapFlagsMatch(
			event.CoverageFlags,
			"docker_event_gap",
			"reconcile_required",
		) ||
		event.SourcePayloadHash != event.NormalizedFieldsSHA256 {
		return nil, ErrSpoolCorrupt
	}
	return &dockerReconcileOpen{
		SourceSequence: event.SourceSequence,
		Generation:     generation,
		OpenedAt:       openedAt,
	}, nil
}

func classifyDockerRecovery(
	event contracts.EventEnvelopeV1,
) (*dockerReconcileReceipt, error) {
	fields := event.NormalizedFields
	if event.EventType != "coverage" ||
		fields["kind"] != "docker_reconcile_recovered" {
		return nil, nil
	}
	component, componentOK := stringField(fields, "component")
	severity, severityOK := stringField(fields, "severity")
	openedAt, openedOK := stringField(fields, "opened_at")
	closedAt, closedOK := stringField(fields, "closed_at")
	reason, reasonOK := stringField(fields, "reason_code")
	generation, generationOK := uint64Field(fields, "reconcile_generation")
	openedTime, openedTimeErr := time.Parse(time.RFC3339Nano, openedAt)
	closedTime, closedTimeErr := time.Parse(time.RFC3339Nano, closedAt)
	if !exactKeys(
		fields,
		"component",
		"kind",
		"severity",
		"opened_at",
		"closed_at",
		"reason_code",
		"reconcile_generation",
	) ||
		!componentOK || component != "observer" ||
		!severityOK || severity != "INFO" ||
		!openedOK || !canonicalUTCTimestamp(openedAt) ||
		!closedOK || !canonicalUTCTimestamp(closedAt) || !reasonOK ||
		openedTimeErr != nil || closedTimeErr != nil ||
		closedTime.Before(openedTime) ||
		reason != "docker_full_reconcile_succeeded" ||
		!generationOK || generation == 0 ||
		event.EventTime != closedAt ||
		event.InventoryGeneration != generation ||
		event.ContainerID != nil ||
		event.ContainerStartTime != nil ||
		event.ReleaseID != nil ||
		event.InventoryRevision != nil ||
		len(event.RedactionFlags) != 0 ||
		!sequenceGapFlagsMatch(
			event.CoverageFlags,
			"docker_event_gap",
			"reconcile_required",
		) ||
		event.SourcePayloadHash != event.NormalizedFieldsSHA256 {
		return nil, ErrSpoolCorrupt
	}
	return &dockerReconcileReceipt{
		SourceSequence: event.SourceSequence,
		Generation:     generation,
		ClosedAt:       closedAt,
		openedAt:       openedAt,
	}, nil
}

func proofKey(start uint64, end uint64, openedAt string) string {
	return fmt.Sprintf("%d:%d:%s", start, end, openedAt)
}

func sequenceGapPayloadHash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func rangesOverlap(
	leftStart uint64,
	leftEnd uint64,
	rightStart uint64,
	rightEnd uint64,
) bool {
	return leftStart <= rightEnd && rightStart <= leftEnd
}

func (spool *Spool) authenticatedPriorityEvents() (
	[]contracts.EventEnvelopeV1,
	error,
) {
	spool.mutex.Lock()
	defer spool.mutex.Unlock()
	if spool.closed {
		return nil, fmt.Errorf("spool closed")
	}
	sequences := make([]uint64, 0, len(spool.items))
	for sequence, item := range spool.items {
		if item.Tier == PriorityTier {
			sequences = append(sequences, sequence)
		}
	}
	sort.Slice(sequences, func(left, right int) bool {
		return sequences[left] < sequences[right]
	})
	events := make([]contracts.EventEnvelopeV1, 0, len(sequences))
	var scanned uint64
	for _, sequence := range sequences {
		item := spool.items[sequence]
		event, canonical, contentHash, frameBytes, identity, err :=
			readStandaloneFrame(item.path, spool.keys)
		if err != nil ||
			event.SourceSequence != item.Sequence ||
			event.EventID != item.EventID ||
			contentHash != item.ContentSHA256 ||
			frameBytes != item.frameBytes ||
			identity != item.identity ||
			!bytes.Equal(canonical, item.Canonical) ||
			validatePublicationItem(item) != nil {
			return nil, ErrSpoolCorrupt
		}
		canonicalBytes := uint64(len(canonical))
		if canonicalBytes > spool.config.MaxBytes ||
			scanned > spool.config.MaxBytes-canonicalBytes {
			return nil, ErrSpoolCorrupt
		}
		scanned += canonicalBytes
		events = append(events, event)
	}
	return events, nil
}

func (spool *Spool) scanSequenceGapProofs() (
	sequenceGapProofScan,
	error,
) {
	events, err := spool.authenticatedPriorityEvents()
	if err != nil {
		return sequenceGapProofScan{}, err
	}
	result := sequenceGapProofScan{
		Opens:      make([]sequenceGapOpen, 0),
		Closes:     make([]sequenceGapClose, 0),
		Unpaired:   make([]sequenceGapOpen, 0),
		recoveries: make([]dockerReconcileReceipt, 0),
	}
	dockerOpens := make([]dockerReconcileOpen, 0)
	for _, event := range events {
		open, closeProof, classifyErr := classifySequenceGap(event)
		if classifyErr != nil {
			return sequenceGapProofScan{}, classifyErr
		}
		recovery, recoveryErr := classifyDockerRecovery(event)
		if recoveryErr != nil {
			return sequenceGapProofScan{}, recoveryErr
		}
		dockerOpen, dockerOpenErr := classifyDockerReconcileOpen(event)
		if dockerOpenErr != nil {
			return sequenceGapProofScan{}, dockerOpenErr
		}
		if open != nil {
			result.Opens = append(result.Opens, *open)
		}
		if closeProof != nil {
			result.Closes = append(result.Closes, *closeProof)
		}
		if recovery != nil {
			result.recoveries = append(result.recoveries, *recovery)
		}
		if dockerOpen != nil {
			dockerOpens = append(dockerOpens, *dockerOpen)
		}
	}
	for left := range result.Opens {
		for right := left + 1; right < len(result.Opens); right++ {
			if rangesOverlap(
				result.Opens[left].Start,
				result.Opens[left].End,
				result.Opens[right].Start,
				result.Opens[right].End,
			) {
				return sequenceGapProofScan{}, ErrSpoolCorrupt
			}
		}
	}
	opens := make(map[string]sequenceGapOpen, len(result.Opens))
	for _, open := range result.Opens {
		opens[proofKey(open.Start, open.End, open.OpenedAt)] = open
	}
	closes := make(map[string]sequenceGapClose, len(result.Closes))
	for _, closeProof := range result.Closes {
		key := proofKey(closeProof.Start, closeProof.End, closeProof.OpenedAt)
		if _, exists := closes[key]; exists {
			return sequenceGapProofScan{}, ErrSpoolCorrupt
		}
		if open, exists := opens[key]; exists {
			if closeProof.SourceSequence <= open.SourceSequence {
				return sequenceGapProofScan{}, ErrSpoolCorrupt
			}
			matchedRecovery := false
			for _, recovery := range result.recoveries {
				if recovery.SourceSequence > open.SourceSequence &&
					recovery.SourceSequence < closeProof.SourceSequence &&
					recovery.Generation == closeProof.Generation &&
					recovery.ClosedAt == closeProof.ClosedAt {
					for _, dockerOpen := range dockerOpens {
						if dockerOpen.SourceSequence > open.SourceSequence &&
							dockerOpen.SourceSequence <
								recovery.SourceSequence &&
							dockerOpen.Generation ==
								recovery.Generation &&
							dockerOpen.OpenedAt ==
								recovery.openedAt {
							matchedRecovery = true
							break
						}
					}
					if matchedRecovery {
						break
					}
				}
			}
			if !matchedRecovery {
				return sequenceGapProofScan{}, ErrSpoolCorrupt
			}
		} else {
			for _, retainedOpen := range result.Opens {
				if rangesOverlap(
					closeProof.Start,
					closeProof.End,
					retainedOpen.Start,
					retainedOpen.End,
				) {
					return sequenceGapProofScan{}, ErrSpoolCorrupt
				}
			}
		}
		closes[key] = closeProof
	}
	for _, open := range result.Opens {
		if _, closed := closes[proofKey(open.Start, open.End, open.OpenedAt)]; !closed {
			result.Unpaired = append(result.Unpaired, open)
		}
	}
	return result, nil
}

func (spool *Spool) failSequenceGapProofs(err error) error {
	persistErr := spool.state.PersistReadOnly(
		"observer_sequence_gap_proof_conflict",
	)
	return errors.Join(ErrSpoolCorrupt, err, persistErr)
}

func (spool *Spool) recoverSequenceGapMarkers() error {
	scan, err := spool.scanSequenceGapProofs()
	if err != nil {
		return spool.failSequenceGapProofs(err)
	}
	marker := spool.state.Snapshot().LastCoveredGapEnd
	gaps := spool.UncoveredGaps(marker)
	for index, gap := range gaps {
		matches := 0
		for _, open := range scan.Opens {
			if open.End <= marker {
				continue
			}
			if open.Start == gap.Start && open.End == gap.End {
				matches++
			} else if rangesOverlap(open.Start, open.End, gap.Start, gap.End) {
				return spool.failSequenceGapProofs(
					fmt.Errorf("sequence-gap open partially overlaps physical gap"),
				)
			}
		}
		if matches > 1 {
			return spool.failSequenceGapProofs(
				fmt.Errorf("duplicate sequence-gap open"),
			)
		}
		if matches == 0 {
			for _, laterGap := range gaps[index+1:] {
				for _, open := range scan.Opens {
					if open.Start == laterGap.Start && open.End == laterGap.End {
						return spool.failSequenceGapProofs(
							fmt.Errorf("sequence-gap marker recovery would skip a gap"),
						)
					}
				}
			}
			break
		}
		if err := spool.state.markGapCovered(gap.End); err != nil {
			return err
		}
		marker = gap.End
	}
	for _, open := range scan.Opens {
		if open.End <= marker {
			continue
		}
		matched := false
		for _, gap := range gaps {
			if open.Start == gap.Start && open.End == gap.End {
				matched = true
				break
			}
		}
		if !matched {
			return spool.failSequenceGapProofs(
				fmt.Errorf("sequence-gap open lacks exact physical gap"),
			)
		}
	}
	return nil
}

func (service *Service) closeOutstandingSequenceGaps(
	ctx context.Context,
	baseline uint64,
	receipt dockerReconcileReceipt,
) error {
	if service == nil || service.daemon == nil ||
		service.daemon.spool == nil || service.daemon.signer == nil ||
		receipt.Generation == 0 || receipt.Generation <= baseline ||
		receipt.SourceSequence == 0 || receipt.ClosedAt == "" {
		return fmt.Errorf("invalid sequence-gap recovery receipt")
	}
	scan, err := service.daemon.spool.scanSequenceGapProofs()
	if err != nil {
		return service.daemon.spool.failSequenceGapProofs(err)
	}
	receiptFound := false
	for _, recovered := range scan.recoveries {
		if recovered == receipt {
			receiptFound = true
			break
		}
	}
	if !receiptFound {
		return service.daemon.spool.failSequenceGapProofs(
			fmt.Errorf("sequence-gap recovery receipt is not durably spooled"),
		)
	}
	closedTime, err := time.Parse(time.RFC3339Nano, receipt.ClosedAt)
	if err != nil {
		return service.daemon.spool.failSequenceGapProofs(err)
	}
	openTimes := make([]time.Time, len(scan.Unpaired))
	for index, open := range scan.Unpaired {
		openTimes[index], err = time.Parse(time.RFC3339Nano, open.OpenedAt)
		if err != nil {
			return service.daemon.spool.failSequenceGapProofs(err)
		}
	}
	for _, openedAt := range openTimes {
		if closedTime.Before(openedAt) {
			return errors.Join(
				fmt.Errorf("Docker recovery predates sequence-gap open"),
				service.openDockerReconcileFences(),
			)
		}
	}
	for _, open := range scan.Unpaired {
		fields := map[string]any{
			"component":                      "observer",
			"kind":                           "observer_sequence_gap",
			"severity":                       "INFO",
			"opened_at":                      open.OpenedAt,
			"closed_at":                      receipt.ClosedAt,
			"affected_source_sequence_start": open.Start,
			"affected_source_sequence_end":   open.End,
			"reason_code":                    "reserved_sequence_reconciled",
			"reconcile_generation":           receipt.Generation,
		}
		canonical, canonicalErr := contracts.CanonicalJSON(fields)
		if canonicalErr != nil {
			return canonicalErr
		}
		sum := sequenceGapPayloadHash(canonical)
		if _, wrapErr := service.daemon.signer.Wrap(
			ctx,
			"coverage",
			fields,
			EventMetadata{
				EventTime:           closedTime,
				InventoryGeneration: receipt.Generation,
				RedactionFlags:      []string{},
				CoverageFlags: []string{
					"reconcile_required",
					"sequence_gap",
				},
				SourcePayloadHash: sum,
			},
		); wrapErr != nil {
			return wrapErr
		}
	}
	finalScan, err := service.daemon.spool.scanSequenceGapProofs()
	if err != nil {
		return service.daemon.spool.failSequenceGapProofs(err)
	}
	if len(finalScan.Unpaired) != 0 {
		return service.daemon.spool.failSequenceGapProofs(
			fmt.Errorf("sequence-gap close pairing is incomplete"),
		)
	}
	return nil
}
