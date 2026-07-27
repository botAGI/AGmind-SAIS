package observerd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"agmind.local/sais/internal/contracts"
)

type Coverage struct {
	state  *StateStore
	signer *EnvelopeSigner
}

func NewCoverage(state *StateStore, signer *EnvelopeSigner) *Coverage {
	return &Coverage{state: state, signer: signer}
}

func coverageMetadata(now time.Time, fields map[string]any) (EventMetadata, error) {
	canonical, err := contracts.CanonicalJSON(fields)
	if err != nil {
		return EventMetadata{}, err
	}
	sum := sha256.Sum256(canonical)
	return EventMetadata{
		EventTime:         now.UTC(),
		RedactionFlags:    []string{},
		CoverageFlags:     []string{"storage_pressure"},
		SourcePayloadHash: hex.EncodeToString(sum[:]),
	}, nil
}

func (signer *EnvelopeSigner) recordRoutineDrop() error {
	emit, err := signer.state.incrementRoutineDrop()
	if err != nil {
		return err
	}
	if !emit {
		return nil
	}
	now := signer.config.Now().UTC()
	fields := map[string]any{
		"component":     "observer",
		"kind":          "observer_spool_drop",
		"severity":      "CRITICAL",
		"opened_at":     now.Format(time.RFC3339Nano),
		"dropped_count": uint64(1),
		"reason_code":   "routine_spool_quota",
	}
	metadata, err := coverageMetadata(now, fields)
	if err != nil {
		return err
	}
	_, err = signer.Wrap(context.Background(), "coverage", fields, metadata)
	return err
}

func (store *StateStore) clearRoutineDrops() error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	next := store.state
	next.RoutineDropped = 0
	next.DropEventPending = false
	return store.replaceLocked(next)
}

// RecoverSpoolPressure emits one signed priority close record and only then
// clears the coalesced persistent counter.
func (coverage *Coverage) RecoverSpoolPressure(ctx context.Context) error {
	snapshot := coverage.state.Snapshot()
	if !snapshot.DropEventPending {
		return nil
	}
	now := coverage.signer.config.Now().UTC()
	fields := map[string]any{
		"component":     "observer",
		"kind":          "observer_spool_drop_recovered",
		"severity":      "INFO",
		"opened_at":     now.Format(time.RFC3339Nano),
		"closed_at":     now.Format(time.RFC3339Nano),
		"dropped_count": snapshot.RoutineDropped,
		"reason_code":   "routine_spool_recovered",
	}
	metadata, err := coverageMetadata(now, fields)
	if err != nil {
		return err
	}
	if _, err := coverage.signer.Wrap(ctx, "coverage", fields, metadata); err != nil {
		return err
	}
	return coverage.state.clearRoutineDrops()
}

func routineQuotaError(quotaErr, coverageErr error) error {
	return errors.Join(quotaErr, coverageErr)
}
