package actuatord

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"agmind.local/sais/internal/contracts"
	"agmind.local/sais/internal/durablefile"
)

const (
	manualKillSwitchName     = "manual-kill-switch.json"
	manualKillSwitchMaxBytes = int64(256)
)

type manualKillSwitchStateV1 struct {
	SchemaVersion string `json:"schema_version"`
	Enabled       bool   `json:"enabled"`
}

func (state manualKillSwitchStateV1) Validate() error {
	if state.SchemaVersion != "agmind.manual-kill-switch.v1" {
		return durablefile.ErrUnsafePath
	}
	return nil
}

type KillSwitchStatusV1 struct {
	SchemaVersion   string   `json:"schema_version"`
	Manual          bool     `json:"manual"`
	EffectiveActive bool     `json:"effective_active"`
	ReasonCodes     []string `json:"reason_codes"`
}

func (status KillSwitchStatusV1) Validate() error {
	if status.SchemaVersion != "agmind.kill-switch-status.v1" ||
		status.EffectiveActive != (len(status.ReasonCodes) != 0) ||
		len(status.ReasonCodes) > 5 ||
		!slices.IsSorted(status.ReasonCodes) {
		return durablefile.ErrUnsafePath
	}
	manualReason := false
	previous := ""
	for _, reason := range status.ReasonCodes {
		if reason <= previous {
			return durablefile.ErrUnsafePath
		}
		previous = reason
		switch reason {
		case "manual":
			manualReason = true
		case "failed_dirty_or_inflight", "journal_failed", "audit_uncertain", "closed":
		default:
			return durablefile.ErrUnsafePath
		}
	}
	if status.Manual != manualReason {
		return durablefile.ErrUnsafePath
	}
	return nil
}

func manualKillSwitchPath(stateDir string) string {
	return filepath.Join(stateDir, manualKillSwitchName)
}

func loadManualKillSwitch(path string) (bool, bool) {
	raw, err := durablefile.ReadRegular(path, manualKillSwitchMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, true
	}
	if err != nil {
		return true, false
	}
	state, err := contracts.DecodeStrict[manualKillSwitchStateV1](
		bytes.NewReader(raw),
		manualKillSwitchMaxBytes,
	)
	if err != nil || state.Validate() != nil {
		return true, false
	}
	canonical, err := contracts.CanonicalJSON(state)
	if err != nil || !bytes.Equal(canonical, raw) {
		return true, false
	}
	return state.Enabled, true
}

func (service *Service) killSwitchStatusLocked() KillSwitchStatusV1 {
	reasons := make([]string, 0, 5)
	if service.manualKillSwitch {
		reasons = append(reasons, "manual")
	}
	if service.journal == nil || service.journal.failed() {
		reasons = append(reasons, "journal_failed")
	}
	if service.journal != nil && service.journal.mutationLocked() {
		reasons = append(reasons, "failed_dirty_or_inflight")
	}
	if service.auditUncertain {
		reasons = append(reasons, "audit_uncertain")
	}
	if service.closed {
		reasons = append(reasons, "closed")
	}
	slices.Sort(reasons)
	return KillSwitchStatusV1{
		SchemaVersion:   "agmind.kill-switch-status.v1",
		Manual:          service.manualKillSwitch,
		EffectiveActive: len(reasons) != 0,
		ReasonCodes:     reasons,
	}
}

func (service *Service) KillSwitchStatus() KillSwitchStatusV1 {
	if service == nil {
		return KillSwitchStatusV1{
			SchemaVersion:   "agmind.kill-switch-status.v1",
			EffectiveActive: true,
			ReasonCodes:     []string{"closed"},
		}
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	return service.killSwitchStatusLocked()
}

func (service *Service) setManualKillSwitch(enabled bool) (KillSwitchStatusV1, error) {
	if service == nil {
		return (*Service)(nil).KillSwitchStatus(), durablefile.ErrJournalClosed
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.closed {
		return service.killSwitchStatusLocked(), durablefile.ErrJournalClosed
	}
	if service.manualKillSwitch == enabled && service.manualKillSwitchExact {
		return service.killSwitchStatusLocked(), nil
	}
	payload, err := contracts.CanonicalJSON(manualKillSwitchStateV1{
		SchemaVersion: "agmind.manual-kill-switch.v1",
		Enabled:       enabled,
	})
	if err == nil {
		err = durablefile.AtomicWrite(service.manualKillSwitchPath, payload)
	}
	if err != nil {
		service.manualKillSwitch = true
		service.manualKillSwitchExact = false
		return service.killSwitchStatusLocked(), err
	}
	service.manualKillSwitch = enabled
	service.manualKillSwitchExact = true
	return service.killSwitchStatusLocked(), nil
}

func (service *Service) EnableManualKillSwitch() (KillSwitchStatusV1, error) {
	return service.setManualKillSwitch(true)
}

func (service *Service) DisableManualKillSwitch() (KillSwitchStatusV1, error) {
	return service.setManualKillSwitch(false)
}
