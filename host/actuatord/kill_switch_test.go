package actuatord

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"agmind.local/sais/internal/contracts"
)

func TestManualKillSwitchPersistsAndCannotClearAutomaticLocks(t *testing.T) {
	fixture := newPrepareFixture(t)
	root := t.TempDir()
	service := openFixtureService(t, root, fixture)
	if status := service.KillSwitchStatus(); status.Manual || status.EffectiveActive ||
		len(status.ReasonCodes) != 0 {
		t.Fatalf("absent state did not default disabled: %+v", status)
	}

	request := func(method, path string) (int, []byte) {
		t.Helper()
		recorder := httptest.NewRecorder()
		newAdminRoutes(service, 2001).ServeHTTP(
			recorder,
			httptest.NewRequest(method, path, http.NoBody),
		)
		response := recorder.Result()
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	decode := func(raw []byte) KillSwitchStatusV1 {
		t.Helper()
		status, err := contracts.DecodeStrict[KillSwitchStatusV1](
			bytes.NewReader(raw),
			manualKillSwitchMaxBytes,
		)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := contracts.CanonicalJSON(status)
		if err != nil || !bytes.Equal(canonical, raw) {
			t.Fatalf("non-canonical status: %q err=%v", raw, err)
		}
		return status
	}

	if code, raw := request(http.MethodPost, "/v1/admin/kill-switch/enable"); code != http.StatusOK {
		t.Fatalf("enable status=%d body=%q", code, raw)
	} else if status := decode(raw); !status.Manual || !status.EffectiveActive ||
		!reflect.DeepEqual(status.ReasonCodes, []string{"manual"}) {
		t.Fatalf("enable returned %+v", status)
	}
	statePath := filepath.Join(root, manualKillSwitchName)
	rawState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(rawState) != `{"enabled":true,"schema_version":"agmind.manual-kill-switch.v1"}` {
		t.Fatalf("unexpected durable state: %q", rawState)
	}
	if info, err := os.Stat(statePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode info=%v err=%v", info, err)
	}
	if _, err := service.Prepare(context.Background(), fixture.intent); !errors.Is(
		err,
		ErrKillSwitchActive,
	) {
		t.Fatalf("manual pause allowed a new plan: %v", err)
	}

	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	service = openFixtureService(t, root, fixture)
	if status := service.KillSwitchStatus(); !status.Manual || !status.EffectiveActive ||
		!reflect.DeepEqual(status.ReasonCodes, []string{"manual"}) {
		t.Fatalf("manual state was not recovered: %+v", status)
	}

	service.mutex.Lock()
	service.auditUncertain = true
	service.mutex.Unlock()
	if code, raw := request(http.MethodGet, "/v1/admin/kill-switch"); code != http.StatusOK {
		t.Fatalf("status code=%d body=%q", code, raw)
	} else if status := decode(raw); !reflect.DeepEqual(
		status.ReasonCodes,
		[]string{"audit_uncertain", "manual"},
	) {
		t.Fatalf("status reasons are not bounded and sorted: %+v", status)
	}
	if code, raw := request(http.MethodPost, "/v1/admin/kill-switch/disable"); code != http.StatusOK {
		t.Fatalf("disable status=%d body=%q", code, raw)
	} else if status := decode(raw); status.Manual || !status.EffectiveActive ||
		!reflect.DeepEqual(status.ReasonCodes, []string{"audit_uncertain"}) {
		t.Fatalf("disable bypassed automatic lock: %+v", status)
	}
	if !service.KillSwitchActive() {
		t.Fatal("automatic lock was bypassed after clearing manual state")
	}

	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	service = openFixtureService(t, root, fixture)
	if status := service.KillSwitchStatus(); !status.Manual || !status.EffectiveActive ||
		!reflect.DeepEqual(status.ReasonCodes, []string{"manual"}) {
		t.Fatalf("corrupt manual state did not fail closed: %+v", status)
	}
}
