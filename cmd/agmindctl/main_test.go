package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"agmind.local/sais/internal/contracts"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestRenderAndConfirmationStayExactAndNonAutomatable(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/v1/plan.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contracts.DecodeStrict[contracts.PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := renderPlan(&output, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Plan hash: "+plan.PlanHashValue) ||
		!strings.Contains(output.String(), "Destination IPv4: "+plan.DestinationIPv4) ||
		!strings.Contains(output.String(), "Immutable spec SHA-256: "+plan.ImmutableSpecSHA256) ||
		!strings.Contains(output.String(), "Policy bundle: "+plan.PolicyBundleVersion) ||
		!strings.Contains(output.String(), "Coverage: admitted snapshot "+plan.CoverageSnapshotSHA256) ||
		!strings.Contains(output.String(), "Expected impact:") ||
		!strings.Contains(output.String(), "Expiry behavior:") {
		t.Fatalf("render omitted authority fields: %s", output.String())
	}
	for _, forbidden := range []string{"narrative", "cmdline", "\x1b"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("render leaked %q", forbidden)
		}
	}
	expected := "approve " + plan.PlanHashValue[len(plan.PlanHashValue)-12:]
	if actual, err := confirmationText("approve", plan.PlanHashValue); err != nil || actual != expected {
		t.Fatalf("confirmation=%q err=%v want=%q", actual, err, expected)
	}
	redirected, err := os.CreateTemp(t.TempDir(), "redirected-input")
	if err != nil {
		t.Fatal(err)
	}
	defer redirected.Close()
	if err := confirmDecision(
		redirected,
		&bytes.Buffer{},
		"approve",
		plan.PlanHashValue,
	); err == nil {
		t.Fatal("redirected input bypassed TTY approval")
	}
	mismatchedClient := &http.Client{Transport: roundTripFunc(
		func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(bytes.NewReader(raw)),
			}, nil
		},
	)}
	if _, err := getPlan(
		context.Background(),
		mismatchedClient,
		"plan_11111111111111111111111111111111",
	); err == nil {
		t.Fatal("mismatched response plan ID was accepted")
	}
}

func TestPendingPlanListCommandIsBoundedAndCanonical(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/fixtures/v1/plan.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contracts.DecodeStrict[contracts.PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(raw),
		65_536,
	)
	if err != nil {
		t.Fatal(err)
	}
	listing := contracts.PendingPlanListV1{
		SchemaVersion: "agmind.pending-plan-list.v1",
		State:         "PENDING_APPROVAL",
		Plans: []contracts.PendingPlanSummaryV1{{
			PlanID:            plan.PlanID,
			DockerContainerID: plan.DockerContainerID,
			DestinationIPv4:   plan.DestinationIPv4,
			PreparedAt:        plan.PreparedAt,
			ApprovalExpiresAt: plan.ApprovalExpiresAt,
		}},
	}
	payload, err := contracts.CanonicalJSON(listing)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet ||
				request.URL.RequestURI() != "/v1/plans?state=PENDING_APPROVAL&limit=7" {
				t.Fatalf("unexpected request: %s %s", request.Method, request.URL.RequestURI())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(bytes.NewReader(payload)),
			}, nil
		},
	)}
	var output bytes.Buffer
	if err := run(
		[]string{"plans", "pending", "--json", "--limit", "7"},
		nil,
		&output,
		client,
	); err != nil {
		t.Fatal(err)
	}
	if output.String() != string(payload)+"\n" {
		t.Fatalf("pending JSON is not canonical: %q", output.String())
	}
}
