package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"agmind.local/sais/internal/contracts"
)

const (
	adminSocketPath = "/run/agmind-sais/actuator-admin/socket"
	maxResponseBody = int64(65_536)
)

var cliPlanIDPattern = regexp.MustCompile(`^plan_[0-9a-f]{32}$`)

type decisionRequestV1 struct {
	SchemaVersion string `json:"schema_version"`
	PlanHashValue string `json:"plan_hash"`
	Nonce         string `json:"nonce"`
}

func newAdminClient() *http.Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", adminSocketPath)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func exactJSONResponse(response *http.Response) error {
	mediaType, parameters, err := mime.ParseMediaType(
		response.Header.Get("Content-Type"),
	)
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return fmt.Errorf("actuator returned an invalid content type")
	}
	return nil
}

func boundedResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > int(maxResponseBody) {
		return nil, fmt.Errorf("actuator response exceeds bound")
	}
	return raw, nil
}

func getPlan(
	ctx context.Context,
	client *http.Client,
	planID string,
) (contracts.PreparedTemporaryEgressDenyPlanV1, error) {
	if !cliPlanIDPattern.MatchString(planID) {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, fmt.Errorf("invalid plan ID")
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://unix/v1/admin/plans/"+planID,
		nil,
	)
	if err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	request.Close = true
	response, err := client.Do(request)
	if err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	raw, readErr := boundedResponse(response)
	if readErr != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, readErr
	}
	if response.StatusCode != http.StatusOK {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, fmt.Errorf(
			"actuator rejected plan lookup with status %d",
			response.StatusCode,
		)
	}
	if err := exactJSONResponse(response); err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	plan, err := contracts.DecodeStrict[contracts.PreparedTemporaryEgressDenyPlanV1](
		bytes.NewReader(raw),
		maxResponseBody,
	)
	if err != nil {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, err
	}
	if plan.PlanID != planID {
		return contracts.PreparedTemporaryEgressDenyPlanV1{}, fmt.Errorf(
			"actuator returned a mismatched plan ID",
		)
	}
	return plan, nil
}

func submitDecision(
	ctx context.Context,
	client *http.Client,
	plan contracts.PreparedTemporaryEgressDenyPlanV1,
	verb string,
) (contracts.ActionRecordV1, error) {
	if err := plan.Validate(); err != nil ||
		(verb != "approve" && verb != "reject") {
		return contracts.ActionRecordV1{}, fmt.Errorf("invalid local plan decision")
	}
	payload, err := contracts.CanonicalJSON(decisionRequestV1{
		SchemaVersion: "agmind.local-plan-decision.v1",
		PlanHashValue: plan.PlanHashValue,
		Nonce:         plan.Nonce,
	})
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://unix/v1/admin/plans/"+plan.PlanID+"/"+verb,
		bytes.NewReader(payload),
	)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Close = true
	response, err := client.Do(request)
	if err != nil {
		return contracts.ActionRecordV1{}, err
	}
	raw, readErr := boundedResponse(response)
	if readErr != nil {
		return contracts.ActionRecordV1{}, readErr
	}
	if response.StatusCode != http.StatusOK {
		return contracts.ActionRecordV1{}, fmt.Errorf(
			"actuator rejected %s with status %d",
			verb,
			response.StatusCode,
		)
	}
	if err := exactJSONResponse(response); err != nil {
		return contracts.ActionRecordV1{}, err
	}
	return contracts.DecodeStrict[contracts.ActionRecordV1](
		bytes.NewReader(raw),
		maxResponseBody,
	)
}

func renderPlan(writer io.Writer, plan contracts.PreparedTemporaryEgressDenyPlanV1) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(
		writer,
		"Plan ID: %s\nAction: temporary egress deny\nHost ID: %s\nHost boot ID: %s\nContainer ID: %s\nContainer started at: %s\nInventory generation/revision: %d/%d\nImage ID: %s\nImmutable spec SHA-256: %s\nInit PID/start ticks: %d/%d\nCgroup path SHA-256: %s\nNetwork namespace inode: %d\nDestination IPv4: %s\nTTL seconds: %d\nDetector bundle SHA-256: %s\nPolicy bundle: %s (%s)\nCoverage: admitted snapshot %s\nHard limits: %s\nDocker network snapshot SHA-256: %s\nManagement denylist SHA-256: %s\nSpecial-use registry SHA-256: %s\nPrepared at: %s\nApproval expires at: %s\nExpected impact: block only outbound IPv4 traffic to %s inside this container network namespace; other destinations and ingress remain unchanged.\nExpiry behavior: approval is never automatic; after apply, the native deny expires after %d seconds even if the control plane is unavailable; expired or stale plans are never retargeted.\n",
		plan.PlanID,
		plan.HostID,
		plan.BootID,
		plan.DockerContainerID,
		plan.DockerStartedAt,
		plan.InventoryGeneration,
		plan.InventoryRevision,
		plan.ImageID,
		plan.ImmutableSpecSHA256,
		plan.InitPID,
		plan.PIDStartTicks,
		plan.CgroupPathSHA256,
		plan.NetworkNamespaceInode,
		plan.DestinationIPv4,
		plan.TTLSeconds,
		plan.DetectorBundleSHA256,
		plan.PolicyBundleVersion,
		plan.PolicyBundleSHA256,
		plan.CoverageSnapshotSHA256,
		plan.HardLimitsVersion,
		plan.DockerNetworkSnapshotSHA256,
		plan.ManagementDenylistSHA256,
		plan.SpecialUseRegistrySHA256,
		plan.PreparedAt,
		plan.ApprovalExpiresAt,
		plan.DestinationIPv4,
		plan.TTLSeconds,
	)
	if err != nil {
		return err
	}
	for _, evidenceID := range plan.EvidenceIDs {
		if _, err := fmt.Fprintf(writer, "Evidence: %s\n", evidenceID); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(writer, "Plan hash: %s\n", plan.PlanHashValue)
	return err
}

func confirmationText(verb, planHash string) (string, error) {
	if (verb != "approve" && verb != "reject") || len(planHash) != 64 {
		return "", fmt.Errorf("invalid confirmation")
	}
	return verb + " " + planHash[len(planHash)-12:], nil
}

func confirmDecision(
	stdin *os.File,
	stdout io.Writer,
	verb string,
	planHash string,
) error {
	if stdin == nil {
		return fmt.Errorf("interactive TTY is required")
	}
	if !isTerminal(stdin) {
		return fmt.Errorf("interactive TTY is required")
	}
	expected, err := confirmationText(verb, planHash)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "Type %q to continue: ", expected); err != nil {
		return err
	}
	reader := bufio.NewReader(io.LimitReader(stdin, 130))
	line, err := reader.ReadString('\n')
	if err != nil || len(line) > 129 || !strings.HasSuffix(line, "\n") {
		return fmt.Errorf("confirmation rejected")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line != expected {
		return fmt.Errorf("confirmation rejected")
	}
	return nil
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: agmindctl proposal show <plan-id>")
	fmt.Fprintln(writer, "       agmindctl proposal approve <plan-id>")
	fmt.Fprintln(writer, "       agmindctl proposal reject <plan-id>")
}

func run(
	arguments []string,
	stdin *os.File,
	stdout io.Writer,
	client *http.Client,
) error {
	if len(arguments) != 3 || arguments[0] != "proposal" ||
		(arguments[1] != "show" && arguments[1] != "approve" && arguments[1] != "reject") ||
		!cliPlanIDPattern.MatchString(arguments[2]) {
		return fmt.Errorf("invalid command")
	}
	if client == nil {
		return fmt.Errorf("admin client is unavailable")
	}
	lookupContext, cancelLookup := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	plan, err := getPlan(lookupContext, client, arguments[2])
	cancelLookup()
	if err != nil {
		return err
	}
	if err := renderPlan(stdout, plan); err != nil {
		return err
	}
	if arguments[1] == "show" {
		return nil
	}
	if err := confirmDecision(stdin, stdout, arguments[1], plan.PlanHashValue); err != nil {
		return err
	}
	decisionContext, cancelDecision := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancelDecision()
	record, err := submitDecision(
		decisionContext,
		client,
		plan,
		arguments[1],
	)
	if err != nil {
		return err
	}
	expectedState := "APPROVED"
	if arguments[1] == "reject" {
		expectedState = "REJECTED"
	}
	if record.PlanID != plan.PlanID || record.PlanHashValue != plan.PlanHashValue ||
		record.State != expectedState {
		return fmt.Errorf("actuator returned a mismatched decision receipt")
	}
	_, err = fmt.Fprintf(stdout, "Decision: %s\nRecord ID: %s\n", record.State, record.RecordID)
	return err
}

func main() {
	err := run(os.Args[1:], os.Stdin, os.Stdout, newAdminClient())
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "agmindctl: canceled")
	} else {
		fmt.Fprintln(os.Stderr, "agmindctl:", err)
	}
	usage(os.Stderr)
	os.Exit(1)
}
