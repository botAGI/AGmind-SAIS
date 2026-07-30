package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func task6APointer[T any](value T) *T {
	return &value
}

func task6ARequest() PCCCorrelationSnapshotRequestV1 {
	return PCCCorrelationSnapshotRequestV1{
		SchemaVersion:         "agmind.pcc-correlation-snapshot-request.v1",
		TriggerEventID:        "evt_" + strings.Repeat("a", 64),
		TriggerContentSHA256:  strings.Repeat("b", 64),
		TriggerSourceSequence: 41,
		RequestedTTLSeconds:   120,
	}
}

func task6ATrigger() PCCFalcoTriggerProjectionV1 {
	return PCCFalcoTriggerProjectionV1{
		SchemaVersion:          "agmind.pcc-falco-trigger-projection.v1",
		EventID:                "evt_" + strings.Repeat("a", 64),
		ContentSHA256:          strings.Repeat("b", 64),
		NormalizedFieldsSHA256: strings.Repeat("c", 64),
		SourceSequence:         41,
		SourceID:               "agmind-observerd",
		SourceVersion:          "0.1.0",
		HostID:                 "123e4567-e89b-42d3-a456-426614174000",
		BootID:                 "123e4567-e89b-42d3-a456-426614174000",
		EventTime:              "2026-07-29T12:00:00.123456789Z",
		IngestTime:             "2026-07-29T12:00:00.123456789Z",
		ClockUncertaintyMS:     100,
		InventoryGeneration:    7,
		InventoryRevision:      3,
		ContainerID:            strings.Repeat("d", 64),
		ContainerStartTime:     "2026-07-29T11:59:00Z",
		ReleaseID:              "rel_2c9c95784f8c31c4eb4c3f75a770277e",
		DetectorRule:           "AGmind PCC Suspicious Process Outbound Connect",
		DetectorRuleVersion:    "agmind-pcc-rules-v1",
		FalcoVersion:           "0.44.1",
		EvtRawres:              task6APointer(int64(0)),
		EvtRes:                 "SUCCESS",
		SuccessfulConnect:      true,
		InvestigationOnly:      false,
		ImageID:                "sha256:" + strings.Repeat("e", 64),
		RepoDigests:            []string{},
		ImmutableSpecSHA256:    strings.Repeat("f", 64),
		ProcName:               task6APointer("curl"),
		ProcExePath:            task6APointer("/usr/bin/curl"),
		ProcParentName:         task6APointer("sh"),
		DestinationIPv4:        "1.1.1.1",
		DestinationPort:        443,
		L4Protocol:             "tcp",
		MissingRequiredFields:  []string{},
		CoverageFlags:          []string{},
		RawEventSHA256:         strings.Repeat("1", 64),
	}
}

func task6ANetworks() []PCCDockerNetworkV1 {
	return []PCCDockerNetworkV1{{
		NetworkID:        strings.Repeat("c", 64),
		Driver:           "bridge",
		SubnetCIDRs:      []string{"172.18.0.0/16"},
		GatewayAddresses: []string{"172.18.0.1"},
	}}
}

func task6ACompleteSnapshot() PCCCorrelationSnapshotV1 {
	return PCCCorrelationSnapshotV1{
		SchemaVersion:           "agmind.pcc-correlation-snapshot.v1",
		Outcome:                 "complete",
		RequestSHA256:           "4bc87347010d86cbeca0d11c1dc1e45dfd6dedc018d65bdbd246af659d48e2d5",
		Trigger:                 task6ATrigger(),
		DecisionTime:            "2026-07-29T12:00:01.123456Z",
		RequestedTTLSeconds:     120,
		CoverageThroughSequence: 41,
		HardLimitsVersion:       "pcc-hard-limits-v1",
		DetectorBundleSHA256: task6APointer(
			"f6189db90ea61fefe991672b20316f1693f723de28ab37800029a40545af7b15",
		),
		SpecialUseRegistrySHA256: task6APointer(
			"e3e39e76d00b1677335db8e9a805c7b9480ea2f4dc9e33f0b93cd3a905128d73",
		),
		OperatorDeniedNetworks:  task6APointer([]string{"10.0.0.0/24"}),
		OperatorDeniedAddresses: task6APointer([]string{"10.0.0.2"}),
		OperatorDenylistSHA256: task6APointer(
			"c5e904a2c27cc1ad3f01a9cb6cf0a6dee20fa4c842f9a1448052ff143fd2eba5",
		),
		ManagementDeniedNetworks:  task6APointer([]string{"10.0.0.0/24"}),
		ManagementDeniedAddresses: task6APointer([]string{"10.0.0.2"}),
		ManagementDenylistSHA256: task6APointer(
			"a9751844b944ce899506632969d875e36a5049dfb5c6ef7543295f3ae9bd5c71",
		),
		DockerNetworks: task6APointer(task6ANetworks()),
		DockerNetworkSnapshotSHA256: task6APointer(
			"36ad699bd9f227d9ec3b1158556a89fe19bb939fd8533ce53d3dc9b905b170a8",
		),
		DockerContainerID: task6APointer(strings.Repeat("d", 64)),
		DockerStartedAt:   task6APointer("2026-07-29T11:59:00Z"),
		ImageID:           task6APointer("sha256:" + strings.Repeat("e", 64)),
		RepoDigests:       task6APointer([]string{}),
		ImmutableSpecSHA256: task6APointer(
			strings.Repeat("f", 64),
		),
		InventoryGeneration:  task6APointer(uint64(7)),
		InventoryRevision:    task6APointer(uint64(3)),
		InventoryObservedAt:  task6APointer("2026-07-29T12:00:01Z"),
		NetworkMode:          task6APointer("default"),
		NetworkDriver:        task6APointer("bridge"),
		Privileged:           task6APointer(false),
		ConfiguredCapAdd:     task6APointer([]string{}),
		ConfiguredCapDrop:    task6APointer([]string{}),
		EffectiveCapNetAdmin: task6APointer(false),
		Running:              task6APointer(true),
	}
}

func task6AFailedSnapshot(reason string) PCCCorrelationSnapshotV1 {
	return PCCCorrelationSnapshotV1{
		SchemaVersion:           "agmind.pcc-correlation-snapshot.v1",
		Outcome:                 "failed",
		RequestSHA256:           "4bc87347010d86cbeca0d11c1dc1e45dfd6dedc018d65bdbd246af659d48e2d5",
		Trigger:                 task6ATrigger(),
		DecisionTime:            "2026-07-29T12:00:01.123456Z",
		RequestedTTLSeconds:     120,
		FailureReasons:          task6APointer([]string{reason}),
		CoverageThroughSequence: 41,
		HardLimitsVersion:       "pcc-hard-limits-v1",
	}
}

func task6ADecode[T Contract](t *testing.T, value T) error {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeStrict[T](bytes.NewReader(raw), 32*1024)
	return err
}

func task6AMutateJSON(
	t *testing.T,
	value any,
	mutate func(map[string]any),
) []byte {
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
	mutate(document)
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTask6AHashParityAndCanonicalInputValidation(t *testing.T) {
	requestHash, err := PCCCorrelationRequestSHA256(task6ARequest())
	if err != nil {
		t.Fatal(err)
	}
	detectorHash, err := PCCDetectorBundleSHA256([]byte("- rule: outbound\n"))
	if err != nil {
		t.Fatal(err)
	}
	operatorHash, err := PCCOperatorDenylistSHA256(
		[]string{"10.0.0.0/24"},
		[]string{"10.0.0.2"},
	)
	if err != nil {
		t.Fatal(err)
	}
	managementHash, err := PCCManagementDenylistSHA256(
		[]string{"10.0.0.0/24"},
		[]string{"10.0.0.2"},
	)
	if err != nil {
		t.Fatal(err)
	}
	networkHash, err := PCCDockerNetworkSnapshotSHA256(task6ANetworks())
	if err != nil {
		t.Fatal(err)
	}
	emptyNetworkHash, err := PCCDockerNetworkSnapshotSHA256(
		[]PCCDockerNetworkV1{},
	)
	if err != nil {
		t.Fatal(err)
	}
	hop := PCCBootTransitionHopV1{
		BoundaryEventType:      "observer_boot_boundary",
		EventID:                "evt_" + strings.Repeat("4", 64),
		ContentSHA256:          strings.Repeat("5", 64),
		SourceSequence:         100,
		BootID:                 "223e4567-e89b-42d3-a456-426614174001",
		PreviousBootID:         "123e4567-e89b-42d3-a456-426614174000",
		PreviousSourceSequence: 99,
	}
	chainHash, err := PCCBootTransitionChainSHA256(
		[]PCCBootTransitionHopV1{hop},
	)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{
		requestHash,
		detectorHash,
		operatorHash,
		managementHash,
		networkHash,
		emptyNetworkHash,
		chainHash,
	}
	want := []string{
		"4bc87347010d86cbeca0d11c1dc1e45dfd6dedc018d65bdbd246af659d48e2d5",
		"f6189db90ea61fefe991672b20316f1693f723de28ab37800029a40545af7b15",
		"c5e904a2c27cc1ad3f01a9cb6cf0a6dee20fa4c842f9a1448052ff143fd2eba5",
		"a9751844b944ce899506632969d875e36a5049dfb5c6ef7543295f3ae9bd5c71",
		"36ad699bd9f227d9ec3b1158556a89fe19bb939fd8533ce53d3dc9b905b170a8",
		"6748f6e775bc393276f0e78faeb4aa167bc69b0b90a012076d1f0a103feb3ac8",
		"84d7b640b5b0fa842ce99f646658832bbf538d663052eb4183d5402a7b83585c",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hash parity mismatch:\n got %q\nwant %q", got, want)
	}

	if _, err := PCCOperatorDenylistSHA256(
		[]string{"203.0.113.0/24", "198.18.0.0/15"},
		[]string{},
	); err == nil {
		t.Fatal("unsorted denylist was hashed")
	}
	if _, err := PCCManagementDenylistSHA256(nil, []string{}); err == nil {
		t.Fatal("absent denylist array was hashed")
	}
	if _, err := PCCOperatorDenylistSHA256(
		[]string{"2001:db8::/64"},
		[]string{},
	); err == nil {
		t.Fatal("IPv6 operator deny network was accepted in the IPv4 contract")
	}
	if _, err := PCCManagementDenylistSHA256(
		[]string{},
		[]string{"2001:db8::1"},
	); err == nil {
		t.Fatal("IPv6 management address was accepted in the IPv4 contract")
	}
	tooManyNetworks := make([]string, 129)
	tooManyAddresses := make([]string, 129)
	for index := range tooManyNetworks {
		tooManyNetworks[index] = fmt.Sprintf("10.0.0.%d/32", index)
		tooManyAddresses[index] = fmt.Sprintf("10.0.0.%d", index)
	}
	sort.Strings(tooManyNetworks)
	sort.Strings(tooManyAddresses)
	if _, err := PCCOperatorDenylistSHA256(
		tooManyNetworks,
		[]string{},
	); err == nil {
		t.Fatal("operator deny-network count above 128 was hashed")
	}
	if _, err := PCCManagementDenylistSHA256(
		[]string{},
		tooManyAddresses,
	); err == nil {
		t.Fatal("management deny-address count above 128 was hashed")
	}
	if _, err := PCCBootTransitionChainSHA256(nil); err == nil {
		t.Fatal("empty boot-transition chain was hashed")
	}
}

func TestTask6ARequestIsExactStrictAndBounded(t *testing.T) {
	request := task6ARequest()
	if err := task6ADecode(t, request); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []uint64{30, 120, 300} {
		request.RequestedTTLSeconds = ttl
		if err := request.Validate(); err != nil {
			t.Fatalf("TTL %d rejected: %v", ttl, err)
		}
	}
	for _, ttl := range []uint64{29, 301} {
		request.RequestedTTLSeconds = ttl
		if err := request.Validate(); err == nil {
			t.Fatalf("TTL %d accepted", ttl)
		}
	}
	request = task6ARequest()
	for _, field := range []string{
		"schema_version",
		"trigger_event_id",
		"trigger_content_sha256",
		"trigger_source_sequence",
		"requested_ttl_seconds",
	} {
		raw := task6AMutateJSON(t, request, func(document map[string]any) {
			delete(document, field)
		})
		if _, err := DecodeStrict[PCCCorrelationSnapshotRequestV1](
			bytes.NewReader(raw),
			32*1024,
		); err == nil {
			t.Fatalf("missing request field %q was accepted", field)
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown": func(document map[string]any) {
			document["detector_bundle_sha256"] = strings.Repeat("0", 64)
		},
		"null": func(document map[string]any) {
			document["trigger_content_sha256"] = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw := task6AMutateJSON(t, request, mutate)
			if _, err := DecodeStrict[PCCCorrelationSnapshotRequestV1](
				bytes.NewReader(raw),
				32*1024,
			); err == nil {
				t.Fatal("non-exact request was accepted")
			}
		})
	}
}

func TestTask6ARetainedTriggerRequiresCandidateCapableFacts(t *testing.T) {
	trigger := task6ATrigger()
	if err := task6ADecode(t, trigger); err != nil {
		t.Fatal(err)
	}
	nonblocking := trigger
	nonblocking.EvtRawres = nil
	nonblocking.EvtRes = "EINPROGRESS"
	if err := task6ADecode(t, nonblocking); err != nil {
		t.Fatalf("valid nonblocking trigger rejected: %v", err)
	}

	tests := map[string]func(*PCCFalcoTriggerProjectionV1){
		"source": func(value *PCCFalcoTriggerProjectionV1) {
			value.SourceID = "caller"
		},
		"clock": func(value *PCCFalcoTriggerProjectionV1) {
			value.ClockUncertaintyMS = 2001
		},
		"generation": func(value *PCCFalcoTriggerProjectionV1) {
			value.InventoryGeneration = 0
		},
		"release": func(value *PCCFalcoTriggerProjectionV1) {
			value.ReleaseID = "rel_" + strings.Repeat("0", 32)
		},
		"falco-version": func(value *PCCFalcoTriggerProjectionV1) {
			value.FalcoVersion = "0.43.0"
		},
		"detector-rule": func(value *PCCFalcoTriggerProjectionV1) {
			value.DetectorRule = "other"
		},
		"detector-rule-version": func(value *PCCFalcoTriggerProjectionV1) {
			value.DetectorRuleVersion = "other"
		},
		"hard-error": func(value *PCCFalcoTriggerProjectionV1) {
			value.EvtRawres = task6APointer(int64(-111))
			value.EvtRes = "ECONNREFUSED"
			value.SuccessfulConnect = false
		},
		"investigation": func(value *PCCFalcoTriggerProjectionV1) {
			value.InvestigationOnly = true
		},
		"sensor-omission": func(value *PCCFalcoTriggerProjectionV1) {
			value.ProcName = nil
			value.MissingRequiredFields = []string{"proc_name"}
		},
		"destination": func(value *PCCFalcoTriggerProjectionV1) {
			value.DestinationIPv4 = "01.1.1.1"
		},
		"repo-order": func(value *PCCFalcoTriggerProjectionV1) {
			value.RepoDigests = []string{"z", "a"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := task6ATrigger()
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid retained trigger was accepted")
			}
		})
	}

	raw := task6AMutateJSON(t, nonblocking, func(document map[string]any) {
		document["evt_rawres"] = nil
	})
	if _, err := DecodeStrict[PCCFalcoTriggerProjectionV1](
		bytes.NewReader(raw),
		32*1024,
	); err == nil {
		t.Fatal("explicit null optional trigger field was accepted")
	}
}

func TestTask6ANestedTriggerRequiresExactRequiredShape(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"missing-zero-field": func(trigger map[string]any) {
			delete(trigger, "clock_uncertainty_ms")
		},
		"null-zero-field": func(trigger map[string]any) {
			trigger["clock_uncertainty_ms"] = nil
		},
		"missing-false-field": func(trigger map[string]any) {
			delete(trigger, "investigation_only")
		},
		"null-false-field": func(trigger map[string]any) {
			trigger["investigation_only"] = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw := task6AMutateJSON(
				t,
				task6ACompleteSnapshot(),
				func(document map[string]any) {
					trigger, ok := document["trigger"].(map[string]any)
					if !ok {
						t.Fatal("encoded trigger is not an object")
					}
					mutate(trigger)
				},
			)
			if _, err := DecodeStrict[PCCCorrelationSnapshotV1](
				bytes.NewReader(raw),
				32*1024,
			); err == nil {
				t.Fatal("non-exact nested trigger shape was accepted")
			}
		})
	}
}

func TestTask6ADockerNetworksEnforceCanonicalCompleteBounds(t *testing.T) {
	network := task6ANetworks()[0]
	if err := task6ADecode(t, network); err != nil {
		t.Fatal(err)
	}
	ipv6 := network
	ipv6.SubnetCIDRs = []string{"2001:db8::/64"}
	ipv6.GatewayAddresses = []string{"2001:db8::1"}
	if err := ipv6.Validate(); err != nil {
		t.Fatalf("canonical IPv6 Docker facts were rejected: %v", err)
	}

	invalidNetwork := network
	invalidNetwork.SubnetCIDRs = []string{"10.0.0.1/24"}
	if err := invalidNetwork.Validate(); err == nil {
		t.Fatal("non-network CIDR was accepted")
	}
	invalidNetwork = network
	invalidNetwork.GatewayAddresses = []string{"2001:0db8::1"}
	if err := invalidNetwork.Validate(); err == nil {
		t.Fatal("non-canonical gateway was accepted")
	}
	invalidNetwork = network
	invalidNetwork.SubnetCIDRs = []string{"::ffff:192.0.2.0/120"}
	if err := invalidNetwork.Validate(); err == nil {
		t.Fatal("IPv4-mapped IPv6 subnet was accepted")
	}
	invalidNetwork = network
	invalidNetwork.GatewayAddresses = []string{"::ffff:192.0.2.1"}
	if err := invalidNetwork.Validate(); err == nil {
		t.Fatal("IPv4-mapped IPv6 gateway was accepted")
	}
	invalidNetwork = network
	invalidNetwork.SubnetCIDRs = nil
	if err := invalidNetwork.Validate(); err == nil {
		t.Fatal("absent subnet array was accepted")
	}
	invalidNetwork = network
	invalidNetwork.GatewayAddresses = make([]string, 33)
	if err := invalidNetwork.Validate(); err == nil {
		t.Fatal("per-network gateway limit was not enforced")
	}

	tooMany := make([]PCCDockerNetworkV1, 65)
	for index := range tooMany {
		tooMany[index] = PCCDockerNetworkV1{
			NetworkID:        fmt.Sprintf("%064x", index+1),
			Driver:           "bridge",
			SubnetCIDRs:      []string{},
			GatewayAddresses: []string{},
		}
	}
	if _, err := PCCDockerNetworkSnapshotSHA256(tooMany); err == nil {
		t.Fatal("network-count overflow was hashed")
	}

	totalOverflow := make([]PCCDockerNetworkV1, 5)
	for index := range totalOverflow {
		subnets := make([]string, 0, 32)
		for item := 0; item < 32; item++ {
			subnets = append(subnets, fmt.Sprintf("10.%d.%d.0/24", index, item))
		}
		totalOverflow[index] = PCCDockerNetworkV1{
			NetworkID:        fmt.Sprintf("%064x", index+1),
			Driver:           "bridge",
			SubnetCIDRs:      subnets,
			GatewayAddresses: []string{},
		}
	}
	if _, err := PCCDockerNetworkSnapshotSHA256(totalOverflow); err == nil {
		t.Fatal("total subnet overflow was hashed")
	}

	oversize := make([]PCCDockerNetworkV1, 64)
	for index := range oversize {
		subnets := []string{
			fmt.Sprintf("2001:db8:%x::/64", index*2),
			fmt.Sprintf("2001:db8:%x::/64", index*2+1),
		}
		gateways := []string{
			fmt.Sprintf("2001:db8:%x::1", index*2),
			fmt.Sprintf("2001:db8:%x::1", index*2+1),
		}
		sort.Strings(subnets)
		sort.Strings(gateways)
		oversize[index] = PCCDockerNetworkV1{
			NetworkID:        fmt.Sprintf("%064x", index+1),
			Driver:           strings.Repeat("d", 64),
			SubnetCIDRs:      subnets,
			GatewayAddresses: gateways,
		}
	}
	if _, err := PCCDockerNetworkSnapshotSHA256(oversize); err == nil {
		t.Fatal("16 KiB Docker network snapshot overflow was hashed")
	}
}

func TestTask6ABootTransitionHopEnforcesClosedBoundaryUnion(t *testing.T) {
	dedicated := PCCBootTransitionHopV1{
		BoundaryEventType:      "observer_boot_boundary",
		EventID:                "evt_" + strings.Repeat("4", 64),
		ContentSHA256:          strings.Repeat("5", 64),
		SourceSequence:         100,
		BootID:                 "223e4567-e89b-42d3-a456-426614174001",
		PreviousBootID:         "123e4567-e89b-42d3-a456-426614174000",
		PreviousSourceSequence: 99,
	}
	if err := task6ADecode(t, dedicated); err != nil {
		t.Fatal(err)
	}
	reservedGap := dedicated
	reservedGap.PreviousSourceSequence = 90
	if err := reservedGap.Validate(); err != nil {
		t.Fatalf("dedicated boundary with reserved sequence gap rejected: %v", err)
	}
	newBootTransition := dedicated
	newBootTransition.BoundaryEventType = "observer_key_transition"
	newBootTransition.RotationCompanionEventType = task6APointer(
		"observer_key_epoch_start",
	)
	newBootTransition.RotationCompanionEventID = task6APointer(
		"evt_" + strings.Repeat("6", 64),
	)
	newBootTransition.RotationCompanionContentSHA256 = task6APointer(
		strings.Repeat("7", 64),
	)
	newBootTransition.RotationCompanionSourceSequence = task6APointer(uint64(101))
	newBootTransition.RotationCompanionBootID = task6APointer(
		newBootTransition.BootID,
	)
	newBootTransition.PreviousSourceSequence = 90
	if err := newBootTransition.Validate(); err != nil {
		t.Fatalf("new-boot rotation pair with reserved gap rejected: %v", err)
	}
	oldBootTransition := newBootTransition
	oldBootTransition.BoundaryEventType = "observer_key_epoch_start"
	oldBootTransition.RotationCompanionEventType = task6APointer(
		"observer_key_transition",
	)
	oldBootTransition.RotationCompanionSourceSequence = task6APointer(uint64(99))
	oldBootTransition.RotationCompanionBootID = task6APointer(
		oldBootTransition.PreviousBootID,
	)
	oldBootTransition.PreviousSourceSequence = 99
	if err := oldBootTransition.Validate(); err != nil {
		t.Fatalf("old-boot rotation pair rejected: %v", err)
	}
	zeroCompanionSequence := oldBootTransition
	zeroCompanionSequence.SourceSequence = 1
	zeroCompanionSequence.PreviousSourceSequence = 0
	zeroCompanionSequence.RotationCompanionSourceSequence = task6APointer(
		uint64(0),
	)
	if err := zeroCompanionSequence.Validate(); err == nil {
		t.Fatal("zero rotation companion source sequence was accepted")
	}
	sameEventPair := newBootTransition
	sameEventPair.RotationCompanionEventID = task6APointer(
		sameEventPair.EventID,
	)
	if err := sameEventPair.Validate(); err == nil {
		t.Fatal("boundary and rotation companion reused one event ID")
	}

	partial := newBootTransition
	partial.RotationCompanionContentSHA256 = nil
	if err := partial.Validate(); err == nil {
		t.Fatal("partial rotation companion was accepted")
	}
	nonAdjacent := newBootTransition
	nonAdjacent.RotationCompanionSourceSequence = task6APointer(uint64(102))
	if err := nonAdjacent.Validate(); err == nil {
		t.Fatal("non-adjacent rotation companion was accepted")
	}
	sameBoot := dedicated
	sameBoot.BootID = sameBoot.PreviousBootID
	if err := sameBoot.Validate(); err == nil {
		t.Fatal("same-boot hop was accepted")
	}

	next := dedicated
	next.EventID = "evt_" + strings.Repeat("8", 64)
	next.ContentSHA256 = strings.Repeat("9", 64)
	next.PreviousBootID = dedicated.BootID
	next.PreviousSourceSequence = 150
	next.SourceSequence = 160
	next.BootID = "323e4567-e89b-42d3-a456-426614174002"
	if _, err := PCCBootTransitionChainSHA256(
		[]PCCBootTransitionHopV1{dedicated, next},
	); err != nil {
		t.Fatalf("valid multi-hop chain rejected: %v", err)
	}
	duplicateBoundary := next
	duplicateBoundary.EventID = dedicated.EventID
	if _, err := PCCBootTransitionChainSHA256(
		[]PCCBootTransitionHopV1{dedicated, duplicateBoundary},
	); err == nil {
		t.Fatal("duplicate boundary event ID across hops was hashed")
	}
	duplicateCompanion := next
	duplicateCompanion.BoundaryEventType = "observer_key_transition"
	duplicateCompanion.RotationCompanionEventType = task6APointer(
		"observer_key_epoch_start",
	)
	duplicateCompanion.RotationCompanionEventID = task6APointer(
		dedicated.EventID,
	)
	duplicateCompanion.RotationCompanionContentSHA256 = task6APointer(
		strings.Repeat("7", 64),
	)
	duplicateCompanion.RotationCompanionSourceSequence = task6APointer(
		duplicateCompanion.SourceSequence + 1,
	)
	duplicateCompanion.RotationCompanionBootID = task6APointer(
		duplicateCompanion.BootID,
	)
	if _, err := PCCBootTransitionChainSHA256(
		[]PCCBootTransitionHopV1{dedicated, duplicateCompanion},
	); err == nil {
		t.Fatal("duplicate companion event ID across hops was hashed")
	}
	repeatedBoot := next
	repeatedBoot.BootID = dedicated.PreviousBootID
	if _, err := PCCBootTransitionChainSHA256(
		[]PCCBootTransitionHopV1{dedicated, repeatedBoot},
	); err == nil {
		t.Fatal("repeated boot ID in transition chain was hashed")
	}

	disconnected := dedicated
	disconnected.PreviousBootID = "323e4567-e89b-42d3-a456-426614174003"
	disconnected.PreviousSourceSequence = 50
	disconnected.SourceSequence = 51
	if _, err := PCCBootTransitionChainSHA256(
		[]PCCBootTransitionHopV1{dedicated, disconnected},
	); err == nil {
		t.Fatal("disconnected transition chain was hashed")
	}
	if _, err := PCCBootTransitionChainSHA256(
		make([]PCCBootTransitionHopV1, 1025),
	); err == nil {
		t.Fatal("transition chain above 1,024 hops was hashed")
	}
}

func TestTask6ASnapshotCompleteAndFailedFormsAreExclusive(t *testing.T) {
	complete := task6ACompleteSnapshot()
	if err := task6ADecode(t, complete); err != nil {
		t.Fatal(err)
	}
	oversized := complete
	capAdd := make([]string, 128)
	capDrop := make([]string, 128)
	repoDigests := make([]string, 16)
	for index := range capAdd {
		capAdd[index] = fmt.Sprintf(
			"CAP_%03d_%s",
			index,
			strings.Repeat("X", 56),
		)
		capDrop[index] = fmt.Sprintf(
			"DROP_%03d_%s",
			index,
			strings.Repeat("Y", 55),
		)
	}
	for index := range repoDigests {
		repoDigests[index] = fmt.Sprintf(
			"registry-%02d.invalid/%s@sha256:%064x",
			index,
			strings.Repeat("z", 150),
			index,
		)
	}
	oversized.ConfiguredCapAdd = task6APointer(capAdd)
	oversized.ConfiguredCapDrop = task6APointer(capDrop)
	oversized.RepoDigests = task6APointer(repoDigests)
	oversized.Trigger.RepoDigests = append([]string{}, repoDigests...)
	canonicalOversized, err := CanonicalJSON(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonicalOversized) <= 24*1024 {
		t.Fatalf("oversize fixture is only %d bytes", len(canonicalOversized))
	}
	if err := oversized.Validate(); err == nil {
		t.Fatal("complete normalized snapshot above 24 KiB was accepted")
	}

	failed := task6AFailedSnapshot("inventory_stale")
	if err := task6ADecode(t, failed); err != nil {
		t.Fatal(err)
	}
	crossBoot := task6AFailedSnapshot("observer_boot_changed")
	crossBoot.BootTransitionHopCount = task6APointer(uint64(1))
	crossBoot.BootTransitionChainSHA256 = task6APointer(
		"84d7b640b5b0fa842ce99f646658832bbf538d663052eb4183d5402a7b83585c",
	)
	if err := task6ADecode(t, crossBoot); err != nil {
		t.Fatal(err)
	}
	nonblocking := complete
	nonblocking.Trigger.EvtRawres = nil
	nonblocking.Trigger.EvtRes = "EINPROGRESS"
	if err := task6ADecode(t, nonblocking); err != nil {
		t.Fatalf("absent nested evt_rawres was rejected: %v", err)
	}

	tests := map[string]PCCCorrelationSnapshotV1{
		"complete-with-failure": func() PCCCorrelationSnapshotV1 {
			value := complete
			value.FailureReasons = task6APointer([]string{"inventory_stale"})
			return value
		}(),
		"complete-missing-array": func() PCCCorrelationSnapshotV1 {
			value := complete
			value.OperatorDeniedNetworks = nil
			return value
		}(),
		"complete-wrong-management-hash": func() PCCCorrelationSnapshotV1 {
			value := complete
			value.ManagementDenylistSHA256 = task6APointer(strings.Repeat("0", 64))
			return value
		}(),
		"complete-wrong-network-hash": func() PCCCorrelationSnapshotV1 {
			value := complete
			value.DockerNetworkSnapshotSHA256 = task6APointer(strings.Repeat("0", 64))
			return value
		}(),
		"complete-wrong-special-use-pin": func() PCCCorrelationSnapshotV1 {
			value := complete
			value.SpecialUseRegistrySHA256 = task6APointer(strings.Repeat("0", 64))
			return value
		}(),
		"complete-identity-conflict": func() PCCCorrelationSnapshotV1 {
			value := complete
			value.InventoryRevision = task6APointer(uint64(4))
			return value
		}(),
		"complete-submicrosecond-decision": func() PCCCorrelationSnapshotV1 {
			value := complete
			value.DecisionTime = "2026-07-29T12:00:01.1234567Z"
			return value
		}(),
		"failed-with-complete-field": func() PCCCorrelationSnapshotV1 {
			value := failed
			value.DetectorBundleSHA256 = task6APointer(strings.Repeat("0", 64))
			return value
		}(),
		"failed-empty-reasons": func() PCCCorrelationSnapshotV1 {
			value := failed
			value.FailureReasons = task6APointer([]string{})
			return value
		}(),
		"ordinary-failed-with-chain": func() PCCCorrelationSnapshotV1 {
			value := failed
			value.BootTransitionHopCount = task6APointer(uint64(1))
			value.BootTransitionChainSHA256 = task6APointer(strings.Repeat("0", 64))
			return value
		}(),
		"cross-boot-missing-chain": func() PCCCorrelationSnapshotV1 {
			value := crossBoot
			value.BootTransitionChainSHA256 = nil
			return value
		}(),
		"cross-boot-mixed-reasons": func() PCCCorrelationSnapshotV1 {
			value := crossBoot
			value.FailureReasons = task6APointer([]string{
				"inventory_stale",
				"observer_boot_changed",
			})
			return value
		}(),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if err := value.Validate(); err == nil {
				t.Fatal("invalid snapshot outcome was accepted")
			}
		})
	}

	raw := task6AMutateJSON(t, complete, func(document map[string]any) {
		document["failure_reasons"] = nil
	})
	if _, err := DecodeStrict[PCCCorrelationSnapshotV1](
		bytes.NewReader(raw),
		32*1024,
	); err == nil {
		t.Fatal("null failed-only field was accepted in complete form")
	}
	raw = task6AMutateJSON(t, complete, func(document map[string]any) {
		delete(document, "configured_cap_add")
	})
	if _, err := DecodeStrict[PCCCorrelationSnapshotV1](
		bytes.NewReader(raw),
		32*1024,
	); err == nil {
		t.Fatal("omitted empty complete-only array was accepted")
	}
	raw = task6AMutateJSON(t, failed, func(document map[string]any) {
		document["docker_networks"] = []any{}
	})
	if _, err := DecodeStrict[PCCCorrelationSnapshotV1](
		bytes.NewReader(raw),
		32*1024,
	); err == nil {
		t.Fatal("present complete-only field was accepted in failed form")
	}
	raw = task6AMutateJSON(t, nonblocking, func(document map[string]any) {
		trigger, ok := document["trigger"].(map[string]any)
		if !ok {
			t.Fatal("encoded trigger is not an object")
		}
		trigger["evt_rawres"] = nil
	})
	if _, err := DecodeStrict[PCCCorrelationSnapshotV1](
		bytes.NewReader(raw),
		32*1024,
	); err == nil {
		t.Fatal("nested null evt_rawres was accepted as absent")
	}
	raw = task6AMutateJSON(t, complete, func(document map[string]any) {
		document["model_output"] = "BLOCK EVERYTHING"
	})
	if _, err := DecodeStrict[PCCCorrelationSnapshotV1](
		bytes.NewReader(raw),
		32*1024,
	); err == nil {
		t.Fatal("unknown snapshot authority field was accepted")
	}
}
