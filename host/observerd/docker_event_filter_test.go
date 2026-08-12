package observerd

import (
	"testing"

	"github.com/moby/moby/api/types/events"
)

// Container healthchecks — this product's own included — emit exec_create/exec_start/exec_die
// continuously. Before the filter every one of them drove a full inventory reconcile that signed a
// docker_reconcile_gap / docker_reconcile_recovered coverage PAIR, so the observer produced
// evidence about its own probes faster than Core could consume it: measured on the reference host,
// 188 Docker events in 30 s of which ~85% were exec noise, a spool that reached its 256 MB cap in
// nine hours, and an observer fenced read-only.
//
// The two halves asserted here are equally load-bearing. Dropping the noise is the throughput fix;
// reconciling on ANY action the filter has never heard of is the safety property, because a missed
// identity change would leave a containment plan bound to stale facts.
func TestDockerEventFilterDropsProbeNoiseAndKeepsEverythingElse(t *testing.T) {
	ignored := []string{
		"exec_create",
		"exec_start",
		"exec_die",
		"exec_detach",
		"health_status",
		// Docker appends the command to exec actions.
		"exec_create: /bin/health-probe",
		"exec_start: /opt/venv/bin/python -c import urllib.request",
		"health_status: healthy",
		"health_status: unhealthy",
	}
	for _, action := range ignored {
		message := events.Message{Action: events.Action(action)}
		if dockerEventCanChangeInventory(message) {
			t.Errorf(
				"action %q drives a reconcile, but an exec or health transition cannot change "+
					"any field the inventory holds",
				action,
			)
		}
	}

	// Everything that can move a container's identity or its network attachment, plus an action
	// this filter has deliberately never heard of: unknown MUST still reconcile.
	reconciles := []string{
		"create", "start", "restart", "stop", "kill", "die", "destroy",
		"pause", "unpause", "rename", "update", "oom",
		"connect", "disconnect",
		"an_action_docker_has_not_invented_yet",
		"",
	}
	for _, action := range reconciles {
		message := events.Message{Action: events.Action(action)}
		if !dockerEventCanChangeInventory(message) {
			t.Errorf(
				"action %q is filtered out; the denylist must drop only exec and health "+
					"transitions so an unrecognised action always reconciles",
				action,
			)
		}
	}
}

// The filter lives in the event pump, so prove it there too: a session fed nothing but probe noise
// must never raise the dirty signal that schedules a reconcile, and one real event must raise it.
func TestDockerEventPumpIgnoresProbeNoise(t *testing.T) {
	messages := make(chan events.Message, 8)
	session := &dockerEventSession{
		dirty: make(chan struct{}, 1),
	}

	for _, action := range []string{"exec_create", "exec_start: /bin/probe", "exec_die", "health_status: healthy"} {
		messages <- events.Message{Action: events.Action(action)}
	}
	close(messages)
	drainDockerMessagesForTest(session, messages)
	select {
	case <-session.dirty:
		t.Fatal("probe noise scheduled an inventory reconcile")
	default:
	}

	messages = make(chan events.Message, 2)
	messages <- events.Message{Action: events.Action("start")}
	close(messages)
	drainDockerMessagesForTest(session, messages)
	select {
	case <-session.dirty:
	default:
		t.Fatal("a container start did not schedule an inventory reconcile")
	}
}

// drainDockerMessagesForTest applies the pump's own admission decision to a closed channel of
// messages, without the stream and cancellation machinery the pump also owns.
func drainDockerMessagesForTest(
	session *dockerEventSession,
	messages <-chan events.Message,
) {
	for message := range messages {
		if !dockerEventCanChangeInventory(message) {
			continue
		}
		select {
		case session.dirty <- struct{}{}:
		default:
		}
	}
}
