//go:build linux

package observerd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"agmind.local/sais/internal/uds"
)

const coreAPIRouteChildSocket = "AGMIND_CORE_API_ROUTE_CHILD_SOCKET"

func TestCoreAPIRouteGroupOnlyChild(t *testing.T) {
	path := os.Getenv(coreAPIRouteChildSocket)
	if path == "" {
		t.Skip("route child only")
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(
				ctx context.Context,
				network string,
				address string,
			) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
		Timeout: 2 * time.Second,
	}
	getResponse, err := client.Get("http://unix/v1/events?after=0&limit=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = getResponse.Body.Close()
	ackResponse, err := client.Post(
		"http://unix/v1/events/ack",
		"application/json",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = ackResponse.Body.Close()
	if getResponse.StatusCode != http.StatusOK ||
		ackResponse.StatusCode != http.StatusForbidden {
		t.Fatalf(
			"group-only route status GET=%d ACK=%d",
			getResponse.StatusCode,
			ackResponse.StatusCode,
		)
	}
}

func TestCoreAPIRoutesAllowGroupGETButForbidGroupOnlyACK(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential-switch route test requires root")
	}
	service, _, _, _, _ := observerServiceFixture(t)
	directory, err := os.MkdirTemp("", "agmind-core-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chown(directory, 0, 2002); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(directory, "observerd-route.test")
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, binary, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(executable, 0, 2002); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "socket")
	server, err := uds.ListenHTTP(
		path,
		0o660,
		2002,
		65_536,
		newCoreAPI(service, 2002, 1002),
	)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case serveErr := <-serveDone:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				t.Errorf("Serve: %v", serveErr)
			}
		case <-time.After(time.Second):
			t.Error("route server did not stop")
		}
	})
	command := exec.Command(
		executable,
		"-test.run=^TestCoreAPIRouteGroupOnlyChild$",
		"-test.count=1",
	)
	command.Env = append(
		os.Environ(),
		coreAPIRouteChildSocket+"="+path,
	)
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 1003,
			Gid: 2002,
		},
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("group-only route child: %v\n%s", err, output)
	}
}
