package observerd

import (
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

// When the daemon refuses to start, its journal line is the only thing an operator has. It used to
// read "observer runtime dependencies unavailable" for ten different missing dependencies, so it
// identified nothing and diagnosis meant reading this source. Every refusal must name its cause,
// and a complete set must refuse nothing.
func TestRuntimeRefusalNamesTheMissingDependency(t *testing.T) {
	complete := func() observerRuntimeOptions {
		return observerRuntimeOptions{
			openDocker: func() (DockerReader, io.Closer, error) { return nil, nil, nil },
			processes:  stubProcessReader{},
			groupID:    func(string) (uint32, error) { return 0, nil },
			userID:     func(string) (uint32, error) { return 0, nil },
			listen: func(
				string,
				os.FileMode,
				int,
				int64,
				http.Handler,
			) (observerRuntimeServer, error) {
				return nil, nil
			},
			now: time.Now,
		}
	}
	// A daemon whose own three dependencies are present, so the option-level checks are reachable.
	wired := &Daemon{state: &StateStore{}, spool: &Spool{}, signer: &EnvelopeSigner{}}

	if missing := missingObserverRuntimeDependency(wired, complete()); missing != "" {
		t.Fatalf("a complete dependency set was refused for %q", missing)
	}

	for _, testCase := range []struct {
		expect string
		blank  func(*observerRuntimeOptions)
	}{
		{"Docker reader", func(o *observerRuntimeOptions) { o.openDocker = nil }},
		{"process table reader", func(o *observerRuntimeOptions) { o.processes = nil }},
		{"group resolver", func(o *observerRuntimeOptions) { o.groupID = nil }},
		{"user resolver", func(o *observerRuntimeOptions) { o.userID = nil }},
		{"socket listener", func(o *observerRuntimeOptions) { o.listen = nil }},
		{"clock", func(o *observerRuntimeOptions) { o.now = nil }},
	} {
		options := complete()
		testCase.blank(&options)
		if missing := missingObserverRuntimeDependency(wired, options); missing != testCase.expect {
			t.Errorf("refusal named %q, want %q", missing, testCase.expect)
		}
	}

	for _, testCase := range []struct {
		expect string
		daemon *Daemon
	}{
		{"daemon", nil},
		{"durable state", &Daemon{}},
		{"evidence spool", &Daemon{state: &StateStore{}}},
		{"event signer", &Daemon{state: &StateStore{}, spool: &Spool{}}},
	} {
		if missing := missingObserverRuntimeDependency(testCase.daemon, complete()); missing != testCase.expect {
			t.Errorf("refusal named %q, want %q", missing, testCase.expect)
		}
	}
}

// stubProcessReader satisfies processIdentityReader without touching /proc.
type stubProcessReader struct{}

func (stubProcessReader) ReadProcessIdentity(string, int) (processIdentity, error) {
	return processIdentity{}, nil
}
