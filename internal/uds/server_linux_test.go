//go:build linux

package uds_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"agmind.local/sais/internal/uds"
)

func unixClient(path string) *http.Client {
	transport := &http.Transport{
		DialContext: func(
			ctx context.Context,
			network string,
			address string,
		) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", path)
		},
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func startServer(t *testing.T, path string, handler http.Handler) *uds.HTTPServer {
	t.Helper()
	server, err := uds.ListenHTTP(path, 0o660, os.Getegid(), 64, handler)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve did not stop")
		}
	})
	return server
}

func TestListenHTTPAttachesRealLinuxPeerCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "socket")
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		peer, ok := uds.PeerFromContext(request.Context())
		if !ok {
			http.Error(writer, "missing", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(
			writer,
			`{"pid":`+strconv.FormatInt(int64(peer.PID), 10)+
				`,"uid":`+strconv.FormatUint(uint64(peer.UID), 10)+
				`,"gid":`+strconv.FormatUint(uint64(peer.GID), 10)+`}`,
		)
	})
	startServer(t, path, handler)
	response, err := unixClient(path).Post(
		"http://unix/test",
		"application/json; charset=utf-8",
		strings.NewReader(`{"ok":true}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`"pid":` + strconv.Itoa(os.Getpid()),
		`"uid":` + strconv.Itoa(os.Geteuid()),
		`"gid":` + strconv.Itoa(os.Getegid()),
	} {
		if !strings.Contains(string(raw), fragment) {
			t.Fatalf("response %q missing %q", raw, fragment)
		}
	}
	parentInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if parentInfo.Mode().Perm() != 0o750 {
		t.Fatalf("parent mode=%#o", parentInfo.Mode().Perm())
	}
	socketInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if socketInfo.Mode().Perm() != 0o660 || socketInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode=%v", socketInfo.Mode())
	}
}

func TestListenHTTPRejectsUnsafeModeAndSymlinkPath(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	path := filepath.Join(t.TempDir(), "run", "socket")
	if _, err := uds.ListenHTTP(path, 0o666, os.Getegid(), 64, handler); !errors.Is(
		err,
		uds.ErrUnsafeSocket,
	) {
		t.Fatalf("mode got %v", err)
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := uds.ListenHTTP(
		filepath.Join(link, "socket"),
		0o600,
		os.Getegid(),
		64,
		handler,
	); !errors.Is(err, uds.ErrUnsafeSocket) {
		t.Fatalf("symlink got %v", err)
	}
}

func TestSecondListenerDoesNotUnlinkActiveSamePathSocket(t *testing.T) {
	var calls atomic.Int64
	path := filepath.Join(t.TempDir(), "run", "socket")
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{}`)
	})
	startServer(t, path, handler)
	if _, err := uds.ListenHTTP(
		path,
		0o660,
		os.Getegid(),
		64,
		handler,
	); !errors.Is(err, uds.ErrSocketInUse) {
		t.Fatalf("got %v, want ErrSocketInUse", err)
	}
	response, err := unixClient(path).Post(
		"http://unix/test",
		"application/json",
		strings.NewReader(`{}`),
	)
	if err != nil {
		t.Fatalf("first listener no longer reachable: %v", err)
	}
	_ = response.Body.Close()
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestHTTPMiddlewareEnforcesMediaTypeAndBodyLimitWithSafeErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "socket")
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("handler read: %v", err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(raw)
	})
	startServer(t, path, handler)
	client := unixClient(path)
	for name, testCase := range map[string]struct {
		contentType     string
		contentEncoding string
		body            string
		status          int
		reason          string
	}{
		"wrong content type": {
			"text/plain", "", `{}`, 415, "unsupported_media_type",
		},
		"non-utf8 charset": {
			"application/json; charset=iso-8859-1",
			"",
			`{}`,
			415,
			"unsupported_media_type",
		},
		"content encoding": {
			"application/json",
			"gzip",
			`{}`,
			415,
			"unsupported_content_encoding",
		},
		"oversize": {
			"application/json",
			"",
			strings.Repeat("x", 65),
			413,
			"body_too_large",
		},
	} {
		t.Run(name, func(t *testing.T) {
			request, err := http.NewRequest(
				http.MethodPost,
				"http://unix/private/path-canary",
				strings.NewReader(testCase.body),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", testCase.contentType)
			if testCase.contentEncoding != "" {
				request.Header.Set("Content-Encoding", testCase.contentEncoding)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != testCase.status ||
				!strings.Contains(string(raw), testCase.reason) {
				t.Fatalf("status=%d body=%q", response.StatusCode, raw)
			}
			if strings.Contains(string(raw), "private/path-canary") ||
				strings.Contains(string(raw), path) {
				t.Fatalf("error leaked path: %q", raw)
			}
		})
	}
}

func TestRouteAuthorizationUsesRecordedPeerCredentials(t *testing.T) {
	for name, testCase := range map[string]struct {
		authorize func(uds.Peer) bool
		status    int
	}{
		"allow exact uid": {
			authorize: func(peer uds.Peer) bool {
				return peer.UID == uint32(os.Geteuid())
			},
			status: http.StatusNoContent,
		},
		"deny route": {
			authorize: func(peer uds.Peer) bool {
				return peer.UID == ^uint32(0)
			},
			status: http.StatusForbidden,
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "run", "socket")
			handler := uds.RequirePeer(testCase.authorize)(http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					writer.WriteHeader(http.StatusNoContent)
				},
			))
			startServer(t, path, handler)
			response, err := unixClient(path).Post(
				"http://unix/test",
				"application/json",
				strings.NewReader(`{}`),
			)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != testCase.status {
				t.Fatalf("status=%d want=%d", response.StatusCode, testCase.status)
			}
		})
	}
}

func TestPeerInGroupReadsVerifiedCurrentProcStatus(t *testing.T) {
	member, err := uds.PeerInGroup(
		uds.Peer{
			PID: int32(os.Getpid()),
			UID: uint32(os.Geteuid()),
			GID: uint32(os.Getegid()),
		},
		uint32(os.Getegid()),
	)
	if err != nil || !member {
		t.Fatalf("current primary group member=%v err=%v", member, err)
	}
}
