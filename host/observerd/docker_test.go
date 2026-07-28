package observerd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

func TestMobyDockerCloserCannotEscapeMutationCapableClient(t *testing.T) {
	reader, closer, err := newMobyDockerReader()
	if err != nil {
		t.Fatal(err)
	}
	if reader == nil || closer == nil {
		t.Fatal("Moby Docker boundary returned nil capability")
	}
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Errorf("close Moby client: %v", err)
		}
	})
	if _, escaped := closer.(*client.Client); escaped {
		t.Fatal("io.Closer escaped the mutation-capable Moby client")
	}
	closerType := reflect.TypeOf(closer)
	if closerType.NumMethod() != 1 ||
		closerType.Method(0).Name != "Close" {
		t.Fatalf(
			"closer dynamic type exposes methods beyond Close: %v",
			closerType,
		)
	}
}

func TestMobyEventResponseHookSignalsOnlyExactGET200Events(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		method string
		path   string
		status int
		ready  bool
	}{
		{
			name:   "unversioned events",
			method: http.MethodGet,
			path:   "/events",
			status: http.StatusOK,
			ready:  true,
		},
		{
			name:   "versioned events",
			method: http.MethodGet,
			path:   "/v1.55/events",
			status: http.StatusOK,
			ready:  true,
		},
		{
			name:   "wrong method",
			method: http.MethodPost,
			path:   "/v1.55/events",
			status: http.StatusOK,
		},
		{
			name:   "wrong path",
			method: http.MethodGet,
			path:   "/v1.55/containers/json",
			status: http.StatusOK,
		},
		{
			name:   "path suffix",
			method: http.MethodGet,
			path:   "/v1.55/events/extra",
			status: http.StatusOK,
		},
		{
			name:   "non-200",
			method: http.MethodGet,
			path:   "/v1.55/events",
			status: http.StatusNoContent,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, token := newMobyEventReadyContext(context.Background())
			request := httptest.NewRequest(
				testCase.method,
				"http://docker.invalid"+testCase.path,
				nil,
			).WithContext(ctx)
			mobyEventResponseHook(&http.Response{
				StatusCode: testCase.status,
				Request:    request,
			})
			select {
			case <-token.ready:
				if !testCase.ready {
					t.Fatal("non-events response signaled readiness")
				}
			default:
				if testCase.ready {
					t.Fatal("exact events response did not signal readiness")
				}
			}
		})
	}
}

func TestMobyEventHandshakeDeterministicallyReplaysFailure(t *testing.T) {
	ctx, token := newMobyEventReadyContext(context.Background())
	messages := make(chan events.Message)
	eventErrors := make(chan error, 1)
	injected := errors.New("injected Moby events GET failure")
	eventErrors <- injected
	close(eventErrors)
	stream, err := awaitMobyEventHandshake(
		ctx,
		token,
		client.EventsResult{Messages: messages, Err: eventErrors},
	)
	if !errors.Is(err, injected) {
		t.Fatalf("handshake error=%v", err)
	}
	select {
	case replayed, open := <-stream.Err:
		if !open || !errors.Is(replayed, injected) {
			t.Fatalf("replayed error=%v open=%v", replayed, open)
		}
	default:
		t.Fatal("consumed Moby failure was not ready in returned stream")
	}
}

func TestMobyEventHandshakeAcceptsOnlyPositiveHookToken(t *testing.T) {
	ctx, token := newMobyEventReadyContext(context.Background())
	token.signal()
	messages := make(chan events.Message)
	eventErrors := make(chan error)
	stream, err := awaitMobyEventHandshake(
		ctx,
		token,
		client.EventsResult{Messages: messages, Err: eventErrors},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stream.Messages == nil || stream.Err == nil {
		t.Fatal("positive handshake returned invalid narrow stream")
	}
}

func TestMobyEventHandshakeThroughRealClientTransport(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "exact 200 response establishes readiness",
			statusCode: http.StatusOK,
		},
		{
			name:       "500 response rejects subscription setup",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(
				func(response http.ResponseWriter, request *http.Request) {
					if request.Method != http.MethodGet ||
						(request.URL.Path != "/events" &&
							!versionedDockerEventsPath.MatchString(
								request.URL.Path,
							)) {
						http.NotFound(response, request)
						return
					}
					response.Header().Set(
						"Content-Type",
						"application/json",
					)
					response.WriteHeader(testCase.statusCode)
					if flusher, ok := response.(http.Flusher); ok {
						flusher.Flush()
					}
					if testCase.statusCode == http.StatusOK {
						<-request.Context().Done()
					}
				},
			))
			t.Cleanup(server.Close)

			dockerClient, err := client.New(
				client.WithHost(server.URL),
				client.WithResponseHook(mobyEventResponseHook),
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := dockerClient.Close(); err != nil {
					t.Errorf("close Moby client: %v", err)
				}
			})

			ctx, cancel := context.WithTimeout(
				context.Background(),
				2*time.Second,
			)
			defer cancel()
			stream, err := (&mobyDockerReader{
				client: dockerClient,
			}).Events(ctx, client.EventsListOptions{})
			if testCase.wantErr {
				if !errors.Is(err, ErrDockerEventSubscription) {
					t.Fatalf("subscription error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if stream.Messages == nil || stream.Err == nil {
				t.Fatal("ready transport returned invalid narrow stream")
			}
			cancel()
		})
	}
}
