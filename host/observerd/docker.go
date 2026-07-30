package observerd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

const dockerSocketHost = "unix:///var/run/docker.sock"

var (
	ErrDockerEventSubscription = errors.New(
		"Docker event subscription unavailable",
	)
	versionedDockerEventsPath = regexp.MustCompile(
		`^/v[0-9]+\.[0-9]+/events$`,
	)
)

// DockerEventStream is the narrow event capability returned across the
// DockerReader boundary. It intentionally does not expose a Moby result or
// client, and observerd ignores all event payload content.
type DockerEventStream struct {
	Messages <-chan events.Message
	Err      <-chan error
}

// DockerReader is the complete Docker boundary available to observerd. It has
// no mutation, exec, copy, archive, logs, or generic request surface.
type DockerReader interface {
	ContainerList(
		context.Context,
		client.ContainerListOptions,
	) (client.ContainerListResult, error)
	ContainerInspect(
		context.Context,
		string,
		client.ContainerInspectOptions,
	) (client.ContainerInspectResult, error)
	ImageInspect(
		context.Context,
		string,
		...client.ImageInspectOption,
	) (client.ImageInspectResult, error)
	NetworkInspect(
		context.Context,
		string,
		client.NetworkInspectOptions,
	) (client.NetworkInspectResult, error)
	NetworkList(
		context.Context,
		client.NetworkListOptions,
	) (client.NetworkListResult, error)
	Events(
		context.Context,
		client.EventsListOptions,
	) (DockerEventStream, error)
}

type mobyDockerReader struct {
	client *client.Client
}

type mobyDockerCloser struct {
	client *client.Client
}

type mobyEventReadyContextKey struct{}

type mobyEventReadyToken struct {
	ready chan struct{}
	once  sync.Once
}

func newMobyEventReadyContext(
	ctx context.Context,
) (context.Context, *mobyEventReadyToken) {
	token := &mobyEventReadyToken{ready: make(chan struct{})}
	return context.WithValue(
		ctx,
		mobyEventReadyContextKey{},
		token,
	), token
}

func (token *mobyEventReadyToken) signal() {
	if token == nil {
		return
	}
	token.once.Do(func() { close(token.ready) })
}

func mobyEventResponseHook(response *http.Response) {
	if response == nil ||
		response.StatusCode != http.StatusOK ||
		response.Request == nil ||
		response.Request.Method != http.MethodGet ||
		response.Request.URL == nil {
		return
	}
	path := response.Request.URL.Path
	if path != "/events" && !versionedDockerEventsPath.MatchString(path) {
		return
	}
	token, ok := response.Request.Context().Value(
		mobyEventReadyContextKey{},
	).(*mobyEventReadyToken)
	if ok {
		token.signal()
	}
}

func normalizeDockerEventStreamError(err error, open bool) error {
	if !open || err == nil {
		return io.EOF
	}
	return err
}

func replayDockerEventFailure(
	messages <-chan events.Message,
	err error,
) DockerEventStream {
	replayed := make(chan error, 1)
	replayed <- err
	close(replayed)
	return DockerEventStream{Messages: messages, Err: replayed}
}

func awaitMobyEventHandshake(
	ctx context.Context,
	token *mobyEventReadyToken,
	result client.EventsResult,
) (DockerEventStream, error) {
	if token == nil || result.Messages == nil || result.Err == nil {
		err := fmt.Errorf(
			"%w: invalid Moby event channels",
			ErrDockerEventSubscription,
		)
		return replayDockerEventFailure(result.Messages, err), err
	}
	stream := DockerEventStream{
		Messages: result.Messages,
		Err:      result.Err,
	}
	select {
	case <-token.ready:
		return stream, nil
	default:
	}
	select {
	case <-token.ready:
		return stream, nil
	case streamErr, open := <-result.Err:
		streamErr = normalizeDockerEventStreamError(streamErr, open)
		err := errors.Join(ErrDockerEventSubscription, streamErr)
		return replayDockerEventFailure(result.Messages, streamErr), err
	case <-ctx.Done():
		err := errors.Join(ErrDockerEventSubscription, ctx.Err())
		return replayDockerEventFailure(result.Messages, ctx.Err()), err
	}
}

func newMobyDockerReader() (DockerReader, io.Closer, error) {
	dockerClient, err := client.New(
		client.WithHost(dockerSocketHost),
		client.WithAPIVersionNegotiation(),
		client.WithResponseHook(mobyEventResponseHook),
	)
	if err != nil {
		return nil, nil, err
	}
	reader := &mobyDockerReader{client: dockerClient}
	return reader, &mobyDockerCloser{client: dockerClient}, nil
}

func (closer *mobyDockerCloser) Close() error {
	return closer.client.Close()
}

func (reader *mobyDockerReader) ContainerList(
	ctx context.Context,
	options client.ContainerListOptions,
) (client.ContainerListResult, error) {
	return reader.client.ContainerList(ctx, options)
}

func (reader *mobyDockerReader) ContainerInspect(
	ctx context.Context,
	fullID string,
	options client.ContainerInspectOptions,
) (client.ContainerInspectResult, error) {
	return reader.client.ContainerInspect(ctx, fullID, options)
}

func (reader *mobyDockerReader) ImageInspect(
	ctx context.Context,
	imageID string,
	options ...client.ImageInspectOption,
) (client.ImageInspectResult, error) {
	return reader.client.ImageInspect(ctx, imageID, options...)
}

func (reader *mobyDockerReader) NetworkInspect(
	ctx context.Context,
	networkID string,
	options client.NetworkInspectOptions,
) (client.NetworkInspectResult, error) {
	return reader.client.NetworkInspect(ctx, networkID, options)
}

func (reader *mobyDockerReader) NetworkList(
	ctx context.Context,
	options client.NetworkListOptions,
) (client.NetworkListResult, error) {
	return reader.client.NetworkList(ctx, options)
}

func (reader *mobyDockerReader) Events(
	ctx context.Context,
	options client.EventsListOptions,
) (DockerEventStream, error) {
	eventContext, token := newMobyEventReadyContext(ctx)
	return awaitMobyEventHandshake(
		ctx,
		token,
		reader.client.Events(eventContext, options),
	)
}
