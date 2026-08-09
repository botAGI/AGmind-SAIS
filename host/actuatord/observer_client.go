package actuatord

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"agmind.local/sais/host/observerd"
	"agmind.local/sais/internal/contracts"
)

const (
	observerRequestTimeout       = 2 * time.Second
	observerResponseMaxBytes     = int64(64 * 1024)
	observerErrorDrainMaxBytes   = int64(4 * 1024)
	observerResponseContentType  = "application/json"
	observerSyntheticRequestHost = "http://unix"
)

// ObserverClient is the actuator's narrow, read-only client for observerd's
// root-only private Unix-socket API.
type ObserverClient struct {
	client    *http.Client
	transport *http.Transport
}

// NewObserverClient creates a fixed Unix-socket HTTP/1.1 client. It never
// consults proxy configuration and never follows redirects or keeps a
// connection alive across requests.
func NewObserverClient(socketPath string) (*ObserverClient, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) ||
		filepath.Clean(socketPath) != socketPath ||
		strings.IndexByte(socketPath, 0) >= 0 {
		return nil, fmt.Errorf("invalid observer Unix socket path")
	}
	dialer := &net.Dialer{Timeout: observerRequestTimeout}
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: -1,
		DialContext: func(
			ctx context.Context,
			_, _ string,
		) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &ObserverClient{
		transport: transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   observerRequestTimeout,
			CheckRedirect: func(
				*http.Request,
				[]*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func validObserverContainerID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for index := range value {
		character := value[index]
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

type observerStatusMapping struct {
	notFound       error
	notFoundReason string
	conflict       error
	conflictReason string
}

type observerErrorEnvelope struct {
	Error string `json:"error"`
}

func (envelope observerErrorEnvelope) Validate() error {
	switch envelope.Error {
	case "container_not_found", "shared_network_namespace":
		return nil
	default:
		return fmt.Errorf("invalid observer error reason")
	}
}

func observerStatusError(
	response *http.Response,
	operation string,
	mapping observerStatusMapping,
) error {
	raw, readErr := io.ReadAll(io.LimitReader(
		response.Body,
		observerErrorDrainMaxBytes+1,
	))
	var sentinel error
	var expectedReason string
	switch response.StatusCode {
	case http.StatusNotFound:
		sentinel = mapping.notFound
		expectedReason = mapping.notFoundReason
	case http.StatusConflict:
		sentinel = mapping.conflict
		expectedReason = mapping.conflictReason
	}
	if readErr == nil && int64(len(raw)) <= observerErrorDrainMaxBytes &&
		sentinel != nil && expectedReason != "" &&
		exactObserverContentType(response) == nil {
		envelope, decodeErr := contracts.DecodeStrict[observerErrorEnvelope](
			bytes.NewReader(raw),
			observerErrorDrainMaxBytes,
		)
		if decodeErr == nil && envelope.Error == expectedReason {
			return fmt.Errorf("observer %s: %w", operation, sentinel)
		}
	}
	return fmt.Errorf(
		"observer %s returned HTTP status %d",
		operation,
		response.StatusCode,
	)
}

func exactObserverContentType(response *http.Response) error {
	values := response.Header.Values("Content-Type")
	if len(values) != 1 || values[0] != observerResponseContentType ||
		response.Header.Get("Content-Encoding") != "" {
		return fmt.Errorf("observer returned an invalid JSON content type")
	}
	return nil
}

func doObserverRequest[T contracts.Contract](
	ctx context.Context,
	client *ObserverClient,
	method string,
	path string,
	payload []byte,
	operation string,
	mapping observerStatusMapping,
) (T, error) {
	var zero T
	if client == nil || client.client == nil {
		return zero, fmt.Errorf("observer client is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		method,
		observerSyntheticRequestHost+path,
		body,
	)
	if err != nil {
		return zero, fmt.Errorf("build observer %s request: %w", operation, err)
	}
	request.Close = true
	request.Header.Set("Accept", observerResponseContentType)
	if payload != nil {
		request.Header.Set("Content-Type", observerResponseContentType)
	}

	response, err := client.client.Do(request)
	if err != nil {
		return zero, fmt.Errorf("observer %s request failed: %w", operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return zero, observerStatusError(response, operation, mapping)
	}
	if err := exactObserverContentType(response); err != nil {
		return zero, err
	}
	raw, err := io.ReadAll(io.LimitReader(
		response.Body,
		observerResponseMaxBytes+1,
	))
	if err != nil {
		return zero, fmt.Errorf("read observer %s response: %w", operation, err)
	}
	if int64(len(raw)) > observerResponseMaxBytes {
		return zero, fmt.Errorf("observer %s response exceeds limit", operation)
	}
	decoded, err := contracts.DecodeStrict[T](
		bytes.NewReader(raw),
		observerResponseMaxBytes,
	)
	if err != nil {
		return zero, fmt.Errorf("decode observer %s response: %w", operation, err)
	}
	return decoded, nil
}

func (client *ObserverClient) Integrity(
	ctx context.Context,
) (observerd.ObserverIntegrityV1, error) {
	return doObserverRequest[observerd.ObserverIntegrityV1](
		ctx,
		client,
		http.MethodGet,
		"/v1/private/integrity",
		nil,
		"integrity",
		observerStatusMapping{},
	)
}

func (client *ObserverClient) LookupContainer(
	ctx context.Context,
	fullID string,
) (observerd.ContainerIdentityV1, error) {
	if !validObserverContainerID(fullID) {
		return observerd.ContainerIdentityV1{}, fmt.Errorf(
			"invalid observer container ID",
		)
	}
	identity, err := doObserverRequest[observerd.ContainerIdentityV1](
		ctx,
		client,
		http.MethodGet,
		"/v1/private/container/"+fullID,
		nil,
		"container lookup",
		observerStatusMapping{
			notFound:       observerd.ErrContainerNotFound,
			notFoundReason: "container_not_found",
		},
	)
	if err != nil {
		return observerd.ContainerIdentityV1{}, err
	}
	if identity.FullContainerID != fullID {
		return observerd.ContainerIdentityV1{}, fmt.Errorf(
			"observer returned a mismatched container identity",
		)
	}
	return identity, nil
}

func (client *ObserverClient) CheckNetNS(
	ctx context.Context,
	request observerd.NetNSUniquenessRequestV1,
) (observerd.NetNSUniquenessV1, error) {
	if err := request.Validate(); err != nil {
		return observerd.NetNSUniquenessV1{}, fmt.Errorf(
			"invalid observer namespace request: %w",
			err,
		)
	}
	payload, err := contracts.CanonicalJSON(request)
	if err != nil {
		return observerd.NetNSUniquenessV1{}, fmt.Errorf(
			"encode observer namespace request: %w",
			err,
		)
	}
	result, err := doObserverRequest[observerd.NetNSUniquenessV1](
		ctx,
		client,
		http.MethodPost,
		"/v1/private/netns-uniqueness",
		payload,
		"network namespace check",
		observerStatusMapping{
			notFound:       observerd.ErrContainerNotFound,
			notFoundReason: "container_not_found",
			conflict:       observerd.ErrSharedNetworkNamespace,
			conflictReason: "shared_network_namespace",
		},
	)
	if err != nil {
		return observerd.NetNSUniquenessV1{}, err
	}
	if result.FullContainerID != request.FullContainerID ||
		result.NetworkNamespaceInode != request.NetworkNamespaceInode {
		return observerd.NetNSUniquenessV1{}, fmt.Errorf(
			"observer returned a mismatched namespace result",
		)
	}
	return result, nil
}

// Close releases any transport resources. Requests are connection-close, so
// repeated Close calls are harmless.
func (client *ObserverClient) Close() error {
	if client != nil && client.transport != nil {
		client.transport.CloseIdleConnections()
	}
	return nil
}

var _ Observer = (*ObserverClient)(nil)
