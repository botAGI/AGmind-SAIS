// Package uds provides bounded HTTP/1.1 servers over owned Unix sockets.
package uds

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrUnsupportedPlatform = errors.New("unsupported platform")
	ErrUnsafeSocket        = errors.New("unsafe Unix socket")
	ErrSocketInUse         = errors.New("Unix socket already in use")
	ErrInvalidPeer         = errors.New("invalid Unix peer")
)

type Peer struct {
	PID                         int32
	UID                         uint32
	GID                         uint32
	supplementaryGroups         []uint32
	supplementaryGroupsCaptured bool
}

func (peer Peer) inSupplementaryGroup(group uint32) bool {
	if !peer.supplementaryGroupsCaptured {
		return false
	}
	for _, candidate := range peer.supplementaryGroups {
		if candidate == group {
			return true
		}
	}
	return false
}

type peerContextKey struct{}

func PeerFromContext(ctx context.Context) (Peer, bool) {
	peer, ok := ctx.Value(peerContextKey{}).(Peer)
	return peer, ok
}

// RequirePeer is a route-level authorization middleware. Socket permissions
// constrain who can connect; this check constrains which authenticated peer
// credentials may invoke a specific route.
func RequirePeer(authorize func(Peer) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			peer, ok := PeerFromContext(request.Context())
			if !ok || authorize == nil || !authorize(peer) {
				fixedError(writer, http.StatusForbidden, "peer_not_authorized")
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
}

// RequireRootOrGroup authorizes root or a primary GID from SO_PEERCRED, then
// checks the accept-time SO_PEERGROUPS snapshot for supplementary membership.
func RequireRootOrGroup(group uint32) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			peer, ok := PeerFromContext(request.Context())
			if !ok {
				fixedError(writer, http.StatusForbidden, "peer_not_authorized")
				return
			}
			if peer.UID != 0 &&
				peer.GID != group &&
				!peer.inSupplementaryGroup(group) {
				fixedError(writer, http.StatusForbidden, "peer_not_authorized")
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
}

type peerConnection struct {
	net.Conn
	peer Peer
}

type credentialListener struct {
	net.Listener
}

func (listener *credentialListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if _, ok := connection.RemoteAddr().(*net.UnixAddr); !ok {
			_ = connection.Close()
			continue
		}
		peer, err := PeerCredentials(connection)
		if err != nil {
			_ = connection.Close()
			continue
		}
		return &peerConnection{Conn: connection, peer: peer}, nil
	}
}

type ownedListener struct {
	listener net.Listener
	remove   func() error
	abandon  func() error
}

// HTTPServer owns the listener and socket path. ListenHTTP never starts an
// unobservable goroutine; callers choose when to Serve.
type HTTPServer struct {
	server   *http.Server
	owned    *ownedListener
	close    sync.Once
	closeErr error
}

func fixedError(writer http.ResponseWriter, status int, reason string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"error":"`+reason+`"}`+"\n")
}

func boundedJSON(maxBody int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Content-Encoding") != "" {
			fixedError(
				writer,
				http.StatusUnsupportedMediaType,
				"unsupported_content_encoding",
			)
			return
		}
		if request.Body == nil {
			next.ServeHTTP(writer, request)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(request.Body, maxBody+1))
		_ = request.Body.Close()
		if err != nil {
			fixedError(writer, http.StatusBadRequest, "invalid_body")
			return
		}
		if int64(len(raw)) > maxBody {
			fixedError(writer, http.StatusRequestEntityTooLarge, "body_too_large")
			return
		}
		if len(raw) > 0 && !utf8.Valid(raw) {
			fixedError(writer, http.StatusBadRequest, "invalid_body")
			return
		}
		if len(raw) > 0 {
			mediaType, parameters, parseErr := mime.ParseMediaType(
				request.Header.Get("Content-Type"),
			)
			charset, hasCharset := parameters["charset"]
			if parseErr != nil ||
				mediaType != "application/json" ||
				len(parameters) > 1 ||
				len(parameters) == 1 && !hasCharset ||
				hasCharset && !strings.EqualFold(charset, "utf-8") {
				fixedError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
				return
			}
		}
		request.Body = io.NopCloser(bytes.NewReader(raw))
		request.ContentLength = int64(len(raw))
		next.ServeHTTP(writer, request)
	})
}

// ListenHTTP validates and binds one owned Unix socket.
func ListenHTTP(
	path string,
	mode os.FileMode,
	gid int,
	maxBody int64,
	handler http.Handler,
) (*HTTPServer, error) {
	if handler == nil || maxBody < 1 || maxBody > 65_536 {
		return nil, ErrUnsafeSocket
	}
	owned, err := listenOwned(path, mode, gid)
	if err != nil {
		return nil, err
	}
	credentialed := &credentialListener{Listener: owned.listener}
	server := &http.Server{
		Handler:           boundedJSON(maxBody, handler),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
			peerConnection, ok := connection.(*peerConnection)
			if !ok {
				return ctx
			}
			return context.WithValue(ctx, peerContextKey{}, peerConnection.peer)
		},
	}
	return &HTTPServer{server: server, owned: &ownedListener{
		listener: credentialed,
		remove:   owned.remove,
		abandon:  owned.abandon,
	}}, nil
}

func (server *HTTPServer) Serve() error {
	return server.server.Serve(server.owned.listener)
}

func (server *HTTPServer) Close() error {
	server.close.Do(func() {
		serverErr := server.server.Close()
		listenerErr := server.owned.listener.Close()
		removeErr := server.owned.remove()
		if errors.Is(serverErr, http.ErrServerClosed) {
			serverErr = nil
		}
		if errors.Is(listenerErr, net.ErrClosed) {
			listenerErr = nil
		}
		server.closeErr = errors.Join(serverErr, listenerErr, removeErr)
	})
	return server.closeErr
}
