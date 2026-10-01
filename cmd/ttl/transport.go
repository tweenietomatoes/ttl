package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// userAgent names the CLI on every request. The server buckets its upload
// telemetry by client and looks for "ttl-cli" in the User-Agent.
func userAgent() string {
	return "ttl-cli/" + version + " (" + runtime.GOOS + "; " + runtime.GOARCH + ")"
}

// noRedirect keeps X-API-Key and X-Download-Token on the host they were
// meant for: a 3xx comes back as-is and is reported as a server error.
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// TLS 1.3 pinned on both transports. Production speaks 1.3; pinning here
// guards against a future Go default change.
func newH3Client() *http.Client {
	return &http.Client{
		CheckRedirect: noRedirect,
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				NextProtos: []string{http3.NextProtoH3},
			},
			QUICConfig: &quic.Config{
				MaxIdleTimeout: 120 * time.Second,
			},
		},
	}
}

// newTCPClient returns the HTTP/1.1+2 client. Every request carries its own
// context deadline; a non-zero transferTimeout additionally caps the whole
// exchange (TLS + body + response).
func newTCPClient(transferTimeout time.Duration) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ForceAttemptHTTP2 = true
	base.IdleConnTimeout = 120 * time.Second
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{}
	}
	base.TLSClientConfig.MinVersion = tls.VersionTLS13
	return &http.Client{
		Timeout:       transferTimeout,
		Transport:     base,
		CheckRedirect: noRedirect,
	}
}

// httpConn is the connection for one command run: HTTP/3 when -h3 was
// given, TCP otherwise. The first transport-level failure over HTTP/3 (a
// network that drops UDP, a QUIC handshake that times out) moves the run
// to TCP for good, so it costs one failed request rather than one per
// request.
type httpConn struct {
	client *http.Client
	h3     bool
}

func newConn() *httpConn {
	if forceH3 {
		return &httpConn{client: newH3Client(), h3: true}
	}
	return &httpConn{client: newTCPClient(0)}
}

// newRequest is http.NewRequestWithContext plus the CLI's User-Agent. The
// URL is the server or link the user named on the command line, checked by
// validateServerURL / parseURL (https, or http to loopback only).
func newRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body) //nolint:gosec // G704: user-chosen, validated destination
	if err != nil {
		return nil, fmt.Errorf("Invalid URL: %w", err)
	}
	req.Header.Set("User-Agent", userAgent())
	return req, nil
}

// do sends req. When it fails at the transport level over HTTP/3, the run
// switches to TCP and the same request is sent again there, provided its
// body can be replayed (none, or one with GetBody). A request whose
// context is already done is not retried.
//
// The request URL is the server or link the user named on the command
// line, checked by validateServerURL / parseURL (https, or http to
// loopback only); the CLI has no other destination.
func (h *httpConn) do(req *http.Request) (*http.Response, error) {
	resp, err := h.client.Do(req) //nolint:gosec // G704: user-chosen, validated destination (see above)
	if err == nil || !h.h3 || req.Context().Err() != nil {
		return resp, err
	}
	h.fallbackToTCP()
	if req.Body != nil && req.GetBody == nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, err
		}
		retry.Body = body
	}
	return h.client.Do(retry) //nolint:gosec // G704: same validated destination
}

// fallbackToTCP replaces the HTTP/3 client with a TCP one.
func (h *httpConn) fallbackToTCP() {
	if !h.h3 {
		return
	}
	h.h3 = false
	if closer, ok := h.client.Transport.(io.Closer); ok {
		_ = closer.Close()
	}
	h.client = newTCPClient(0)
	if !jsonMode {
		fmt.Fprintf(os.Stderr, "\n%sH3: Falling back to TCP%s\n", c(cGray), c(cReset))
	}
}
