package main

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// TLS 1.3 pinned on both transports. Production speaks 1.3; pinning here
// guards against a future Go default change.
func newH3Client() *http.Client {
	return &http.Client{
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

// Server only replies after the full upload completes, so we rely on
// Client.Timeout (covers TLS + body + response).
func newTCPClient(transferTimeout time.Duration) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ForceAttemptHTTP2 = true
	base.IdleConnTimeout = 120 * time.Second
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{}
	}
	base.TLSClientConfig.MinVersion = tls.VersionTLS13
	return &http.Client{
		Timeout:   transferTimeout,
		Transport: base,
	}
}
