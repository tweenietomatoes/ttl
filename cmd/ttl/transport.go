package main

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newH3Client() *http.Client {
	return &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				NextProtos: []string{http3.NextProtoH3},
			},
			QUICConfig: &quic.Config{
				MaxIdleTimeout: 120 * time.Second,
			},
		},
	}
}

// Response header timeout is zero because the server replies only
// after the full upload completes.
func newTCPClient(transferTimeout time.Duration) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ForceAttemptHTTP2 = true
	base.IdleConnTimeout = 120 * time.Second
	return &http.Client{
		Timeout:   transferTimeout,
		Transport: base,
	}
}
