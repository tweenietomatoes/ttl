.PHONY: build test clean install snapshot

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='$(LDFLAGS)' -o ttl ./cmd/ttl

test:
	go test -v -count=1 ./internal/... ./cmd/ttl/

clean:
	rm -f ttl
	rm -rf dist/

install:
	CGO_ENABLED=0 go install -trimpath -ldflags='$(LDFLAGS)' ./cmd/ttl

snapshot:
	goreleaser release --snapshot --clean
