GO ?= go

BINARIES := forge forge-worker kliq correlate proof-issuer conformance-worker kernloomctl

.PHONY: fmt vet test build

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

build:
	mkdir -p bin
	$(GO) build -o bin/forge ./cmd/forge
	$(GO) build -o bin/forge-worker ./cmd/forge-worker
	$(GO) build -o bin/kliq ./cmd/kliq
	$(GO) build -o bin/correlate ./cmd/correlate
	$(GO) build -o bin/proof-issuer ./cmd/proof-issuer
	$(GO) build -o bin/conformance-worker ./cmd/conformance-worker
	$(GO) build -o bin/kernloomctl ./cmd/kernloomctl

