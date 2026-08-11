VERSION ?= 0.4.0
BINARY := bin/grok-switch
LDFLAGS := -s -w -X github.com/bbbkawaii/GrokSwitch/internal/cli.Version=$(VERSION)

.PHONY: build install test test-race vet fmt-check check clean

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/grok-switch

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/grok-switch

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

check: fmt-check vet test

clean:
	rm -f $(BINARY)
