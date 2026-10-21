GO ?= go

# Version stamp: git tag ("v0.5"), else commit hash, else "dev".
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all check fmt-check vet test jscheck jstest build release install clean

# The standard gate: formatting, vet, race-enabled tests, then build.
all: check build

check: fmt-check vet test jscheck jstest

jscheck:
	@if command -v node >/dev/null 2>&1; then \
		for f in extension/*.js; do node --check "$$f" || exit 1; done; \
	else \
		echo "node not found – skipping JS syntax check"; \
	fi

jstest:
	@if command -v node >/dev/null 2>&1; then \
		node --test 'jstest/**/*.mjs' || exit 1; \
	else \
		echo "node not found – skipping JS tests"; \
	fi

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run: gofmt -w ."; exit 1; }

vet:
	$(GO) vet ./...

test:
	$(GO) test -race -count=1 ./...

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o torspeed .

release: check
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o torspeed-linux-amd64 .
	GOOS=linux   GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o torspeed-linux-arm64 .
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o torspeed-windows-amd64.exe .
	GOOS=darwin  GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o torspeed-darwin-arm64 .
	GOOS=darwin  GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o torspeed-darwin-amd64 .

install: build
	cp torspeed ~/bin/

clean:
	rm -f torspeed torspeed-*
