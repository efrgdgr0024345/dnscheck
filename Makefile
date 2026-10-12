GO ?= go
NODE ?= node
PYTHON ?= python3
GOFLAGS := -mod=readonly
export GOFLAGS
REVISION ?= $(shell git rev-parse --verify HEAD 2>/dev/null || printf source-archive)$(shell test -z "$$(git status --porcelain 2>/dev/null)" || printf '%s' -dirty)

.PHONY: build test vet check-config frontend-test script-test
build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-X main.revision=$(REVISION)" -o bin/addrd ./cmd/addrd

frontend-test:
	$(NODE) --test tests/frontend/*.test.mjs

script-test:
	$(PYTHON) -m unittest discover -s tests/scripts -p 'test_*.py'
	bash -n scripts/build-addrd.sh scripts/run-addrd.sh scripts/certbot-env.sh scripts/get-certs.sh scripts/renew-certs.sh

test: frontend-test script-test
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

check-config:
	$(GO) run ./cmd/addrd -check-config -c configs/local-addrd.json
