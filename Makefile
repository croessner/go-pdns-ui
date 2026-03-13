GO ?= go
BIN_DIR ?= bin
APP_BIN := $(BIN_DIR)/go-pdns-ui
DOCKER_RUN_ARGS ?=
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS ?= -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)
SBOM_OUTPUT_DIR ?= sbom
SBOM_OUTPUT_PREFIX ?= go-pdns-ui
SBOM_DOCKER_IMAGE ?= ghcr.io/croessner/go-pdns-ui:latest
SBOM_DOCKER_PULL ?= true
SBOM_SYFT_VERSION ?= v1.16.0
.DEFAULT_GOAL := build

ifeq ($(firstword $(MAKECMDGOALS)),docker-run)
DOCKER_RUN_CLI_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
%:
	@:
endif

.PHONY: run test build clean tidy vendor fmt docker-build docker-run compose-up compose-down compose-logs sbom

run:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; $(GO) run ./cmd/go-pdns-ui

test:
	$(GO) test ./...

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(APP_BIN) ./cmd/go-pdns-ui

clean:
	rm -f $(APP_BIN) go-pdns-ui

tidy:
	GOFLAGS=-mod=mod $(GO) mod tidy

vendor:
	GOFLAGS=-mod=mod $(GO) mod vendor

fmt:
	gofmt -w $$(rg --files -g '*.go')

docker-build:
	docker build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg COMMIT="$(COMMIT)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		-t go-pdns-ui:local .

docker-run:
	docker run --rm -p 8080:8080 --env-file .env $(DOCKER_RUN_ARGS) $(DOCKER_RUN_CLI_ARGS) go-pdns-ui:local

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f

sbom:
	./scripts/sbom.sh \
		--output-dir $(SBOM_OUTPUT_DIR) \
		--output-prefix $(SBOM_OUTPUT_PREFIX) \
		--source-dir . \
		--docker-image $(SBOM_DOCKER_IMAGE) \
		--docker-pull $(SBOM_DOCKER_PULL) \
		--syft-version $(SBOM_SYFT_VERSION)
