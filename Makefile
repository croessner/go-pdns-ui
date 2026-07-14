GO ?= go
GO_MOD_FLAGS ?= -mod=vendor
GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK ?= govulncheck
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

.PHONY: run fix fmt vet lint-config lint test race build build-check guardrails govulncheck release-guardrails install-hooks clean tidy vendor docker-build docker-run compose-up compose-down compose-logs generate-config sbom

run:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; $(GO) run $(GO_MOD_FLAGS) ./cmd/go-pdns-ui

fix:
	GOFLAGS=$(GO_MOD_FLAGS) $(GO) fix ./...
	find . -path ./vendor -prune -o -type f -name '*.go' -exec gofmt -w {} +

fmt:
	find . -path ./vendor -prune -o -type f -name '*.go' -exec gofmt -w {} +

vet:
	GOFLAGS=$(GO_MOD_FLAGS) $(GO) vet ./...

lint-config:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { echo "$(GOLANGCI_LINT) not found. Install golangci-lint v2 and rerun make guardrails"; exit 1; }
	$(GOLANGCI_LINT) config verify

lint: lint-config
	$(GOLANGCI_LINT) run ./...

test:
	GOFLAGS=$(GO_MOD_FLAGS) $(GO) test ./...

race:
	CGO_ENABLED=1 GOFLAGS=$(GO_MOD_FLAGS) $(GO) test -race -short ./...

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GO_MOD_FLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(APP_BIN) ./cmd/go-pdns-ui

build-check:
	CGO_ENABLED=0 $(GO) build $(GO_MOD_FLAGS) -trimpath ./...

guardrails: fix vet lint test race build-check

govulncheck:
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { echo "$(GOVULNCHECK) not found. Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	GOFLAGS=$(GO_MOD_FLAGS) $(GOVULNCHECK) -scan=package ./...

release-guardrails: guardrails govulncheck

install-hooks:
	bash ./scripts/install-hooks.sh

clean:
	rm -f $(APP_BIN) go-pdns-ui

tidy:
	GOFLAGS=-mod=mod $(GO) mod tidy

vendor:
	GOFLAGS=-mod=mod $(GO) mod vendor

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

generate-config:
	@if [ ! -f .env ]; then echo "Error: .env not found. Copy .env.example and fill in values."; exit 1; fi
	@set -a; . ./.env; set +a; \
	envsubst < deploy/nauthilus/nauthilus.yml.template > deploy/nauthilus/nauthilus.yml
	@echo "Generated deploy/nauthilus/nauthilus.yml"

sbom:
	./scripts/sbom.sh \
		--output-dir $(SBOM_OUTPUT_DIR) \
		--output-prefix $(SBOM_OUTPUT_PREFIX) \
		--source-dir . \
		--docker-image $(SBOM_DOCKER_IMAGE) \
		--docker-pull $(SBOM_DOCKER_PULL) \
		--syft-version $(SBOM_SYFT_VERSION)
