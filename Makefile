GO ?= go
BIN_DIR ?= bin
APP_BIN := $(BIN_DIR)/go-pdns-ui
DOCKER_RUN_ARGS ?=
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS ?= -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

ifeq ($(firstword $(MAKECMDGOALS)),docker-run)
DOCKER_RUN_CLI_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
%:
	@:
endif

.PHONY: run test build tidy vendor fmt docker-build docker-run compose-up compose-down compose-logs

run:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; $(GO) run ./cmd/go-pdns-ui

test:
	$(GO) test ./...

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(APP_BIN) ./cmd/go-pdns-ui

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
