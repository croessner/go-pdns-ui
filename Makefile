GO ?= go
BIN_DIR ?= bin
APP_BIN := $(BIN_DIR)/go-pdns-ui

.PHONY: run test build tidy vendor fmt docker-build docker-run

run:
	@if [ -f .env ]; then set -a; . ./.env; set +a; fi; $(GO) run ./cmd/go-pdns-ui

test:
	$(GO) test ./...

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -o $(APP_BIN) ./cmd/go-pdns-ui

tidy:
	GOFLAGS=-mod=mod $(GO) mod tidy

vendor:
	GOFLAGS=-mod=mod $(GO) mod vendor

fmt:
	gofmt -w $$(rg --files -g '*.go')

docker-build:
	docker build -t go-pdns-ui:local .

docker-run:
	docker run --rm -p 8080:8080 --env-file .env go-pdns-ui:local
