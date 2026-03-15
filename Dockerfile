FROM golang:1.26 AS builder

WORKDIR /src

COPY . .

ENV CGO_ENABLED=0
ENV GOFLAGS=-mod=vendor

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" -o /out/go-pdns-ui ./cmd/go-pdns-ui

FROM alpine:3.22

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="go-pdns-ui" \
      org.opencontainers.image.description="A web UI for PowerDNS" \
      org.opencontainers.image.url="https://github.com/croessner/go-pdns-ui" \
      org.opencontainers.image.source="https://github.com/croessner/go-pdns-ui" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache ca-certificates tzdata \
	&& addgroup -S app \
	&& adduser -S -G app app

COPY --from=builder /out/go-pdns-ui /usr/local/bin/go-pdns-ui

USER app
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/go-pdns-ui"]
