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

RUN apk add --no-cache ca-certificates tzdata \
	&& addgroup -S app \
	&& adduser -S -G app app

COPY --from=builder /out/go-pdns-ui /usr/local/bin/go-pdns-ui

USER app
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/go-pdns-ui"]
