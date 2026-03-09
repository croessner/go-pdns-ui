# Go-PDNS UI (Prototype)

Modern HTMX UI prototype for administering PowerDNS zones with draft/apply workflow.

## Features in this prototype

- Login via hardcoded username/password (`admin`/`admin`)
- Optional OpenID Connect login (Discovery + Authorization Code + PKCE)
- Role mapping from OIDC `groups` claim (`admin` / `user`)
- Domain list with create/delete
- Zone editor with record add/delete
- DNSSEC toggle on draft state
- Draft vs apply behavior per zone
- Reverse zone validation for IPv4 (`.in-addr.arpa`) and IPv6 (`.ip6.arpa`)
- PowerDNS API abstraction with real backend integration
- Dark mode toggle
- Multi-language UI (`de`, `en`) via JSON locale files

## Configuration

### Local login

- `GO_PDNS_UI_USERNAME` (default: `admin`)
- `GO_PDNS_UI_PASSWORD` (default: `admin`)

### OIDC (optional)

- `GO_PDNS_UI_OIDC_DISCOVERY_URL`
- `GO_PDNS_UI_OIDC_CLIENT_ID`
- `GO_PDNS_UI_OIDC_CLIENT_SECRET` (optional for public clients)
- `GO_PDNS_UI_OIDC_REDIRECT_URL` (for example `http://localhost:8080/auth/oidc/callback`)
- `GO_PDNS_UI_OIDC_SCOPES` (default: `openid profile email groups`)
- `GO_PDNS_UI_OIDC_ADMIN_GROUP` (default: `admin`)
- `GO_PDNS_UI_OIDC_USER_GROUP` (default: `user`)

### PowerDNS API

- `GO_PDNS_API_URL` (for example `http://127.0.0.1:8081/api/v1`)
- `GO_PDNS_API_KEY`
- `GO_PDNS_SERVER_ID` (default: `localhost`)
- `GO_PDNS_HTTP_TIMEOUT_SECONDS` (default: `10`)

## Setup

Create your local env file:

```bash
cp .env.example .env
```

Adjust the values in `.env` for your environment.

Notes:

- If OIDC variables are unset, local username/password login stays active.
- If `GO_PDNS_API_URL` and `GO_PDNS_API_KEY` are unset, the app uses in-memory demo data.

## Run

```bash
set -a && source .env && set +a
go run ./cmd/go-pdns-ui
```

The UI is available at `http://localhost:8080`.

## Make Targets

```bash
make run
make test
make build
make docker-build
make docker-run
```

## Docker

Build:

```bash
docker build -t go-pdns-ui:local .
```

Run with env file:

```bash
docker run --rm -p 8080:8080 --env-file .env go-pdns-ui:local
```
