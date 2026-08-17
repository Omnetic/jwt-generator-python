# jwt-generator-python

Python SDK for generating signed **RS256** JWT tokens used to authenticate Omnetic DMS
**Service Account** requests against the DMS API. Python port of
[`jwt-generator-php`](https://github.com/Omnetic/jwt-generator-php).

## Requirements

- Python **3.11+** (for consumers)
- Docker + Docker Compose (for local development)

## Installation

Installed directly from GitHub (no public package index, v1):

```bash
pip install git+https://github.com/Omnetic/jwt-generator-python.git
```

## Usage

```python
from omnetic_jwt_generator import generate_token

token = generate_token(private_key, kid, 3600)
# Authorization: Bearer <token>
```

- `private_key` — RSA private key in PEM format (issued on SA creation / key rotation)
- `kid` — key ID (issued alongside the key)
- `lifetime` — token validity in seconds, optional, default `3600`, max `3600`

`generate_token()` builds and RS256-signs a JWT with header
`{"alg":"RS256","typ":"JWT","kid":"<kid>"}` and the claims:

```json
{ "type": "sa", "sub": "<kid>", "iat": "<now>", "exp": "<now + lifetime>" }
```

It raises `ValueError` if the `kid` is empty, `lifetime` is outside `1…3600`,
or the private key is empty / not a valid RSA PEM / shorter than 2048 bits.

## Examples

Two runnable scripts in [`examples/`](examples) — both take the key path, the `kid` and
(for the request example) the endpoint URL as arguments, or from the `OMNETIC_SA_KEY_PATH`,
`OMNETIC_SA_KID` and `OMNETIC_DMS_API_URL` environment variables.

```bash
# Print a signed token (default lifetime 3600 s; optional third argument overrides it)
python examples/generate_token.py ./sa-key.pem <kid> 600

# Call a DMS endpoint with a freshly signed token — prints the status and body
python examples/call_dms_api.py ./sa-key.pem <kid> https://<dms-host>/<endpoint>
```

The examples stay in this repo rather than in the installed package, so run them from a
clone with the SDK importable (`uv run python examples/…`). They are short and
self-contained — copying one into your own project works just as well.

Pass the path to the key, never the key itself, so no key material lands in your shell
history. Both scripts write the token / response to stdout and every diagnostic to stderr,
and exit non-zero on failure (`call_dms_api.py` exits `0` on any `2xx`), so they compose
in scripts and CI.

Use the URL of a DMS endpoint your Service Account is allowed to call; the example does
not assume one. A `401` means the Gateway rejected the token — check that the `kid` matches
the key, that the Service Account is enabled, and that the clock is not skewed.
`call_dms_api.py` requests through the standard library (`urllib`), so the examples need
nothing beyond the SDK's own dependencies. It does not follow redirects — a `3xx` is
reported like any other non-`2xx`, so the token is never handed to whatever the `Location`
header points at.

Via Docker, wrapped by the Makefile (the key must sit inside the repo — that is what gets
mounted; `*.pem` is git-ignored):

```bash
make example         KEY=./sa-key.pem KID=<kid> [LIFETIME=600]
make example-request KEY=./sa-key.pem KID=<kid> URL=https://<dms-host>/<endpoint>
```

The three environment variables are forwarded into the container, so they work as fallbacks
for the `make` targets too.

## Development

Everything runs inside Docker — no local Python required.

```bash
make build       # build the dev/test image (Python 3.13)
make install     # uv sync (resolve + install deps)
make test        # run pytest
make typecheck   # run mypy (strict)
make lint        # check code style (ruff)
make lint-fix    # auto-fix code style (ruff)
make shell       # open a shell in the container
```
