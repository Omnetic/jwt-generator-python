# jwt-generator-python

Python SDK that generates signed **RS256** JWT tokens for authenticating Omnetic DMS
**Service Account (SA)** requests against the DMS API. Distributed to third parties as a
standalone library — installed directly from GitHub, no public package registry (v1). Python
port of the reference package `jwt-generator-php`.

> **Status:** the SA token generator is implemented — `generate_token()` produces an
> RS256-signed JWT (see Public API). The other-language SDKs (C#/TypeScript/PHP) live in
> separate repos.

## Tech Stack

- **Library floor:** Python **3.11+** (what consumers need).
- **Runtime dependency:** `pyjwt[crypto]` — PyJWT for RS256 signing; its `[crypto]` extra
  pulls in `cryptography`, used directly for RSA key parsing/validation.
- **Dev/test image:** Python **3.13** (pinned in the Dockerfile).
- **Testing:** pytest. **Static analysis:** mypy (strict). **Code style:** ruff (lint + format).
- **Package manager:** `uv` (`uv.lock` committed). **Local runtime:** Docker + Docker Compose.

## Layout

```
src/omnetic_jwt_generator/__init__.py   ← public API; generate_token()
tests/test_generator.py                 ← pytest suite
examples/generate_token.py              ← runnable example; prints a signed SA token
examples/call_dms_api.py                ← runnable example; signs a token, calls a DMS endpoint
tests/test_examples.py                  ← subprocess smoke tests for the two examples
Dockerfile                              ← python:3.13-alpine + uv binary
docker-compose.yml                      ← single `python` service, mounts the repo, no ports
Makefile                                ← dev entry points (wrap `docker compose run --rm python …`)
pyproject.toml                          ← metadata, deps, tool config
```

## Development

Everything runs inside Docker — no local Python required.

```bash
make build       # build the dev/test image
make install     # uv sync
make test        # run pytest
make typecheck   # run mypy (strict)
make lint        # check code style (ruff)
make lint-fix    # auto-fix code style (ruff)
make shell       # open a shell in the container

make example         KEY=./sa-key.pem KID=<kid> [LIFETIME=600]   # print a signed token
make example-request KEY=./sa-key.pem KID=<kid> URL=<url>         # call a DMS endpoint
```

Equivalent without `make`: `docker compose run --rm python <cmd>` (e.g.
`docker compose run --rm python uv run pytest`).

The example targets bind-mount the repo, so the key must sit inside it (`*.pem` is
git-ignored). `OMNETIC_SA_KEY_PATH`, `OMNETIC_SA_KID` and `OMNETIC_DMS_API_URL` are
forwarded into the container and serve as fallbacks for the arguments.

## Public API

```python
from omnetic_jwt_generator import generate_token

token = generate_token(private_key, kid, lifetime=3600)
```

- `private_key` — RSA private key in **PEM** format (issued on SA creation / key rotation).
- `kid` — key ID (issued alongside the key); becomes the JWT `sub` claim.
- `lifetime` — token validity in seconds, optional, default `3600`, **max `3600`**.
- Returns a signed JWT for the `Authorization: Bearer` header.

The signed token uses **RS256** with header `{"alg":"RS256","typ":"JWT","kid":"<kid>"}`
(the `kid` is carried in **both** the header and the `sub` claim) and these payload claims:

```json
{ "type": "sa", "sub": "<kid>", "iat": "<now>", "exp": "<now + lifetime>" }
```

Validation the SDK enforces (cheap argument checks first, key parsing last): non-empty
`kid`, `1 <= lifetime <= 3600`, non-empty key, valid RSA PEM of at least 2048 bits. All
failures raise `ValueError`.

## Conventions

- Full type hints; `mypy --strict` clean (it covers `src`, `tests` **and** `examples`).
- Signing goes through `pyjwt` (RS256); `cryptography` provides key parsing/validation.
- Every public behavior gets a pytest test; `make test`, `make typecheck`, and `make lint`
  must stay green.
- The two examples are deliberately self-contained — they duplicate a little argument and
  key-reading code rather than share a helper module, so either one copies cleanly into a
  consumer project. They use only the standard library beyond the SDK itself.
- **No input may make an example print a traceback.** Consumers copy these files, so every
  failure exits `1` with a one-line message on stderr. `call_dms_api.py` therefore catches
  `http.client.HTTPException` and `UnicodeError` alongside `OSError` — urllib raises those
  for a non-numeric port, control characters or a non-ASCII host, and none of them is an
  `OSError`. `tests/test_examples.py` asserts `"Traceback" not in stderr` for those inputs.

### Deviations from the PHP reference

Intentional, and the only ones — keep this list current if the examples change:

| Deviation | Why |
|---|---|
| Examples are not in the built wheel (PHP ships them in `vendor/`) | A wheel contains only `src/omnetic_jwt_generator`; example code does not belong in the shipped namespace. The README says to run them from a clone. |
| A URL without a scheme is rejected, not just warned about | PHP's curl tolerates it; `urllib` would raise `ValueError: unknown url type` and traceback. |
| An empty `lifetime` argument means "default" | PHP's `(int)""` yields `0` and bounces off the SDK's range check. Empty-means-omitted is what the env fallthrough does everywhere else. |
| A non-numeric `lifetime` gets its own message | PHP's `(int)` cast silently turns `"abc"` into `0`, reporting a range error for what is really a typo. |
| Redirects are refused (`_NoRedirect`) | urllib follows them by default **and forwards the `Authorization` header**, so an `https` → `http` hop would leak the token in plaintext. PHP sets no `CURLOPT_FOLLOWLOCATION`, so this restores parity. |

## Context

- Jira: **T20-127460** ("[BE] JWT Generator SDK — C#, Python, TypeScript, PHP").
- Tokens must pass Gateway validation — **UC10 in T20-120653**. The claim shape and RS256
  algorithm above are the contract; do not diverge from them.
- The token-type claim is **`type`** (value `sa`), per the gateway contract (DEV-2012,
  confirmed in MR !13706). The legacy `typ` payload claim is deprecated — do **not** emit it.
- Sibling SDKs (separate repos): `jwt-generator-csharp`, `jwt-generator-php`,
  `jwt-generator-typescript`.
