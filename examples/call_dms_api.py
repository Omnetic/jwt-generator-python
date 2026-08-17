"""Sign a Service Account token and call a DMS API endpoint with it.

Usage:
    python examples/call_dms_api.py <path-to-private-key.pem> <kid> <url>

The arguments may also come from the OMNETIC_SA_KEY_PATH, OMNETIC_SA_KID and
OMNETIC_DMS_API_URL environment variables. Use the URL of the DMS endpoint your
Service Account is allowed to call.

The request goes through the standard library (urllib), so this example needs no
dependencies beyond the SDK itself. Redirects are not followed — see _NoRedirect.
"""

from __future__ import annotations

import http.client
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import IO

from omnetic_jwt_generator import generate_token

# A short lifetime is enough for a single request; tokens are cheap to mint.
TOKEN_LIFETIME = 300
TIMEOUT_SECONDS = 30
USAGE = "Usage: python examples/call_dms_api.py <path-to-private-key.pem> <kid> <url>"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: urllib would forward the Bearer token to wherever they point."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> None:
        # Returning None leaves the 3xx to surface as an HTTPError, so it is reported
        # like any other non-2xx response. curl — and so the PHP example — likewise
        # does not follow redirects unless asked to.
        return None


# The default opener follows redirects, which would leak the token (an https -> http
# hop would also leak it in plaintext, after this script promised HTTPS).
_OPENER = urllib.request.build_opener(_NoRedirect)


def main(argv: list[str]) -> int:
    # Empty arguments fall through to the environment, so an omitted `make
    # example-request` variable behaves the same as passing nothing at all.
    key_path = _argument(argv, 0) or os.environ.get("OMNETIC_SA_KEY_PATH", "")
    kid = _argument(argv, 1) or os.environ.get("OMNETIC_SA_KID", "")
    url = _argument(argv, 2) or os.environ.get("OMNETIC_DMS_API_URL", "")

    if key_path == "" or kid == "" or url == "":
        print(USAGE, file=sys.stderr)

        return 1

    if not url.startswith(("https://", "http://")):
        print(f"The URL must start with https:// (or http://), got '{url}'.", file=sys.stderr)

        return 1

    if url.startswith("http://"):
        print(
            f"Warning: {url} is not HTTPS — the token would travel in plaintext.",
            file=sys.stderr,
        )

    private_key = _read_private_key(key_path)
    if private_key is None:
        return 1

    try:
        token = generate_token(private_key, kid, TOKEN_LIFETIME)
    except ValueError as error:
        print(f"Could not generate a token: {error}", file=sys.stderr)

        return 1

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    )

    try:
        with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            body = response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        # A non-2xx — a refused redirect included — is still a response worth printing;
        # the exit code below reports it.
        status = error.code
        body = error.read().decode(errors="replace")
    except (OSError, http.client.HTTPException, UnicodeError) as error:
        # OSError covers URLError (DNS, TLS, refused connection) and socket timeouts.
        # The other two cover URLs that http.client rejects once it builds the request
        # line: a non-numeric port, control characters, non-ASCII outside the query.
        print(f"The request to {url} failed: {error}", file=sys.stderr)

        return 1

    print(f"HTTP {status}")
    print(body)

    # A 401 means the Gateway rejected the token: check that the kid matches the
    # key, that the Service Account is enabled, and that the clock is not skewed.
    return 0 if 200 <= status < 300 else 1


def _argument(argv: list[str], index: int) -> str:
    """Return the positional argument at ``index``, or an empty string when absent."""
    return argv[index] if index < len(argv) else ""


def _read_private_key(key_path: str) -> str | None:
    """Read the PEM key file, or report to stderr and return ``None`` on failure."""
    try:
        return Path(key_path).read_text()
    except OSError:
        print(
            f"The private key file {key_path} does not exist or is not readable.",
            file=sys.stderr,
        )
    except UnicodeDecodeError:
        print(
            f"The private key file {key_path} is not PEM text — export the key as PEM.",
            file=sys.stderr,
        )

    return None


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
