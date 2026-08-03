"""Sign a Service Account token and print it.

Usage:
    python examples/generate_token.py <path-to-private-key.pem> <kid> [lifetime]

The key path and kid may also come from the OMNETIC_SA_KEY_PATH and OMNETIC_SA_KID
environment variables. Both the key and the kid are issued on Service Account
creation / key rotation.

Run from a clone of this repo (the examples are not part of the installed package).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from omnetic_jwt_generator import generate_token

DEFAULT_LIFETIME = 3600
USAGE = "Usage: python examples/generate_token.py <path-to-private-key.pem> <kid> [lifetime]"


def main(argv: list[str]) -> int:
    # Empty arguments fall through to the environment, so an omitted `make example`
    # variable behaves the same as passing nothing at all.
    key_path = _argument(argv, 0) or os.environ.get("OMNETIC_SA_KEY_PATH", "")
    kid = _argument(argv, 1) or os.environ.get("OMNETIC_SA_KID", "")
    lifetime_argument = _argument(argv, 2)

    if key_path == "" or kid == "":
        print(USAGE, file=sys.stderr)

        return 1

    if lifetime_argument == "":
        lifetime = DEFAULT_LIFETIME
    else:
        try:
            lifetime = int(lifetime_argument)
        except ValueError:
            print(
                f"The lifetime must be a whole number of seconds, got '{lifetime_argument}'.",
                file=sys.stderr,
            )

            return 1

    private_key = _read_private_key(key_path)
    if private_key is None:
        return 1

    try:
        token = generate_token(private_key, kid, lifetime)
    except ValueError as error:
        print(f"Could not generate a token: {error}", file=sys.stderr)

        return 1

    # Send this as `Authorization: Bearer <token>` on every DMS API request.
    print(token)

    return 0


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
