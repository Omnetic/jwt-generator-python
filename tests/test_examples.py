"""Smoke tests for the scripts in examples/ — mirrors the PHP reference suite.

The examples ship with the SDK, so their argument handling, output streams and exit
codes are behavior worth pinning down. Each script runs in a subprocess, the way a
consumer runs it. The request path is exercised against a loopback server on an
ephemeral port; no test reaches outside the machine.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KID = "kid-uuid-1"
EXAMPLES = Path(__file__).parent.parent / "examples"
# Never reached: the tests that pass this fail before the request is made.
UNREACHED_URL = "https://dms.example.com/endpoint"


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    """Write a freshly generated 2048-bit RSA private key to a temporary PEM file."""
    return _write_key(tmp_path / "sa-key.pem", serialization.Encoding.PEM)


@pytest.fixture
def server() -> Iterator[_Server]:
    """Serve on 127.0.0.1 for the duration of one test, recording what it receives."""
    httpd = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=10)


class _Server(ThreadingHTTPServer):
    """Loopback server that records Authorization headers and can issue a redirect."""

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(address, handler)
        self.authorization: list[str | None] = []
        self.redirect_target = ""

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server_port}{path}"


class _Handler(BaseHTTPRequestHandler):
    """Answers by path: /ok is 2xx, /redirect is a 302, anything else is a 404."""

    def do_GET(self) -> None:
        server = self.server
        assert isinstance(server, _Server)
        server.authorization.append(self.headers.get("Authorization"))

        if self.path == "/ok":
            self._respond(200, b'{"ok":true}')
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", server.redirect_target)
            self.end_headers()
        else:
            self._respond(404, b'{"error":"not found"}')

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Keep the server quiet; pytest captures enough already."""


def _write_key(path: Path, encoding: serialization.Encoding) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return path


def _run(script: str, *arguments: str, **environment: str) -> subprocess.CompletedProcess[str]:
    """Run an example in a subprocess, with the variables it reads under test control.

    Drops the OMNETIC_* variables a developer may have exported, so the fallback tests
    cannot pass for the wrong reason, and the proxy variables, so a proxied environment
    cannot reroute the loopback requests.
    """
    inherited = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("OMNETIC_") and not key.lower().endswith("_proxy")
    }

    return subprocess.run(
        [sys.executable, str(EXAMPLES / script), *arguments],
        capture_output=True,
        text=True,
        env={**inherited, **environment},
        timeout=30,
        check=False,
    )


def test_generate_token_prints_a_signed_token_on_stdout(key_file: Path) -> None:
    result = _run("generate_token.py", str(key_file), KID, "600")

    assert result.returncode == 0, result.stderr
    token = result.stdout.strip()
    assert len(token.split(".")) == 3
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["sub"] == KID
    assert payload["exp"] - payload["iat"] == 600


def test_generate_token_defaults_to_the_maximum_lifetime(key_file: Path) -> None:
    result = _run("generate_token.py", str(key_file), KID)

    assert result.returncode == 0, result.stderr
    payload = jwt.decode(result.stdout.strip(), options={"verify_signature": False})
    assert payload["exp"] - payload["iat"] == 3600


def test_generate_token_falls_back_to_the_environment_when_arguments_are_empty(
    key_file: Path,
) -> None:
    # `make example` always passes both arguments, empty ones included.
    result = _run(
        "generate_token.py",
        "",
        "",
        OMNETIC_SA_KEY_PATH=str(key_file),
        OMNETIC_SA_KID=KID,
    )

    assert result.returncode == 0, result.stderr
    assert len(result.stdout.strip().split(".")) == 3


def test_generate_token_prefers_its_arguments_over_the_environment(key_file: Path) -> None:
    result = _run(
        "generate_token.py",
        str(key_file),
        "kid-from-argument",
        OMNETIC_SA_KEY_PATH="/nonexistent/sa-key.pem",
        OMNETIC_SA_KID="kid-from-environment",
    )

    assert result.returncode == 0, result.stderr
    payload = jwt.decode(result.stdout.strip(), options={"verify_signature": False})
    assert payload["sub"] == "kid-from-argument"


def test_generate_token_prints_usage_without_arguments() -> None:
    result = _run("generate_token.py")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Usage: python examples/generate_token.py" in result.stderr


def test_generate_token_reports_a_key_path_that_is_not_a_readable_file(tmp_path: Path) -> None:
    result = _run("generate_token.py", str(tmp_path), KID)

    assert result.returncode == 1
    assert "does not exist or is not readable" in result.stderr


def test_generate_token_reports_a_key_file_that_is_not_pem_text(tmp_path: Path) -> None:
    der_key = _write_key(tmp_path / "sa-key.der", serialization.Encoding.DER)

    result = _run("generate_token.py", str(der_key), KID)

    assert result.returncode == 1
    assert "is not PEM text" in result.stderr


def test_generate_token_reports_the_sdk_validation_message(key_file: Path) -> None:
    result = _run("generate_token.py", str(key_file), KID, "9999")

    assert result.returncode == 1
    assert "The lifetime must be between 1 and 3600 seconds" in result.stderr


def test_generate_token_rejects_a_non_numeric_lifetime(key_file: Path) -> None:
    result = _run("generate_token.py", str(key_file), KID, "an-hour")

    assert result.returncode == 1
    assert "The lifetime must be a whole number of seconds" in result.stderr


def test_call_dms_api_prints_usage_without_arguments() -> None:
    result = _run("call_dms_api.py")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Usage: python examples/call_dms_api.py" in result.stderr


def test_call_dms_api_prints_usage_when_only_the_url_is_missing(key_file: Path) -> None:
    result = _run("call_dms_api.py", str(key_file), KID)

    assert result.returncode == 1
    assert "Usage: python examples/call_dms_api.py" in result.stderr


def test_call_dms_api_rejects_a_url_without_a_scheme(key_file: Path) -> None:
    result = _run("call_dms_api.py", str(key_file), KID, "dms.example.com/endpoint")

    assert result.returncode == 1
    assert "must start with https://" in result.stderr


def test_call_dms_api_reports_a_key_path_that_is_not_a_readable_file(tmp_path: Path) -> None:
    result = _run("call_dms_api.py", str(tmp_path), KID, UNREACHED_URL)

    assert result.returncode == 1
    assert "does not exist or is not readable" in result.stderr


def test_call_dms_api_sends_a_bearer_token_and_reports_a_2xx(
    key_file: Path, server: _Server
) -> None:
    result = _run("call_dms_api.py", str(key_file), KID, server.url("/ok"))

    assert result.returncode == 0, result.stderr
    assert "HTTP 200" in result.stdout
    assert '{"ok":true}' in result.stdout
    # The endpoint got exactly one request, carrying a signed token.
    assert len(server.authorization) == 1
    scheme, _, token = (server.authorization[0] or "").partition(" ")
    assert scheme == "Bearer"
    assert len(token.split(".")) == 3
    assert jwt.decode(token, options={"verify_signature": False})["sub"] == KID


def test_call_dms_api_warns_that_a_plain_http_url_is_not_encrypted(
    key_file: Path, server: _Server
) -> None:
    result = _run("call_dms_api.py", str(key_file), KID, server.url("/ok"))

    assert result.returncode == 0, result.stderr
    assert "is not HTTPS" in result.stderr


def test_call_dms_api_prints_a_non_2xx_body_and_exits_non_zero(
    key_file: Path, server: _Server
) -> None:
    result = _run("call_dms_api.py", str(key_file), KID, server.url("/missing"))

    assert result.returncode == 1
    assert "HTTP 404" in result.stdout
    assert '{"error":"not found"}' in result.stdout


def test_call_dms_api_does_not_follow_a_redirect_or_forward_the_token(
    key_file: Path, server: _Server
) -> None:
    server.redirect_target = server.url("/ok")

    result = _run("call_dms_api.py", str(key_file), KID, server.url("/redirect"))

    assert result.returncode == 1
    assert "HTTP 302" in result.stdout
    # Only the redirect itself was requested — the token never reached the target.
    assert len(server.authorization) == 1


def test_call_dms_api_reports_a_refused_connection(key_file: Path) -> None:
    # Port 1 on loopback: nothing listens there, and nothing leaves the machine.
    result = _run("call_dms_api.py", str(key_file), KID, "http://127.0.0.1:1/endpoint")

    assert result.returncode == 1
    assert "failed" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("path", ["/control\ncharacters", "/non-ascii-ä"])
def test_call_dms_api_reports_a_url_http_client_rejects(
    key_file: Path, server: _Server, path: str
) -> None:
    result = _run("call_dms_api.py", str(key_file), KID, server.url(path))

    assert result.returncode == 1
    assert "failed" in result.stderr
    assert "Traceback" not in result.stderr


def test_call_dms_api_reports_a_url_with_a_non_numeric_port(key_file: Path) -> None:
    result = _run("call_dms_api.py", str(key_file), KID, "http://127.0.0.1:not-a-port/endpoint")

    assert result.returncode == 1
    assert "failed" in result.stderr
    assert "Traceback" not in result.stderr
