"""Opt-in end-to-end checks for the attended Firstlook network boundary.

The normal suite leaves these tests skipped because one binds TCP 443 and adds
an ephemeral public address to Linux loopback, while the other performs a real
clean virtual-environment install. CI enables them on a disposable runner with
``FIRSTLOOK_CI_ISOLATION=true``.
"""

from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest

from firstlook_security import (
    FirstlookBoundary,
    FirstlookDNSRejected,
    FirstlookFetchError,
    PinnedHTTPSConnection,
)


ROOT = Path(__file__).resolve().parents[1]
APPROVED_HOST = "www.limitlessenterprise.ai"
APPROVED_URL = f"https://{APPROVED_HOST}/audit"
PUBLIC_TEST_ADDRESS = "93.184.216.34"
RUN_ISOLATION = os.environ.get("FIRSTLOOK_CI_ISOLATION") == "true"
MODULES = (
    "server.py",
    "firstlook_security.py",
    "state.py",
    "libreclient.py",
    "runner.py",
    "external_links.py",
    "content_audit.py",
    "extended_checks.py",
    "schema_validator.py",
    "sitemap_fill.py",
    "pdf_report.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(
    RUN_ISOLATION
    and sys.platform.startswith("linux")
    and getattr(os, "geteuid", lambda: -1)() == 0,
    "requires FIRSTLOOK_CI_ISOLATION=true on a root-capable Linux runner",
)
class FirstlookSocketIsolationTests(unittest.TestCase):
    """Drive the production connector through a real TLS socket on port 443."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("ip") or not shutil.which("openssl"):
            raise unittest.SkipTest("iproute2 and openssl are required")

        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.temporary = Path(cls._temporary_directory.name)
        cls.requests = []
        cls.server_names = []
        cls._address_added = False
        cls.server = None
        cls.server_thread = None

        current_addresses = subprocess.run(
            ["ip", "-4", "address", "show", "dev", "lo"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if PUBLIC_TEST_ADDRESS not in current_addresses:
            subprocess.run(
                [
                    "ip",
                    "address",
                    "add",
                    f"{PUBLIC_TEST_ADDRESS}/32",
                    "dev",
                    "lo",
                ],
                check=True,
            )
            cls._address_added = True

        try:
            cls._create_certificate()
            cls._start_https_server()
        except Exception:
            cls._cleanup_resources()
            raise

    @classmethod
    def tearDownClass(cls):
        cls._cleanup_resources()

    @classmethod
    def _cleanup_resources(cls):
        server = getattr(cls, "server", None)
        if server is not None:
            server.shutdown()
            server.server_close()
        thread = getattr(cls, "server_thread", None)
        if thread is not None:
            thread.join(timeout=5)
        if getattr(cls, "_address_added", False):
            subprocess.run(
                [
                    "ip",
                    "address",
                    "delete",
                    f"{PUBLIC_TEST_ADDRESS}/32",
                    "dev",
                    "lo",
                ],
                check=False,
                capture_output=True,
            )
            cls._address_added = False
        temporary_directory = getattr(cls, "_temporary_directory", None)
        if temporary_directory is not None:
            temporary_directory.cleanup()
            cls._temporary_directory = None

    @classmethod
    def _create_certificate(cls):
        cls.ca_certificate = cls.temporary / "ca.crt"
        ca_key = cls.temporary / "ca.key"
        server_key = cls.temporary / "server.key"
        server_request = cls.temporary / "server.csr"
        cls.server_certificate = cls.temporary / "server.crt"
        extensions = cls.temporary / "server.ext"
        extensions.write_text(f"subjectAltName=DNS:{APPROVED_HOST}\n")

        commands = (
            (
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(cls.ca_certificate),
                "-subj",
                "/CN=Firstlook CI CA",
                "-days",
                "1",
            ),
            (
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(server_key),
                "-out",
                str(server_request),
                "-subj",
                f"/CN={APPROVED_HOST}",
            ),
            (
                "openssl",
                "x509",
                "-req",
                "-in",
                str(server_request),
                "-CA",
                str(cls.ca_certificate),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(cls.server_certificate),
                "-days",
                "1",
                "-sha256",
                "-extfile",
                str(extensions),
            ),
        )
        for command in commands:
            subprocess.run(command, check=True, capture_output=True)
        cls.server_key = server_key

    @classmethod
    def _start_https_server(cls):
        test_case = cls

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                test_case.requests.append((self.path, self.headers.get("Host")))
                locations = {
                    "/same-redirect": f"https://{APPROVED_HOST}/landing",
                    "/off-redirect": "https://attacker.example/landing",
                }
                status = 302 if self.path in locations else 200
                body = b"firstlook socket isolation"
                self.send_response(status)
                if self.path in locations:
                    self.send_header("Location", locations[self.path])
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                return

        cls.server = ThreadingHTTPServer((PUBLIC_TEST_ADDRESS, 443), Handler)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cls.server_certificate, cls.server_key)
        server_context.set_servername_callback(
            lambda _socket, server_name, _context: cls.server_names.append(
                server_name
            )
        )
        cls.server.socket = server_context.wrap_socket(
            cls.server.socket, server_side=True
        )
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            name="firstlook-ci-https",
            daemon=True,
        )
        cls.server_thread.start()

    def setUp(self):
        self.requests.clear()
        self.server_names.clear()

    def _connection_factory(self, hostname, pinned_ip, timeout):
        context = ssl.create_default_context(cafile=str(self.ca_certificate))
        return PinnedHTTPSConnection(
            hostname,
            pinned_ip,
            timeout=timeout,
            context=context,
        )

    def test_validated_address_is_the_socket_peer_and_tls_uses_approved_name(self):
        resolutions = []

        def rebinding_resolver(hostname, port):
            resolutions.append((hostname, port))
            return (
                (PUBLIC_TEST_ADDRESS,)
                if len(resolutions) == 1
                else ("127.0.0.1",)
            )

        boundary = FirstlookBoundary(
            APPROVED_URL,
            resolver=rebinding_resolver,
            connection_factory=self._connection_factory,
        )
        response = boundary.get(f"https://{APPROVED_HOST}/socket-proof")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(resolutions, [(APPROVED_HOST, 443)])
        self.assertEqual(self.requests, [("/socket-proof", APPROVED_HOST)])
        self.assertEqual(self.server_names, [APPROVED_HOST])

    def test_same_host_and_off_host_redirects_stop_after_one_hop(self):
        boundary = FirstlookBoundary(
            APPROVED_URL,
            resolver=lambda _hostname, _port: (PUBLIC_TEST_ADDRESS,),
            connection_factory=self._connection_factory,
        )

        same_host = boundary.get(f"https://{APPROVED_HOST}/same-redirect")
        off_host = boundary.get(f"https://{APPROVED_HOST}/off-redirect")

        self.assertEqual(same_host.status_code, 302)
        self.assertEqual(
            same_host.headers["location"],
            f"https://{APPROVED_HOST}/landing",
        )
        self.assertEqual(off_host.status_code, 302)
        self.assertEqual(
            off_host.headers["location"], "https://attacker.example/landing"
        )
        self.assertEqual(
            self.requests,
            [
                ("/same-redirect", APPROVED_HOST),
                ("/off-redirect", APPROVED_HOST),
            ],
        )

    def test_private_and_mixed_answers_open_no_socket(self):
        for answers in (
            ("127.0.0.1",),
            (PUBLIC_TEST_ADDRESS, "10.0.0.9"),
            (PUBLIC_TEST_ADDRESS, "100.64.0.1"),
        ):
            with self.subTest(answers=answers):
                boundary = FirstlookBoundary(
                    APPROVED_URL,
                    resolver=lambda _hostname, _port, result=answers: result,
                    connection_factory=self._connection_factory,
                )
                with self.assertRaises(FirstlookDNSRejected):
                    boundary.get(APPROVED_URL)

        self.assertEqual(self.requests, [])
        self.assertEqual(self.server_names, [])

    def test_certificate_hostname_verification_remains_enabled(self):
        boundary = FirstlookBoundary(
            "https://other.limitlessenterprise.ai/audit",
            resolver=lambda _hostname, _port: (PUBLIC_TEST_ADDRESS,),
            connection_factory=self._connection_factory,
        )

        with self.assertRaises(FirstlookFetchError):
            boundary.get("https://other.limitlessenterprise.ai/audit")
        self.assertEqual(self.requests, [])


@unittest.skipUnless(
    RUN_ISOLATION,
    "requires FIRSTLOOK_CI_ISOLATION=true on a disposable CI runner",
)
class FreshInstallIsolationTests(unittest.TestCase):
    """Install from empty state and drive the installed server over MCP stdio."""

    def test_clean_install_starts_exact_checkout_with_mcp_v1(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            install_directory = temporary / "install"
            librecrawl_directory = install_directory / "librecrawl"
            binary_directory = temporary / "bin"
            external_directory = temporary / "external-cwd"
            binary_directory.mkdir()
            external_directory.mkdir()
            (librecrawl_directory / ".git").mkdir(parents=True)
            (librecrawl_directory / "main.py").write_text(
                textwrap.dedent(
                    """
                    user_id = session.get('user_id')
                    session_id = session.get('session_id')
                    tier = session.get('tier', 'guest')
                    # Get or create crawler for this session
                    crawler = get_or_create_crawler()
                    """
                )
            )
            (librecrawl_directory / "docker-compose.yml").write_text(
                'ports:\n  - "${HOST_BINDING:-0.0.0.0}:5000:5000"\n'
            )

            self._write_stub(
                binary_directory / "docker",
                """
                if [[ "${1:-} ${2:-}" == "compose version" ]]; then exit 0; fi
                if [[ "${1:-}" == "compose" && "${2:-} ${3:-}" == "ps -q" ]]; then
                  echo container-id
                  exit 0
                fi
                if [[ "${1:-}" == "inspect" ]]; then echo healthy; fi
                exit 0
                """,
            )
            for name in ("git", "pm2", "sleep", "sudo", "uvx"):
                self._write_stub(binary_directory / name, "exit 0")
            self._write_stub(
                binary_directory / "curl",
                """
                output=''
                url=''
                while (( $# )); do
                  if [[ "$1" == "-o" ]]; then output="$2"; shift 2; continue; fi
                  if [[ "$1" == -* ]]; then shift; continue; fi
                  url="$1"
                  shift
                done
                if [[ -z "$output" || "$output" == "/dev/null" ]]; then exit 0; fi
                mkdir -p "$(dirname "$output")"
                if [[ "$url" == */SKILL.md ]]; then
                  printf '%s\n' '# installed test skill' > "$output"
                else
                  cp "$FIRSTLOOK_SOURCE_ROOT/${url##*/}" "$output"
                fi
                """,
            )

            environment = os.environ.copy()
            environment.update(
                {
                    "FIRSTLOOK_SOURCE_ROOT": str(ROOT),
                    "HOME": str(temporary / "home"),
                    "INSTALL_DIR": str(install_directory),
                    "PAGESPEED_API_KEY": "test-key",
                    "PATH": f"{binary_directory}:{environment['PATH']}",
                    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                    "PIP_CACHE_DIR": str(temporary / "pip-cache"),
                    "PYTHONPYCACHEPREFIX": str(temporary / "pycache"),
                }
            )
            installed = subprocess.run(
                ["bash", str(ROOT / "install.sh")],
                cwd=external_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                text=True,
                capture_output=True,
                timeout=240,
                check=False,
            )
            self.assertEqual(
                installed.returncode,
                0,
                msg=installed.stderr or installed.stdout,
            )

            mcp_directory = install_directory / "mcp-server"
            for module in MODULES:
                with self.subTest(module=module):
                    self.assertEqual(
                        _sha256(mcp_directory / module),
                        _sha256(ROOT / module),
                    )

            installed_python = mcp_directory / "venv" / "bin" / "python3"
            version_result = subprocess.run(
                [
                    str(installed_python),
                    "-c",
                    (
                        "import importlib.metadata; "
                        "print(importlib.metadata.version('mcp'))"
                    ),
                ],
                cwd=external_directory,
                env={**environment, "PYTHONPATH": ""},
                text=True,
                capture_output=True,
                timeout=30,
                check=True,
            )
            major_version = int(version_result.stdout.strip().split(".", 1)[0])
            self.assertEqual(major_version, 1)

            client_script = r'''
                import asyncio
                import json
                import os

                from mcp import ClientSession, StdioServerParameters
                from mcp.client.stdio import stdio_client

                async def main():
                    server_environment = os.environ.copy()
                    server_environment.update(
                        {
                            "FIRSTLOOK_STAGING_MODE": "true",
                            "MCP_TRANSPORT": "stdio",
                            "LIBRECRAWL_STATE_DB": os.environ["TEST_STATE_DB"],
                            "REPORTS_DIR": os.environ["TEST_REPORTS_DIR"],
                            "PYTHONPATH": "",
                        }
                    )
                    parameters = StdioServerParameters(
                        command=os.environ["INSTALLED_PYTHON"],
                        args=[os.environ["INSTALLED_SERVER"]],
                        env=server_environment,
                        cwd=os.environ["EXTERNAL_CWD"],
                    )
                    async with stdio_client(parameters) as (read, write):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            tools = await session.list_tools()
                            denial = await session.call_tool(
                                "librecrawl_site_check",
                                {
                                    "url": (
                                        "https://www.limitlessenterprise.ai/"
                                        "audit?visitor=authority"
                                    )
                                },
                            )
                            print(
                                json.dumps(
                                    {
                                        "tools": sorted(
                                            tool.name for tool in tools.tools
                                        ),
                                        "denial": "".join(
                                            getattr(item, "text", "")
                                            for item in denial.content
                                        ),
                                    }
                                )
                            )

                asyncio.run(main())
            '''
            product_environment = {
                **environment,
                "PYTHONPATH": "",
                "INSTALLED_PYTHON": str(installed_python),
                "INSTALLED_SERVER": str(mcp_directory / "server.py"),
                "EXTERNAL_CWD": str(external_directory),
                "TEST_STATE_DB": str(temporary / "installed-state.db"),
                "TEST_REPORTS_DIR": str(temporary / "installed-reports"),
            }
            product = subprocess.run(
                [
                    str(installed_python),
                    "-c",
                    textwrap.dedent(client_script),
                ],
                cwd=external_directory,
                env=product_environment,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                product.returncode,
                0,
                msg=product.stderr or product.stdout,
            )
            result = json.loads(product.stdout.strip().splitlines()[-1])
            self.assertEqual(
                result["tools"],
                ["librecrawl_schema_check", "librecrawl_site_check"],
            )
            self.assertIn("query strings are disabled", result["denial"])

    def _write_stub(self, path: Path, body: str):
        path.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n" + textwrap.dedent(body)
        )
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
