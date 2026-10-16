import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MCP_SOURCE_BASE_URL = (
    "https://raw.githubusercontent.com/Limitless-Enterprise/"
    "librecrawl-technical-seo-audit-mcp/"
    "5f6608f47d0529eeef87562899fccbc1d448c928"
)


@unittest.skipUnless(shutil.which("docker"), "requires Docker Compose")
class ComposeConfigurationTests(unittest.TestCase):
    def test_mode_preserves_absent_empty_and_literal_values(self):
        from firstlook_security import FirstlookConfigurationError, load_firstlook_boundary

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            empty_env = Path(temporary_directory) / "empty.env"
            empty_env.write_text("")
            for value in (None, "", "true", "false"):
                with self.subTest(value=value):
                    environment = os.environ.copy()
                    environment.pop("FIRSTLOOK_STAGING_MODE", None)
                    if value is not None:
                        environment["FIRSTLOOK_STAGING_MODE"] = value
                    result = subprocess.run(
                        ["docker", "compose", "--env-file", str(empty_env),
                         "-f", str(ROOT / "docker-compose.yml"),
                         "config", "--format", "json"],
                        cwd=ROOT, env=environment,
                        capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, msg=result.stderr)
                    configured = json.loads(result.stdout)["services"]["mcp"]["environment"]
                    self.assertEqual(configured["FIRSTLOOK_STAGING_MODE"],
                                     "false" if value is None else value)
                    if value == "":
                        with self.assertRaises(FirstlookConfigurationError):
                            load_firstlook_boundary(configured)
                    else:
                        enabled, boundary = load_firstlook_boundary(configured)
                        self.assertEqual(enabled, value == "true")
                        if enabled:
                            self.assertEqual(boundary.approved_url,
                                             "https://limitlessenterprise.ai/audit")
                        else:
                            self.assertIsNone(boundary)


class InstallerTests(unittest.TestCase):
    def test_installs_firstlook_module_and_mcp_v1(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            install_directory = temporary / "install"
            librecrawl_directory = install_directory / "librecrawl"
            binary_directory = temporary / "bin"
            log_path = temporary / "commands.log"
            binary_directory.mkdir()
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
                if [[ "$1 $2" == "compose version" ]]; then exit 0; fi
                if [[ "$1" == "compose" && "$2 $3" == "ps -q" ]]; then
                  echo container-id
                  exit 0
                fi
                if [[ "$1" == "inspect" ]]; then echo healthy; fi
                """,
            )
            self._write_stub(binary_directory / "git", "exit 0")
            self._write_stub(binary_directory / "pm2", "exit 0")
            self._write_stub(binary_directory / "sleep", "exit 0")
            self._write_stub(binary_directory / "uvx", "exit 0")
            self._write_stub(
                binary_directory / "sudo",
                """
                printf 'sudo %s\\n' "$*" >> "$INSTALLER_TEST_LOG"
                exit 0
                """,
            )
            self._write_stub(
                binary_directory / "apt-get",
                """
                printf 'apt-get %s\\n' "$*" >> "$INSTALLER_TEST_LOG"
                exit 0
                """,
            )
            self._write_stub(
                binary_directory / "curl",
                """
                printf 'curl %s\\n' "$*" >> "$INSTALLER_TEST_LOG"
                output=''
                url=''
                while (( $# )); do
                  if [[ "$1" == "-o" ]]; then output="$2"; shift 2; continue; fi
                  if [[ "$1" != -* ]]; then url="$1"; fi
                  shift
                done
                if [[ -n "$output" && "$output" != "/dev/null" &&
                      "$url" != "$EXPECTED_MCP_SOURCE_BASE_URL/"* ]]; then
                  exit 22
                fi
                if [[ -n "$output" && "$output" != "/dev/null" ]]; then
                  mkdir -p "$(dirname "$output")"
                  printf '# downloaded fixture\\n' > "$output"
                fi
                """,
            )
            self._write_python_stub(binary_directory / "python3")

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(temporary / "home"),
                    "INSTALL_DIR": str(install_directory),
                    "INSTALLER_TEST_LOG": str(log_path),
                    "EXPECTED_MCP_SOURCE_BASE_URL": MCP_SOURCE_BASE_URL,
                    "PAGESPEED_API_KEY": "test-key",
                    "PATH": f"{binary_directory}:{environment['PATH']}",
                }
            )
            subprocess.run(
                ["bash", str(ROOT / "install.sh")],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )

            command_log = log_path.read_text()
            self.assertIn(
                f"{MCP_SOURCE_BASE_URL}/firstlook_security.py", command_log
            )
            self.assertTrue(
                (install_directory / "mcp-server" / "firstlook_security.py").is_file()
            )
            self.assertIn("pip install --quiet mcp>=1.0.0,<2", command_log)
            self.assertIn("sudo apt-get install", command_log)
            self.assertNotIn("\napt-get ", command_log)

    def _write_stub(self, path, body):
        path.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n" + textwrap.dedent(body)
        )
        path.chmod(0o755)

    def _write_python_stub(self, path):
        self._write_stub(
            path,
            f"""
            if [[ "${{1:-}} ${{2:-}}" == "-m venv" ]]; then
              venv="$3"
              mkdir -p "$venv/bin"
              cat > "$venv/bin/pip" <<'EOF'
            #!/usr/bin/env bash
            printf 'pip %s\\n' "$*" >> "$INSTALLER_TEST_LOG"
            EOF
              chmod +x "$venv/bin/pip"
              ln -s {sys.executable!s} "$venv/bin/python3"
              exit 0
            fi
            exec {sys.executable!s} "$@"
            """,
        )


if __name__ == "__main__":
    unittest.main()
