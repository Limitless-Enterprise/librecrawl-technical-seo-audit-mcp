import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class FirstlookServerModeTests(unittest.TestCase):
    def run_server_script(self, script, *, approved_url="https://audit.example/"):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temp_dir:
            env = os.environ.copy()
            env.update(
                {
                    "FIRSTLOOK_STAGING_MODE": "true",
                    "FIRSTLOOK_APPROVED_URL": approved_url,
                    "LIBRECRAWL_STATE_DB": str(Path(temp_dir) / "state.db"),
                    "REPORTS_DIR": str(Path(temp_dir) / "reports"),
                }
            )
            return subprocess.run(
                [sys.executable, "-c", textwrap.dedent(script)],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

    def test_server_startup_fails_closed_without_approved_url(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temp_dir:
            env = os.environ.copy()
            env.pop("FIRSTLOOK_APPROVED_URL", None)
            env.update(
                {
                    "FIRSTLOOK_STAGING_MODE": "true",
                    "LIBRECRAWL_STATE_DB": str(Path(temp_dir) / "state.db"),
                }
            )
            result = subprocess.run(
                [sys.executable, "-c", "import server"],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FIRSTLOOK_APPROVED_URL is required", result.stderr)

    def test_general_mode_remains_the_default(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temp_dir:
            env = os.environ.copy()
            env.pop("FIRSTLOOK_APPROVED_URL", None)
            env.update(
                {
                    "FIRSTLOOK_STAGING_MODE": "false",
                    "LIBRECRAWL_STATE_DB": str(Path(temp_dir) / "state.db"),
                    "REPORTS_DIR": str(Path(temp_dir) / "reports"),
                }
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import server; "
                        "assert server.FIRSTLOOK_STAGING_MODE is False; "
                        "assert server.FIRSTLOOK_BOUNDARY is None; "
                        "assert server._runner._runner_thread.is_alive(); "
                        "server._runner.stop_runner()"
                    ),
                ],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)

    def test_only_bounded_site_and_schema_requests_can_reach_transport(self):
        result = self.run_server_script(
            r'''
            import server
            from firstlook_security import FirstlookBoundary

            PUBLIC_IP = "93.184.216.34"
            attempts = []

            class Response:
                status = 200
                def __init__(self, body):
                    self.body = body
                def read(self, _limit):
                    return self.body
                def getheaders(self):
                    return [("content-type", "text/html; charset=utf-8")]

            class Connection:
                def __init__(self, host, ip, timeout):
                    self.host = host
                    self.ip = ip
                    self.timeout = timeout
                    self.path = None
                def request(self, method, path, headers):
                    self.path = path
                    attempts.append((self.host, self.ip, method, path, headers["Host"]))
                def getresponse(self):
                    if self.path == "/robots.txt":
                        return Response(b"User-agent: *\nSitemap: https://audit.example/sitemap.xml")
                    if self.path == "/sitemap.xml":
                        return Response(b"<urlset><url><loc>https://audit.example/</loc></url></urlset>")
                    return Response(
                        b'<script type="application/ld+json">'
                        b'{"@type":"Organization","name":"Tower"}'
                        b'</script>'
                    )
                def close(self):
                    pass

            server.FIRSTLOOK_BOUNDARY = FirstlookBoundary(
                "https://audit.example/",
                resolver=lambda _host, _port: (PUBLIC_IP,),
                connection_factory=Connection,
            )
            server.httpx.get = lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("legacy httpx transport was reached")
            )
            server.call = lambda *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("LibreCrawl engine was reached")
            )

            assert server._runner._runner_thread is None

            assert server.librecrawl_site_check("https://off-host.example/")["success"] is False
            assert server.librecrawl_schema_check("https://audit.example/?visitor=url")["success"] is False
            assert attempts == []

            site = server.librecrawl_site_check("https://audit.example/")
            assert site["robots_txt"]["found"] is True
            assert site["sitemap"]["found"] is True
            assert site["https_redirect"]["skipped"] is True
            assert site["www_redirect"]["skipped"] is True

            schema = server.librecrawl_schema_check("https://audit.example/")
            assert schema["types_found"] == ["Organization"]
            assert all(attempt[1] == PUBLIC_IP for attempt in attempts)
            assert all(attempt[4] == "audit.example" for attempt in attempts)

            blocked = (
                server.librecrawl_audit("https://audit.example/"),
                server.librecrawl_generate_report(),
                server.librecrawl_start_crawl("https://audit.example/"),
                server.librecrawl_get_status(),
                server.librecrawl_export_results(),
                server.librecrawl_list_crawls(),
                server.librecrawl_stop_crawl(),
                server.librecrawl_pause_crawl(),
                server.librecrawl_resume_crawl(),
                server.librecrawl_resume_from_crawl_id(1),
                server.librecrawl_get_settings(),
                server.librecrawl_filter_issues([]),
                server.librecrawl_visualization_data(),
                server.librecrawl_internal_links_analysis(),
                server.librecrawl_start_chunked_audit("https://audit.example/"),
                server.librecrawl_audit_status("session"),
                server.librecrawl_audit_artifacts("session"),
                server.librecrawl_audit_pause("session"),
                server.librecrawl_audit_resume("session"),
                server.librecrawl_audit_cancel("session"),
                server.librecrawl_audit_force_advance("session"),
                server.librecrawl_full_audit_strict("https://audit.example/"),
                server.librecrawl_report_content("missing.md"),
                server.librecrawl_audit_pdf("missing.md"),
                server.librecrawl_pagespeed("https://audit.example/"),
                server.librecrawl_pagespeed_audit(["https://audit.example/"]),
                server.librecrawl_pagespeed_audit_all_crawl_pages(1),
                server.librecrawl_schema_audit(["https://audit.example/"]),
                server.librecrawl_schema_validate(1),
                server.librecrawl_external_links_audit(1),
                server.librecrawl_append_gsc_section("missing.md", {}),
                server.librecrawl_merge_gsc_data(1, {}),
                server.librecrawl_brain_purge_audit(1),
                server.librecrawl_audit_zip("session"),
                server.librecrawl_wipe_everything(),
            )
            assert all(item["success"] is False for item in blocked)
            assert all(item["firstlook_staging_mode"] is True for item in blocked)
            '''
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
