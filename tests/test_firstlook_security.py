import socket
import ssl
import unittest
from unittest import mock

from firstlook_security import (
    FIRSTLOOK_APPROVED_URL,
    FirstlookBoundary,
    FirstlookConfigurationError,
    FirstlookDNSRejected,
    FirstlookFetchError,
    FirstlookURLRejected,
    PinnedHTTPSConnection,
    load_firstlook_boundary,
    resolve_public_addresses,
)


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


class FakeHTTPResponse:
    def __init__(self, status=200, body=b"ok", headers=None):
        self.status = status
        self._body = body
        self._headers = list((headers or {}).items())

    def read(self, _limit):
        return self._body

    def getheaders(self):
        return self._headers


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def dns_answer(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


class FirstlookConfigurationTests(unittest.TestCase):
    def test_mode_is_explicit_opt_in(self):
        self.assertEqual(load_firstlook_boundary({}), (False, None))

    def test_enabled_mode_uses_only_hard_coded_approved_url(self):
        enabled, boundary = load_firstlook_boundary(
            {
                "FIRSTLOOK_STAGING_MODE": "true",
                "FIRSTLOOK_APPROVED_URL": "https://attacker.example/",
            }
        )

        self.assertTrue(enabled)
        self.assertEqual(boundary.approved_url, FIRSTLOOK_APPROVED_URL)
        with self.assertRaises(FirstlookURLRejected):
            boundary.authorize_tool_url("https://limitlessenterprise.ai/audit")
        with self.assertRaises(FirstlookURLRejected):
            boundary.authorize_tool_url("https://attacker.example/")

    def test_invalid_boolean_fails_closed(self):
        for value in (
            "sometimes",
            "1",
            "yes",
            "on",
            "0",
            "no",
            "off",
            "TRUE",
            " true ",
        ):
            with self.subTest(value=value), self.assertRaises(
                FirstlookConfigurationError
            ):
                load_firstlook_boundary({"FIRSTLOOK_STAGING_MODE": value})

    def test_literal_false_disables_mode(self):
        self.assertEqual(
            load_firstlook_boundary({"FIRSTLOOK_STAGING_MODE": "false"}),
            (False, None),
        )

    def test_direct_private_ipv4_and_ipv6_are_rejected_at_configuration(self):
        for url in (
            "https://127.0.0.1/",
            "https://10.1.2.3/",
            "https://169.254.169.254/",
            "https://100.64.0.1/",
            "https://[::1]/",
            "https://[fd00::1]/",
            "https://[fe80::1]/",
        ):
            with self.subTest(url=url), self.assertRaises(FirstlookURLRejected):
                FirstlookBoundary(url)


class URLPolicyTests(unittest.TestCase):
    def setUp(self):
        self.boundary = FirstlookBoundary("https://Audit.Example:443/")

    def test_normalized_exact_url_is_authorized(self):
        self.assertEqual(
            self.boundary.authorize_tool_url("HTTPS://audit.example/"),
            "https://audit.example/",
        )

    def test_exact_host_and_path_must_match(self):
        for url in (
            "https://www.audit.example/",
            "https://audit.example/other",
            "https://audit.example.evil.test/",
        ):
            with self.subTest(url=url), self.assertRaises(FirstlookURLRejected):
                self.boundary.authorize_tool_url(url)

    def test_scheme_port_credentials_query_and_fragment_are_rejected(self):
        for url in (
            "http://audit.example/",
            "https://audit.example:444/",
            "https://user:pass@audit.example/",
            "https://audit.example/?visitor=authority",
            "https://audit.example/?",
            "https://audit.example/#fragment",
            "https://audit.example/#",
            "https://audit.example/path with space",
        ):
            with self.subTest(url=url), self.assertRaises(FirstlookURLRejected):
                self.boundary.authorize_tool_url(url)

    def test_obvious_internal_names_are_rejected(self):
        for url in (
            "https://localhost/",
            "https://metadata.google.internal/",
            "https://service.internal/",
            "https://printer/",
        ):
            with self.subTest(url=url), self.assertRaises(FirstlookURLRejected):
                FirstlookBoundary(url)


class DNSPolicyTests(unittest.TestCase):
    def assert_dns_rejected(self, *addresses):
        with mock.patch(
            "firstlook_security.socket.getaddrinfo",
            return_value=[dns_answer(address) for address in addresses],
        ):
            with self.assertRaises(FirstlookDNSRejected):
                resolve_public_addresses("audit.example")

    def test_public_ipv4_and_ipv6_answers_are_accepted(self):
        with mock.patch(
            "firstlook_security.socket.getaddrinfo",
            return_value=[dns_answer(PUBLIC_V4), dns_answer(PUBLIC_V6)],
        ):
            self.assertEqual(
                resolve_public_addresses("audit.example"),
                (PUBLIC_V4, PUBLIC_V6),
            )

    def test_private_loopback_link_local_reserved_and_unspecified_are_rejected(self):
        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::",
            "ff02::1",
        ):
            with self.subTest(address=address):
                self.assert_dns_rejected(address)

    def test_metadata_and_tailscale_cgnat_are_rejected(self):
        for address in (
            "169.254.169.254",
            "100.100.100.200",
            "100.64.0.1",
            "100.127.255.254",
            "fd00:ec2::254",
        ):
            with self.subTest(address=address):
                self.assert_dns_rejected(address)

    def test_mixed_public_private_answer_rejects_the_entire_set(self):
        self.assert_dns_rejected(PUBLIC_V4, "10.0.0.9")


class PinnedTransportTests(unittest.TestCase):
    def test_transport_receives_only_resolved_validated_address(self):
        attempts = []
        connection = FakeConnection(FakeHTTPResponse(body=b"safe"))

        def connection_factory(hostname, pinned_ip, timeout):
            attempts.append((hostname, pinned_ip, timeout))
            return connection

        boundary = FirstlookBoundary(
            "https://audit.example/",
            resolver=lambda _host, _port: (PUBLIC_V4,),
            connection_factory=connection_factory,
        )
        response = boundary.get("https://audit.example/robots.txt", timeout=7)

        self.assertEqual(response.body, b"safe")
        self.assertEqual(attempts, [("audit.example", PUBLIC_V4, 7)])
        self.assertEqual(connection.requests[0][0:2], ("GET", "/robots.txt"))
        self.assertEqual(connection.requests[0][2]["Host"], "audit.example")

    def test_dns_rebinding_has_no_second_resolution_at_connect_time(self):
        resolutions = []
        attempts = []

        def rebinding_resolver(_host, _port):
            resolutions.append(True)
            return (PUBLIC_V4,) if len(resolutions) == 1 else ("127.0.0.1",)

        def connection_factory(hostname, pinned_ip, timeout):
            attempts.append((hostname, pinned_ip, timeout))
            return FakeConnection(FakeHTTPResponse())

        boundary = FirstlookBoundary(
            "https://audit.example/",
            resolver=rebinding_resolver,
            connection_factory=connection_factory,
        )
        boundary.get("https://audit.example/")

        self.assertEqual(len(resolutions), 1)
        self.assertEqual(attempts[0][1], PUBLIC_V4)

    def test_deadline_limits_connection_timeout_and_stops_expired_request(self):
        attempts = []

        def connection_factory(hostname, pinned_ip, timeout):
            attempts.append((hostname, pinned_ip, timeout))
            return FakeConnection(FakeHTTPResponse())

        boundary = FirstlookBoundary(
            "https://audit.example/",
            resolver=lambda _host, _port: (PUBLIC_V4,),
            connection_factory=connection_factory,
        )
        with mock.patch("firstlook_security.time.monotonic", return_value=103):
            boundary.get("https://audit.example/", timeout=15, deadline=105)

        self.assertEqual(attempts[0][2], 2)

        with mock.patch("firstlook_security.time.monotonic", return_value=106):
            with self.assertRaisesRegex(FirstlookFetchError, "deadline exceeded"):
                boundary.get("https://audit.example/", deadline=105)
        self.assertEqual(len(attempts), 1)

    def test_rejected_input_and_dns_answers_make_no_outbound_request(self):
        attempts = []

        def connection_factory(*args):
            attempts.append(args)
            return FakeConnection(FakeHTTPResponse())

        mismatch_boundary = FirstlookBoundary(
            "https://audit.example/",
            resolver=lambda _host, _port: (PUBLIC_V4,),
            connection_factory=connection_factory,
        )
        with self.assertRaises(FirstlookURLRejected):
            mismatch_boundary.get("https://off-host.example/")

        for answers in (
            ("192.168.1.10",),
            (PUBLIC_V4, "192.168.1.10"),
            ("not-an-ip",),
        ):
            with self.subTest(answers=answers):
                private_dns_boundary = FirstlookBoundary(
                    "https://audit.example/",
                    resolver=lambda _host, _port, answers=answers: answers,
                    connection_factory=connection_factory,
                )
                with self.assertRaises(FirstlookDNSRejected):
                    private_dns_boundary.get("https://audit.example/")

        self.assertEqual(attempts, [])

    def test_same_host_and_off_host_redirects_are_never_followed(self):
        for location in (
            "https://audit.example/next",
            "https://attacker.example/next",
        ):
            with self.subTest(location=location):
                attempts = []

                def connection_factory(hostname, pinned_ip, timeout):
                    attempts.append((hostname, pinned_ip, timeout))
                    return FakeConnection(
                        FakeHTTPResponse(302, headers={"Location": location})
                    )

                boundary = FirstlookBoundary(
                    "https://audit.example/",
                    resolver=lambda _host, _port: (PUBLIC_V4,),
                    connection_factory=connection_factory,
                )
                response = boundary.get("https://audit.example/")
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers["location"], location)
                self.assertEqual(len(attempts), 1)

    def test_socket_is_pinned_while_tls_uses_approved_sni(self):
        raw_socket = mock.Mock()
        tls_socket = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = tls_socket
        connection = PinnedHTTPSConnection(
            "audit.example", PUBLIC_V4, timeout=3, context=context
        )

        with mock.patch(
            "firstlook_security.socket.create_connection", return_value=raw_socket
        ) as create_connection:
            connection.connect()

        create_connection.assert_called_once_with(
            (PUBLIC_V4, 443), timeout=3, source_address=None
        )
        context.wrap_socket.assert_called_once_with(
            raw_socket, server_hostname="audit.example"
        )
        self.assertIs(connection.sock, tls_socket)

    def test_default_tls_context_verifies_hostname_and_certificate(self):
        connection = PinnedHTTPSConnection(
            "audit.example", PUBLIC_V4, timeout=3
        )
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
