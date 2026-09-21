"""Fail-closed network boundary for the attended Firstlook staging mode.

This module intentionally uses only the Python standard library.  It resolves
the configured hostname once, rejects the complete answer set when any address
is non-public, and passes a validated numeric address directly to the socket
connection.  TLS still authenticates the configured hostname through SNI and
normal certificate verification.
"""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import os
import socket
import ssl
import time
from typing import Callable, Mapping, Sequence
from urllib.parse import SplitResult, urlsplit, urlunsplit


FIRSTLOOK_MODE_ENV = "FIRSTLOOK_STAGING_MODE"
FIRSTLOOK_APPROVED_URL = "https://www.limitlessenterprise.ai/audit"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})
_INTERNAL_HOST_SUFFIXES = (
    ".corp",
    ".home",
    ".internal",
    ".intranet",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
    ".private",
    ".svc",
)
_INTERNAL_HOSTS = frozenset(
    {
        "instance-data.ec2.internal",
        "localhost",
        "metadata",
        "metadata.google.internal",
    }
)
_CLOUD_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("100.100.100.200"),  # Alibaba
        ipaddress.ip_address("169.254.169.254"),  # AWS/Azure/GCP and others
        ipaddress.ip_address("fd00:ec2::254"),    # AWS IMDS IPv6
        ipaddress.ip_address("fe80::a9fe:a9fe"),  # Link-local IPv6 form
    }
)
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class FirstlookBoundaryError(RuntimeError):
    """Base class for a denied or failed Firstlook request."""


class FirstlookConfigurationError(FirstlookBoundaryError):
    """The opt-in mode was enabled without a valid fixed URL."""


class FirstlookURLRejected(FirstlookBoundaryError):
    """A submitted or derived URL is outside the staging policy."""


class FirstlookDNSRejected(FirstlookBoundaryError):
    """DNS returned an unsafe or unusable destination."""


class FirstlookFetchError(FirstlookBoundaryError):
    """The pinned HTTPS request could not be completed safely."""


@dataclass(frozen=True)
class ValidatedURL:
    normalized: str
    hostname: str
    path: str


@dataclass(frozen=True)
class PinnedResponse:
    """Small response surface used by the two attended staging checks."""

    url: str
    status_code: int
    headers: Mapping[str, str]
    body: bytes

    @property
    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        encoding = "utf-8"
        for part in content_type.split(";")[1:]:
            key, separator, value = part.strip().partition("=")
            if separator and key.lower() == "charset" and value.strip():
                encoding = value.strip().strip('"\'')
                break
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection whose TCP peer is an already-validated IP address."""

    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        *,
        timeout: float,
        context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(
            hostname,
            port=443,
            timeout=timeout,
            context=context or ssl.create_default_context(),
        )
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        # Do not call HTTPSConnection.connect(): it resolves self.host again.
        raw_socket = socket.create_connection(
            (self.pinned_ip, 443),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        try:
            # self.host is the approved DNS name, not the pinned numeric peer.
            # create_default_context() keeps hostname and certificate checks on.
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


Resolver = Callable[[str, int], Sequence[str]]
ConnectionFactory = Callable[[str, str, float], http.client.HTTPSConnection]


def parse_firstlook_mode(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    raw = str(env.get(FIRSTLOOK_MODE_ENV, "")).strip().lower()
    if raw in _TRUE_VALUES:
        return True
    if raw in _FALSE_VALUES:
        return False
    raise FirstlookConfigurationError(
        f"{FIRSTLOOK_MODE_ENV} must be one of: 1, true, yes, on, 0, false, no, off"
    )


def _reject_control_characters(url: str) -> None:
    if not isinstance(url, str) or not url:
        raise FirstlookURLRejected("URL must be a non-empty string")
    if "\\" in url or any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise FirstlookURLRejected("URL contains a backslash or control character")


def _normalise_hostname(split: SplitResult) -> str:
    if "@" in split.netloc:
        raise FirstlookURLRejected("credentials are not allowed")
    try:
        hostname = split.hostname
        port = split.port
    except ValueError as exc:
        raise FirstlookURLRejected(f"invalid host or port: {exc}") from exc
    if not hostname:
        raise FirstlookURLRejected("URL must include a hostname")
    if port not in (None, 443):
        raise FirstlookURLRejected("only TCP port 443 is allowed")
    if "%" in hostname:
        raise FirstlookURLRejected("IPv6 zone identifiers are not allowed")

    candidate = hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise FirstlookURLRejected("hostname is not valid IDNA") from exc
        if candidate in _INTERNAL_HOSTS or candidate.endswith(_INTERNAL_HOST_SUFFIXES):
            raise FirstlookURLRejected(f"internal hostname is not allowed: {candidate}")
        if "." not in candidate:
            raise FirstlookURLRejected("single-label/internal hostnames are not allowed")
        labels = candidate.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (char.isalnum() or char == "-") for char in label)
            for label in labels
        ):
            raise FirstlookURLRejected("hostname is malformed")
    else:
        candidate = address.compressed
    return candidate


def validate_https_url(url: str) -> ValidatedURL:
    """Validate and deterministically normalize a Firstlook URL."""
    _reject_control_characters(url)
    if "?" in url:
        raise FirstlookURLRejected("query strings are disabled in Firstlook staging")
    if "#" in url:
        raise FirstlookURLRejected("URL fragments are not allowed")
    try:
        split = urlsplit(url)
    except ValueError as exc:
        raise FirstlookURLRejected(f"invalid URL: {exc}") from exc
    if split.scheme.lower() != "https":
        raise FirstlookURLRejected("only HTTPS URLs are allowed")
    hostname = _normalise_hostname(split)
    path = split.path or "/"
    if (
        not path.startswith("/")
        or " " in path
        or any(ord(char) > 127 for char in path)
    ):
        raise FirstlookURLRejected("path must be an ASCII absolute path")
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    normalized = urlunsplit(("https", netloc, path, "", ""))
    return ValidatedURL(normalized=normalized, hostname=hostname, path=path)


def _address_rejection_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if address in _CLOUD_METADATA_ADDRESSES:
        return "cloud metadata"
    if isinstance(address, ipaddress.IPv4Address) and address in _CGNAT_NETWORK:
        return "CGNAT/Tailscale"
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return "non-public"
    return None


def resolve_public_addresses(hostname: str, port: int = 443) -> tuple[str, ...]:
    """Resolve once and reject the entire answer set if any IP is unsafe."""
    try:
        answers = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise FirstlookDNSRejected(f"DNS resolution failed for {hostname}: {exc}") from exc

    addresses: list[str] = []
    for _family, _socktype, _proto, _canonname, sockaddr in answers:
        raw_address = sockaddr[0]
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise FirstlookDNSRejected(f"DNS returned an invalid address: {raw_address}") from exc
        reason = _address_rejection_reason(address)
        if reason:
            raise FirstlookDNSRejected(
                f"DNS for {hostname} returned prohibited {reason} address {address.compressed}"
            )
        if address.compressed not in addresses:
            addresses.append(address.compressed)

    if not addresses:
        raise FirstlookDNSRejected(f"DNS returned no A or AAAA addresses for {hostname}")
    return tuple(addresses)


def _default_connection_factory(
    hostname: str, pinned_ip: str, timeout: float
) -> PinnedHTTPSConnection:
    return PinnedHTTPSConnection(hostname, pinned_ip, timeout=timeout)


class FirstlookBoundary:
    """Exact-URL authorization plus same-host, DNS-pinned HTTPS requests."""

    def __init__(
        self,
        approved_url: str,
        *,
        resolver: Resolver = resolve_public_addresses,
        connection_factory: ConnectionFactory = _default_connection_factory,
        max_body_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        approved = validate_https_url(approved_url)
        try:
            literal_address = ipaddress.ip_address(approved.hostname)
        except ValueError:
            pass
        else:
            reason = _address_rejection_reason(literal_address)
            if reason:
                raise FirstlookURLRejected(
                    f"approved URL contains prohibited {reason} address "
                    f"{literal_address.compressed}"
                )
        self.approved_url = approved.normalized
        self.approved_hostname = approved.hostname
        self._resolver = resolver
        self._connection_factory = connection_factory
        self._max_body_bytes = max_body_bytes

    def authorize_tool_url(self, submitted_url: str) -> str:
        candidate = validate_https_url(submitted_url)
        if candidate.normalized != self.approved_url:
            raise FirstlookURLRejected(
                "tool URL does not exactly match the hard-coded approved URL"
            )
        return self.approved_url

    def validate_same_host_url(self, url: str) -> ValidatedURL:
        candidate = validate_https_url(url)
        if candidate.hostname != self.approved_hostname:
            raise FirstlookURLRejected(
                f"hostname {candidate.hostname!r} is not the approved hostname"
            )
        return candidate

    def get(
        self,
        url: str,
        *,
        timeout: float = 15.0,
        deadline: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> PinnedResponse:
        """GET one same-host URL without redirect handling or a second DNS lookup."""
        target = self.validate_same_host_url(url)
        addresses = tuple(self._resolver(target.hostname, 443))
        if not addresses:
            raise FirstlookDNSRejected(
                f"DNS returned no A or AAAA addresses for {target.hostname}"
            )
        validated_addresses: list[str] = []
        for raw_address in addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise FirstlookDNSRejected(
                    f"resolver returned invalid address {raw_address!r}"
                ) from exc
            reason = _address_rejection_reason(address)
            if reason:
                # Reject the complete answer set before opening any socket.
                raise FirstlookDNSRejected(
                    f"resolver returned prohibited {reason} address "
                    f"{address.compressed}"
                )
            if address.compressed not in validated_addresses:
                validated_addresses.append(address.compressed)

        host_header = (
            f"[{target.hostname}]" if ":" in target.hostname else target.hostname
        )
        request_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml,text/plain;q=0.9,*/*;q=0.8",
            "Connection": "close",
            "Host": host_header,
            "User-Agent": "LibreCrawl-Firstlook/1.0",
        }
        if headers:
            request_headers.update(headers)
        # Caller-supplied headers must not change the authenticated authority.
        request_headers["Host"] = host_header

        failures: list[str] = []
        for pinned_ip in validated_addresses:
            attempt_timeout = timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FirstlookFetchError("request deadline exceeded")
                attempt_timeout = min(timeout, remaining)
            connection = self._connection_factory(
                target.hostname, pinned_ip, attempt_timeout
            )
            try:
                connection.request("GET", target.path, headers=request_headers)
                response = connection.getresponse()
                body = response.read(self._max_body_bytes + 1)
                if len(body) > self._max_body_bytes:
                    raise FirstlookFetchError(
                        f"response exceeded {self._max_body_bytes} byte limit"
                    )
                response_headers = {
                    key.lower(): value for key, value in response.getheaders()
                }
                # Redirects are returned to the caller as 3xx and never followed.
                return PinnedResponse(
                    url=target.normalized,
                    status_code=response.status,
                    headers=response_headers,
                    body=body,
                )
            except FirstlookFetchError:
                raise
            except Exception as exc:
                failures.append(f"{pinned_ip}: {type(exc).__name__}: {exc}")
            finally:
                connection.close()

        detail = "; ".join(failures) or "no connection attempts"
        raise FirstlookFetchError(f"pinned HTTPS request failed: {detail}")


def load_firstlook_boundary(
    environ: Mapping[str, str] | None = None,
) -> tuple[bool, FirstlookBoundary | None]:
    """Load the opt-in mode and fail startup closed on invalid configuration."""
    enabled = parse_firstlook_mode(environ)
    if not enabled:
        return False, None
    return True, FirstlookBoundary(FIRSTLOOK_APPROVED_URL)
