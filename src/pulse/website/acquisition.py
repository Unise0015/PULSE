"""Bounded HTTP observations shared by all website detection paths."""

import re
import ipaddress
import socket
import ssl
import time
import zlib
from typing import Tuple
from urllib.parse import urlparse

import httpx
import httpcore


def normalize_website_url(url: str) -> str:
    """Allow bare host names while preserving explicit schemes for validation."""
    url = url.strip()
    if not url:
        return ""
    if url.startswith("//"):
        return "https:" + url
    scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", url)
    host_port = re.match(r"^[^/:]+:[0-9]+(?:[/?#]|$)", url)
    if scheme and not host_port:
        return url
    return "https://" + url


def validate_url(url: str, external_only: bool = False) -> Tuple[bool, str]:
    """Pre-request URL validator. Rejects malformed URLs and unsupported protocols."""
    if not url or not isinstance(url, str) or not url.strip():
        return False, "Invalid URL: Empty target string provided"

    raw_url = url.strip()
    try:
        parsed = urlparse(raw_url)
        parsed.port  # Validate numeric ports and the legal port range before HTTPX.
    except Exception as e:
        return False, f"Invalid URL structure: {e}"

    if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only http:// and https:// protocols are supported."

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: Missing hostname or domain"

    if external_only:
        normalized_host = hostname.lower().rstrip(".")
        if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
            return False, f"External-only policy enforced: Target '{hostname}' is localhost/loopback"

        try:
            ip = ipaddress.ip_address(hostname)
            if not ip.is_global or ip.is_multicast:
                return False, f"External-only policy enforced: Target '{hostname}' is a private or internal IP"
        except ValueError:
            pass

    return True, "URL is valid"

class WebsiteURLPolicyError(ValueError):
    """A website request or redirect was rejected before sending it."""


class _PublicNetworkBackend(httpcore.SyncBackend):
    """Resolve once, reject non-public answers, and connect to a checked literal IP."""

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        started = time.monotonic()
        try:
            answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise httpcore.ConnectError(str(exc)) from exc
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses:
            raise httpcore.ConnectError("Hostname returned no addresses")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global or ip.is_multicast:
                raise WebsiteURLPolicyError(f"External-only policy blocked a non-public address for {host}")
        last_error = None
        for address in addresses:
            remaining = None if timeout is None else timeout - (time.monotonic() - started)
            if remaining is not None and remaining <= 0:
                raise httpcore.ConnectTimeout("Website connection timed out")
            try:
                # The origin stays unchanged in HTTPX/HTTPCore, preserving Host and TLS SNI.
                return super().connect_tcp(address, port, timeout=remaining,
                                           local_address=local_address, socket_options=socket_options)
            except httpcore.ConnectError as exc:
                last_error = exc
        raise last_error


class _ExternalOnlyTransport(httpx.HTTPTransport):
    """Isolate HTTPCore backend customization; dependency versions are bounded."""

    def __init__(self):
        super().__init__(trust_env=False)
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(), network_backend=_PublicNetworkBackend())


class _LimitedDecoder:
    def __init__(self, encoding, limit):
        self.encoding = encoding
        self.remaining = limit
        self.first = True
        self.decoder = None
        if encoding in ("gzip", "deflate"):
            self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
        elif encoding != "identity":
            raise httpx.DecodingError(f"Unsupported website content encoding: {encoding}")

    def decode(self, chunk):
        if not chunk or not self.remaining:
            return b""
        if self.decoder is None:
            output = chunk[:self.remaining]
        else:
            first, self.first = self.first, False
            try:
                output = self.decoder.decompress(chunk, self.remaining)
            except zlib.error as exc:
                if self.encoding != "deflate" or not first:
                    raise httpx.DecodingError(str(exc)) from exc
                self.decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                try:
                    output = self.decoder.decompress(chunk, self.remaining)
                except zlib.error as raw_exc:
                    raise httpx.DecodingError(str(raw_exc)) from raw_exc
        self.remaining -= len(output)
        return output


def _read_bounded_body(response, limit):
    # Synthetic/pre-buffered HTTPX responses have already been decoded by their owner.
    if response.is_stream_consumed:
        return response.content[:limit], len(response.content) > limit
    encodings = [item.strip().lower() for item in response.headers.get("content-encoding", "identity").split(",") if item.strip()] or ["identity"]
    if len(encodings) > 8:
        raise httpx.DecodingError("Too many nested website content encodings")
    decoders = [_LimitedDecoder(encoding, limit) for encoding in reversed(encodings)]
    body = bytearray()
    limited = False
    for chunk in response.iter_raw(chunk_size=8192):
        for decoder in decoders:
            chunk = decoder.decode(chunk)
        body.extend(chunk)
        if any(decoder.remaining == 0 for decoder in decoders):
            limited = True
            break
    if not limited and any(decoder.decoder is not None and not decoder.decoder.eof for decoder in decoders):
        raise httpx.DecodingError("Incomplete compressed website response")
    return bytes(body), limited


def fetch_observation(url, *, timeout, max_bytes, headers=None, follow_redirects=True, external_only=False):
    """Read a bounded decoded body, validating each request before sending it.

    Follow HTTPX's prepared redirect requests so cookie and authorization handling
    stay consistent, but enforce URL policy before any redirect leaves the client.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    client_options = {"timeout": timeout, "follow_redirects": False}
    if external_only:
        # An environment proxy could resolve the target itself and bypass the checked address.
        client_options.update(transport=_ExternalOnlyTransport(), trust_env=False)
    request_headers = httpx.Headers(headers)
    request_headers.setdefault("Accept-Encoding", "gzip, deflate")
    with httpx.Client(**client_options) as client:
        request = client.build_request("GET", url, headers=request_headers)
        redirects = 0
        while True:
            valid, reason = validate_url(str(request.url), external_only=external_only)
            if not valid:
                raise WebsiteURLPolicyError(reason)
            response = client.send(request, stream=True, follow_redirects=False)
            try:
                if follow_redirects and response.next_request is not None:
                    if redirects >= 5:
                        raise httpx.TooManyRedirects("Website exceeded the redirect limit", request=request)
                    redirects += 1
                    request = response.next_request
                    continue
                body, limited = _read_bounded_body(response, max_bytes)
                response_headers = response.headers.copy()
                response_headers.pop("content-encoding", None)
                response_headers.pop("content-length", None)
                return httpx.Response(
                    response.status_code, headers=response_headers, content=bytes(body),
                    request=response.request,
                    extensions={"pulse_body_limit_reached": limited},
                )
            finally:
                response.close()
