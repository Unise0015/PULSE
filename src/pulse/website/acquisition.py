"""Bounded HTTP observations shared by all website detection paths."""

import httpx


def fetch_observation(url, *, timeout, max_bytes, headers=None, follow_redirects=True):
    """Return a response with case-insensitive headers and a bounded decoded body.

    Stream decoded bytes so compressed responses are subject to the same limit.
    Closing the stream at the limit avoids buffering an entire auxiliary asset.
    """
    with httpx.Client(timeout=timeout, follow_redirects=follow_redirects, max_redirects=5) as client:
        with client.stream("GET", url, headers=headers) as response:
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=8192):
                body.extend(chunk[:max_bytes - len(body)])
                if len(body) >= max_bytes:
                    break
            # Preserve HTTPX's case-insensitive headers; content is already decoded.
            response_headers = response.headers.copy()
            response_headers.pop("content-encoding", None)
            response_headers.pop("content-length", None)
            return httpx.Response(
                response.status_code, headers=response_headers, content=bytes(body),
                request=response.request,
            )
