# ruff: noqa: S101 -- synthetic protocol qualification only.
"""Synthetic loopback transport fault cases for the credential reader."""

import http.server
import threading
import time

import candidate_credential_reader as R
import pytest


class _Handler(http.server.BaseHTTPRequestHandler):
    mode = "valid"

    def log_message(self, _format, *_args):
        pass

    def _write(self, value):
        try:
            self.wfile.write(value)
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False

    def do_GET(self):
        if self.mode == "drip_header":
            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}":
                if not self._write(bytes((byte,))):
                    break
                time.sleep(0.04)
            return
        if self.mode == "drip_body":
            self._write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: application/json\r\n\r\n")
            for _ in range(1000):
                if not self._write(b"x"):
                    break
                time.sleep(0.04)
            return
        if self.mode == "redirect":
            self._write(b"HTTP/1.1 302 Found\r\nLocation: http://203.0.113.1:9/no-request\r\nContent-Length: 0\r\n\r\n")
            return
        if self.mode == "large":
            length = R.RESPONSE_LIMIT + 1
            self._write(
                f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Type: application/json\r\n\r\n".encode()
            )
            return
        self._write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}")


@pytest.fixture
def loopback_api():
    def make(mode):
        handler = type("SyntheticHandler", (_Handler,), {"mode": mode})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_address[1]}"
        return server, thread, endpoint

    active = []
    try:
        yield lambda mode: _start_server(make, active, mode)
    finally:
        for server, thread, _endpoint in reversed(active):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            assert not thread.is_alive()


def _start_server(make, active, mode):
    created = make(mode)
    active.append(created)
    return created[2]


def _request(endpoint, *, deadline=None):
    return R.LoopbackAPI(endpoint)("GET", "synthetic/path", "synthetic-reader-token", deadline=deadline)


@pytest.mark.parametrize("mode", ["drip_header", "drip_body"])
def test_absolute_deadline_bounds_slow_headers_and_body(loopback_api, mode):
    endpoint = loopback_api(mode)
    started = time.monotonic()
    with pytest.raises(R.ReaderRefused):
        _request(endpoint, deadline=time.monotonic() + 0.2)
    assert time.monotonic() - started < 2


def test_redirect_is_refused_without_following_external_location(loopback_api):
    with pytest.raises(R.ReaderRefused):
        _request(loopback_api("redirect"), deadline=time.monotonic() + 2)


def test_oversized_response_is_refused_from_content_length(loopback_api):
    with pytest.raises(R.ReaderRefused):
        _request(loopback_api("large"), deadline=time.monotonic() + 2)


def test_loopback_transport_ignores_proxy_environment(monkeypatch, loopback_api):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1/unreachable")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1/unreachable")
    status, body = _request(loopback_api("valid"), deadline=time.monotonic() + 2)
    assert (status, body) == (200, {})
