"""Absolute deadlines for the probes' exclusive plain IPv4 loopback requests.

Closing a client connection does not prove that server-side generation stopped.
The watchdog shuts down the original socket, including when an HTTP response's
file object still owns it after HTTPConnection has cleared ``sock``.
"""
from __future__ import annotations

import hashlib
import http.client
import socket
import threading
import time


class DeadlineExceeded(ValueError):
    """A client request or the enclosing probe exhausted its absolute budget."""


class Deadline:
    def __init__(self, expires_at, *, clock=time.monotonic, code="wall_budget_exceeded"):
        self.expires_at, self.clock, self.code = expires_at, clock, code

    def remaining(self):
        remaining = self.expires_at - self.clock()
        if remaining <= 0:
            raise DeadlineExceeded(self.code)
        return remaining

    def check(self):
        self.remaining()


def exchange_http(method, path, body, *, host, port, deadline, event,
                  connection_factory=http.client.HTTPConnection,
                  request_seconds=120, max_bytes=1048577):
    """Return bounded bytes, interrupting connect/send/headers/read at deadline.

    Only the probes' numeric IPv4 loopback endpoints are supported. No DNS lookup,
    proxy, TLS, retry or request serialization is performed here. Factories and
    clocks are supplied by drivers so their existing offline seams remain usable.
    """
    if host != "127.0.0.1":
        raise ValueError("deadline_http_requires_ipv4_loopback")
    remaining = deadline.remaining()
    request_expires_at = deadline.clock() + request_seconds
    # Retain the source of the earlier limit, including a batch/request tie.
    # Otherwise a watchdog wake just before the batch clock advances can report
    # a request timeout even though the batch limit scheduled that watchdog.
    request_deadline = (deadline if deadline.expires_at <= request_expires_at else
                        Deadline(request_expires_at, clock=deadline.clock,
                                 code="request_deadline_exceeded"))
    connection = connection_factory(host, port, timeout=min(request_seconds, remaining))
    sockets, lock, expired = [], threading.Lock(), threading.Event()
    cancelled = threading.Event()

    def check():
        # Attribute cancellation to the actual earlier cutoff, even if the
        # calling thread resumes after both limits have elapsed.
        request_deadline.check()
        if expired.is_set():
            raise DeadlineExceeded(request_deadline.code)

    def abort_socket(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def register(sock):
        with lock:
            if not any(old is sock for old in sockets):
                sockets.append(sock)
            abort = expired.is_set()
        if abort:
            abort_socket(sock)
        check()

    def connect(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        # Publish before connect blocks. Standard socket.create_connection only
        # assigns HTTPConnection.sock after connect, too late for cancellation.
        if address != (host, port):
            raise ValueError("deadline_http_endpoint_changed")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            register(sock)
            sock.settimeout(request_deadline.remaining())
            if source_address:
                sock.bind(source_address)
            sock.connect(address)
            check()
            return sock
        except BaseException:
            sock.close()
            raise

    def expire():
        # Timed waits can wake before the monotonic deadline on some platforms.
        # Recheck that clock before cutting the socket; early wakes keep waiting
        # and remain cancellable when the request completes in time.
        while True:
            remaining = request_deadline.expires_at - request_deadline.clock()
            if remaining <= 0:
                break
            if cancelled.wait(remaining):
                return
        if cancelled.is_set():
            return
        expired.set()
        with lock:
            current = tuple(sockets)
        # Never close an HTTPResponse in the timer thread: its buffered read may
        # hold a lock. Shutdown releases the read; the calling thread closes it.
        for sock in current:
            abort_socket(sock)

    def stage():
        check()
        connection.timeout = request_deadline.remaining()
        sock = getattr(connection, "sock", None)
        if sock is not None:
            register(sock)
        with lock:
            current = tuple(sockets)
        for sock in current:
            sock.settimeout(request_deadline.remaining())

    def capture(raw):
        raw = raw[:max_bytes]
        event.update(raw_response_bytes=len(raw),
                     raw_response_sha256=hashlib.sha256(raw).hexdigest(),
                     raw_response=raw.decode("utf-8", errors="replace"))

    connection._create_connection = connect
    timer = threading.Timer(request_deadline.remaining(), expire)
    timer.daemon = True
    timer.start()
    response = None
    try:
        stage()
        connection.request(method, path, body, {"Content-Type": "application/json"})
        stage()
        response = connection.getresponse()
        event["http_status"] = response.status
        stage()
        received = bytearray()
        try:
            # A single buffered read can discard bytes already received when a
            # socket shutdown raises OSError. Keep a bounded prefix ourselves.
            # Minimal offline reply fakes may only implement read().
            if callable(getattr(type(response), "read1", None)):
                while len(received) < max_bytes:
                    check()
                    chunk = response.read1(max_bytes - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
            else:
                received.extend(response.read(max_bytes))
        except http.client.IncompleteRead as error:
            received.extend(error.partial[:max_bytes - len(received)])
            capture(bytes(received))
            raise
        except Exception:
            if received:
                capture(bytes(received))
            raise
        raw = bytes(received)
        capture(raw)
        check()
        return raw
    except Exception as error:
        # An ordinary I/O or validation error before expiry remains unchanged.
        # A shutdown-induced EOF/OSError after expiry becomes a stable timeout.
        try:
            check()
        except DeadlineExceeded as timeout:
            raise timeout from error
        raise
    finally:
        cancelled.set()
        timer.cancel()
        try:
            # A Connection: close response may no longer belong to connection;
            # release its makefile even when a captured timeout retains frames.
            if response is not None:
                response.close()
        finally:
            connection.close()
