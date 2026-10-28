"""Offline tests: fakes and self-hosted loopback HTTP only; no model calls."""
from contextlib import contextmanager
import http.client
import socketserver
import threading
import time
import unittest
from unittest.mock import Mock, patch

from memory_migration_study import deadline_http as transport


class DeadlineHttpTests(unittest.TestCase):
    def exchange(self, factory, *, seconds=1, event=None, deadline=None):
        return transport.exchange_http("POST", "/fixture", b'{"unchanged": true}',
            host="127.0.0.1", port=12345,
            deadline=deadline or transport.Deadline(time.monotonic() + seconds),
            event=event if event is not None else {}, connection_factory=factory)

    def test_absolute_boundary_and_unknown_host_fail_closed(self):
        deadline = transport.Deadline(10, clock=lambda: 10)
        with self.assertRaisesRegex(transport.DeadlineExceeded, "wall_budget_exceeded"):
            deadline.check()
        factory = Mock()
        with self.assertRaisesRegex(ValueError, "requires_ipv4_loopback"):
            transport.exchange_http("GET", "/", None, host="localhost", port=1,
                deadline=transport.Deadline(10, clock=lambda: 0), event={}, connection_factory=factory)
        factory.assert_not_called()

    def test_stages_recompute_remaining_preserve_bytes_and_close_once(self):
        clock = [0]
        connection, response = Mock(sock=None), Mock(status=503)
        connection.request.side_effect = lambda *args: clock.__setitem__(0, 2)
        connection.getresponse.side_effect = lambda: (clock.__setitem__(0, 5), response)[1]
        response.read.side_effect = lambda n: (clock.__setitem__(0, 6), b'{"error":"fixture"}')[1]
        factory, event = Mock(return_value=connection), {}
        raw = self.exchange(factory, deadline=transport.Deadline(10, clock=lambda: clock[0]), event=event)
        self.assertEqual(raw, b'{"error":"fixture"}')
        factory.assert_called_once_with("127.0.0.1", 12345, timeout=10)
        connection.request.assert_called_once_with("POST", "/fixture", b'{"unchanged": true}', {"Content-Type": "application/json"})
        self.assertEqual(connection.timeout, 5)
        self.assertEqual(event["http_status"], 503)
        self.assertEqual(event["raw_response"], '{"error":"fixture"}')
        connection.close.assert_called_once()

    def test_unexpired_io_error_is_not_hidden_or_reclassified(self):
        error = OSError("fixture original failure")
        connection = Mock(sock=None)
        connection.request.side_effect = error
        with self.assertRaises(OSError) as caught:
            self.exchange(Mock(return_value=connection))
        self.assertIs(caught.exception, error)
        connection.close.assert_called_once()

    def test_partial_error_body_remains_bounded_evidence(self):
        connection, response, event = Mock(sock=None), Mock(status=200), {}
        connection.getresponse.return_value = response
        response.read.side_effect = http.client.IncompleteRead(b"fixture partial", 99)
        with self.assertRaises(http.client.IncompleteRead):
            self.exchange(Mock(return_value=connection), event=event)
        self.assertEqual(event["raw_response"], "fixture partial")
        self.assertEqual(event["raw_response_bytes"], 15)

    def test_watchdog_interrupts_each_blocking_network_stage(self):
        for blocked in ("connect", "request", "headers", "body"):
            with self.subTest(stage=blocked):
                released = threading.Event()
                sock = Mock()
                sock.shutdown.side_effect = lambda how: released.set()
                response = Mock(status=200)
                connection = Mock(sock=None if blocked == "connect" else sock)
                if blocked == "connect":
                    sock.connect.side_effect = lambda address: released.wait(2)
                    connection.request.side_effect = lambda *args: connection._create_connection(("127.0.0.1", 12345))
                elif blocked == "request":
                    connection.request.side_effect = lambda *args: released.wait(2)
                elif blocked == "headers":
                    connection.getresponse.side_effect = lambda: (released.wait(2), response)[1]
                else:
                    # HTTPConnection can discard its socket while the response's
                    # makefile still owns it. The original socket must survive.
                    connection.getresponse.side_effect = lambda: (setattr(connection, "sock", None), response)[1]
                    response.read.side_effect = lambda n: (released.wait(2), b"partial")[1]
                if blocked != "headers" and blocked != "body":
                    connection.getresponse.return_value = response
                started = time.monotonic()
                with patch.object(transport.socket, "socket", return_value=sock):
                    with self.assertRaisesRegex(transport.DeadlineExceeded, "wall_budget_exceeded"):
                        self.exchange(Mock(return_value=connection), seconds=.08)
                self.assertLess(time.monotonic() - started, .8)
                self.assertTrue(released.is_set())
                sock.shutdown.assert_called_with(transport.socket.SHUT_RDWR)
                connection.close.assert_called_once()

    def test_per_request_deadline_is_distinct_from_batch_limit(self):
        released, sock = threading.Event(), Mock()
        sock.shutdown.side_effect = lambda how: released.set()
        connection = Mock(sock=sock)
        connection.request.side_effect = lambda *args: released.wait(2)
        with self.assertRaisesRegex(transport.DeadlineExceeded, "request_deadline_exceeded"):
            transport.exchange_http("GET", "/", None, host="127.0.0.1", port=12345,
                deadline=transport.Deadline(time.monotonic() + 2), event={},
                connection_factory=Mock(return_value=connection), request_seconds=.08)

    def test_early_watchdog_wake_waits_for_batch_clock_before_shutdown(self):
        class EarlyTimer:
            def __init__(self, interval, callback):
                self.callback = callback
            def start(self):
                # Deliberately ignore the initial delay to reproduce an early
                # timer wake independently of operating-system clock granularity.
                self.thread = threading.Thread(target=self.callback, daemon=True)
                self.thread.start()
            def cancel(self):
                self.thread.join(.5)
        released, sock, shutdown_times = threading.Event(), Mock(), []
        sock.shutdown.side_effect = lambda how: (shutdown_times.append(time.monotonic()), released.set())
        connection = Mock(sock=sock)
        def wait_for_expiry(*args):
            self.assertFalse(released.wait(.015), "watchdog shut down before the absolute deadline")
            self.assertTrue(released.wait(1), "watchdog did not shut down at the deadline")
        connection.request.side_effect = wait_for_expiry
        started = time.monotonic()
        deadline = transport.Deadline(started + .08)
        with patch.object(transport.threading, "Timer", EarlyTimer):
            with self.assertRaisesRegex(transport.DeadlineExceeded, "wall_budget_exceeded"):
                self.exchange(Mock(return_value=connection), deadline=deadline)
        connection.request.assert_called_once()
        self.assertGreaterEqual(shutdown_times[0], deadline.expires_at)
        self.assertLess(time.monotonic() - started, .8)
        connection.close.assert_called_once()

    def test_earlier_cutoff_determines_cause_even_when_both_elapsed(self):
        for batch_seconds, request_seconds, expected in (
            (10, 120, "wall_budget_exceeded"),
            (120, 120, "wall_budget_exceeded"),
            (1800, 120, "request_deadline_exceeded"),
        ):
            with self.subTest(batch=batch_seconds, request=request_seconds):
                clock, connection = [0], Mock(sock=None)
                connection.request.side_effect = lambda *args: clock.__setitem__(0, 1801)
                with patch.object(transport.threading, "Timer"):
                    with self.assertRaisesRegex(transport.DeadlineExceeded, expected):
                        transport.exchange_http("GET", "/", None, host="127.0.0.1", port=12345,
                            deadline=transport.Deadline(batch_seconds, clock=lambda: clock[0]),
                            event={}, connection_factory=Mock(return_value=connection),
                            request_seconds=request_seconds)
                connection.close.assert_called_once()


@contextmanager
def slow_server(mode):
    stop = threading.Event()
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = self.request.recv(1024)
                if not chunk:
                    return
                request += chunk
            try:
                if mode == "body":
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n")
                else:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Trickle: ")
                while not stop.wait(.015):
                    self.request.sendall(b"x")
            except OSError:
                pass
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join(1)


class LoopbackDeadlineTests(unittest.TestCase):
    def test_continuously_arriving_headers_and_body_do_not_extend_deadline(self):
        for mode in ("headers", "body"):
            with self.subTest(mode=mode), slow_server(mode) as port:
                event, started = {}, time.monotonic()
                with self.assertRaisesRegex(transport.DeadlineExceeded, "wall_budget_exceeded"):
                    transport.exchange_http("GET", "/slow", None,
                        host="127.0.0.1", port=port,
                        deadline=transport.Deadline(started + .18), event=event,
                        connection_factory=http.client.HTTPConnection)
                self.assertLess(time.monotonic() - started, .8)
                if mode == "body":
                    self.assertEqual(event["http_status"], 200)
                    self.assertGreater(event["raw_response_bytes"], 0)
                    self.assertLessEqual(event["raw_response_bytes"], 1048577)


if __name__ == "__main__":
    unittest.main()
