import multiprocessing
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from threading import Event

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from inspect_fetch_resolver import (  # noqa: E402
    DNSResolutionCancelled,
    DNSResolutionError,
    DNSResolutionTimeout,
    HostDNSResolver,
)


def blocking_getaddrinfo(*_args, **_kwargs):
    time.sleep(10)
    return []


def failing_getaddrinfo(*_args, **_kwargs):
    raise socket.gaierror("resolver down")


class ResolverTests(unittest.TestCase):
    def test_blocking_child_is_terminated_and_reaped_at_dns_deadline(self):
        resolver = HostDNSResolver(timeout=0.05, resolve_fn=blocking_getaddrinfo)
        before = {child.pid for child in multiprocessing.active_children()}
        with self.assertRaises(DNSResolutionTimeout):
            resolver.resolve("api.example.com", 443, deadline=time.monotonic() + 2)
        self.assertEqual(before, {child.pid for child in multiprocessing.active_children()})

    def test_cancellation_terminates_blocking_child_before_returning(self):
        cancelled = Event()
        result = []

        def run():
            try:
                resolver.resolve("api.example.com", 443, deadline=time.monotonic() + 5, cancel=cancelled)
            except BaseException as exc:
                result.append(exc)

        resolver = HostDNSResolver(timeout=2, resolve_fn=blocking_getaddrinfo)
        thread = threading.Thread(target=run)
        thread.start()
        time.sleep(0.05)
        cancelled.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], DNSResolutionCancelled)
        self.assertFalse(multiprocessing.active_children())

    def test_dns_failure_preserves_exception_identity(self):
        resolver = HostDNSResolver(timeout=1, resolve_fn=failing_getaddrinfo)
        with self.assertRaisesRegex(DNSResolutionError, r"gaierror: resolver down"):
            resolver.resolve("api.example.com", 443, deadline=time.monotonic() + 1)
        self.assertFalse(multiprocessing.active_children())

    def test_attempt_deadline_wins_over_independent_dns_timeout(self):
        resolver = HostDNSResolver(timeout=2, resolve_fn=blocking_getaddrinfo)
        with self.assertRaises(DNSResolutionTimeout):
            resolver.resolve("api.example.com", 443, deadline=time.monotonic() + 0.05)
        self.assertFalse(multiprocessing.active_children())


if __name__ == "__main__":
    unittest.main()
