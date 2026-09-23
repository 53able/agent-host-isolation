#!/usr/bin/env python3
"""Killable, host-side DNS resolution for the inspect fetch broker.

``socket.getaddrinfo`` has no portable timeout.  Resolution therefore runs in a
short-lived child process.  The parent owns the deadline and always terminates
and reaps the child before returning an error.
"""

from __future__ import annotations

import multiprocessing
import socket
import time
from threading import Event
from typing import Any, Callable


class DNSResolutionError(RuntimeError):
    """Resolution failed or the resolver child exited without a result."""


class DNSResolutionTimeout(DNSResolutionError):
    """The independent DNS deadline or the attempt deadline elapsed."""


class DNSResolutionCancelled(DNSResolutionError):
    """The broker cancellation event was set during resolution."""


def _resolve_child(connection: Any, hostname: str, port: int,
                   resolve_fn: Callable[..., list[tuple[Any, ...]]]) -> None:
    try:
        answers = resolve_fn(hostname, port, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in answers})
        connection.send(("ok", addresses))
    except BaseException as exc:  # serialize the failure across the process boundary
        try:
            connection.send(("error", type(exc).__name__, str(exc)))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()


class HostDNSResolver:
    """Resolve addresses with an independent bound and cooperative cancellation."""

    def __init__(self, *, timeout: float = 2.0, context: str = "spawn",
                 resolve_fn: Callable[..., list[tuple[Any, ...]]] | None = None):
        if not 0 < timeout <= 30:
            raise ValueError("dns timeout must be between 0 and 30 seconds")
        self.timeout = timeout
        try:
            self._context = multiprocessing.get_context(context)
        except ValueError as exc:
            raise ValueError(f"unsupported multiprocessing context: {context}") from exc
        self._resolve_fn = resolve_fn or socket.getaddrinfo

    @staticmethod
    def _stop_and_reap(process: multiprocessing.Process) -> None:
        if process.is_alive():
            process.terminate()
            process.join(timeout=0.5)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(timeout=0.5)
        if process.is_alive():
            # A live resolver child would violate the broker's cleanup contract.
            raise DNSResolutionError("DNS resolver child could not be reaped")
        process.join()

    def resolve(self, hostname: str, port: int, *, deadline: float,
                cancel: Event | None = None) -> set[str]:
        """Return addresses, bounded by ``min(deadline, now + timeout)``."""
        parent, child = self._context.Pipe(duplex=False)
        process = self._context.Process(target=_resolve_child,
                                        args=(child, hostname, port, self._resolve_fn), daemon=True)
        started = time.monotonic()
        process.start()
        child.close()
        dns_deadline = min(deadline, started + self.timeout)
        try:
            while True:
                if cancel is not None and cancel.is_set():
                    raise DNSResolutionCancelled("DNS cancelled")
                remaining = min(dns_deadline - time.monotonic(), 0.05)
                if remaining <= 0:
                    raise DNSResolutionTimeout("DNS timeout")
                if parent.poll(remaining):
                    try:
                        message = parent.recv()
                    except (EOFError, OSError) as exc:
                        raise DNSResolutionError("DNS resolver child exited without a result") from exc
                    if not message or message[0] != "ok":
                        name = message[1] if len(message) > 1 else "resolver error"
                        detail = message[2] if len(message) > 2 else ""
                        raise DNSResolutionError(f"{name}: {detail}".rstrip(": "))
                    return set(message[1])
                if not process.is_alive():
                    raise DNSResolutionError("DNS resolver child exited without a result")
        finally:
            parent.close()
            self._stop_and_reap(process)
