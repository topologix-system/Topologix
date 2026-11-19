"""Batfish coordinator version probe"""
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional

import pybatfish
from pybatfish.client.consts import CoordConsts, CoordConstsV2

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 2.0
NEGATIVE_CACHE_SECONDS = 30.0


class BatfishProbeError(Exception):
    """The coordinator could not be reached or answered unusably"""


class BatfishVersionProbe:
    """Version of the Batfish coordinator, fetched over HTTP without touching BatfishService"""

    def __init__(self, host: str, port: int, ttl_seconds: float = 300, grace_seconds: float = 3600,
                 negative_seconds: float = NEGATIVE_CACHE_SECONDS, timeout_seconds: float = PROBE_TIMEOUT_SECONDS,
                 clock: Callable[[], float] = time.monotonic):
        self.host = host
        self.port = int(port)
        self.ttl_seconds = float(ttl_seconds)
        self.grace_seconds = float(grace_seconds)
        self.negative_seconds = float(negative_seconds)
        self.timeout_seconds = float(timeout_seconds)
        self.clock = clock
        self._lock = threading.Lock()
        self._value: Optional[str] = None
        self._value_at: Optional[float] = None
        self._expires_at = 0.0
        self._last_success: Optional[float] = None
        self._negative_until = 0.0
        self._inflight: Optional[threading.Event] = None
        self._failure_logged = False

    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}{CoordConsts.SVC_CFG_WORK_MGR2}"

    def http_get(self, path: str) -> tuple[int, str]:
        """GET a coordinator v2 path with the probe timeout; return (status, body) or raise BatfishProbeError."""
        request = urllib.request.Request(
            self.base_url() + path,
            headers={
                CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY: CoordConsts.DEFAULT_API_KEY,
                CoordConstsV2.HTTP_HEADER_BATFISH_VERSION: str(getattr(pybatfish, '__version__', '')),
                'Accept': 'application/json',
            },
            method='GET',
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return response.status, response.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode('utf-8', errors='replace')
            except Exception:
                body = ''
            return exc.code, body
        except Exception as exc:
            raise BatfishProbeError(type(exc).__name__) from exc

    def snapshot_status(self, network_name: str, snapshot_name: str) -> tuple[int, str]:
        """Return (status, body) of GET /v2/networks/<network>/snapshots/<snapshot>."""
        path = "/networks/{}/snapshots/{}".format(
            urllib.parse.quote(network_name, safe=''),
            urllib.parse.quote(snapshot_name, safe=''),
        )
        return self.http_get(path)

    def fetch_version(self) -> str:
        status, body = self.http_get('/version')
        if status != 200:
            raise BatfishProbeError(f"HTTP {status}")
        try:
            payload = json.loads(body)
        except ValueError as exc:
            raise BatfishProbeError("invalid JSON") from exc
        version = payload.get('Batfish') if isinstance(payload, dict) else None
        if not version:
            raise BatfishProbeError("no Batfish component version")
        return str(version)

    def _grace_value(self, now: float) -> Optional[str]:
        if self._value is None or self._last_success is None:
            return None
        if now - self._last_success > self.grace_seconds:
            return None
        return self._value

    def peek(self) -> Optional[str]:
        """Return the last known version while it is within the grace period, else None, without fetching."""
        with self._lock:
            return self._grace_value(self.clock())

    def current(self) -> Optional[str]:
        """Return the Batfish version, cached for its TTL; None while it is unknown."""
        now = self.clock()
        with self._lock:
            if self._value is not None and now < self._expires_at:
                return self._value
            if now < self._negative_until:
                return self._grace_value(now)
            event = self._inflight
            owner = event is None
            if owner:
                event = self._inflight = threading.Event()
        if not owner:
            event.wait(self.timeout_seconds + 1.0)
            with self._lock:
                now = self.clock()
                if self._value is not None and now < self._expires_at:
                    return self._value
                return self._grace_value(now)

        started = now
        version = None
        failure = None
        try:
            version = self.fetch_version()
        except Exception as exc:
            failure = exc
        with self._lock:
            try:
                now = self.clock()
                if version is not None:
                    if self._value_at is None or started >= self._value_at:
                        self._value = version
                        self._value_at = started
                    self._expires_at = started + self.ttl_seconds
                    self._last_success = max(self._last_success or started, started)
                    self._negative_until = 0.0
                    self._failure_logged = False
                    return self._value
                self._negative_until = now + self.negative_seconds
                log_failure = not self._failure_logged
                self._failure_logged = True
                result = self._grace_value(now)
            finally:
                self._inflight = None
                event.set()
        if log_failure:
            logger.warning(
                "Batfish version probe failed (%s); the result cache is bypassed once no known version is "
                "within the grace period",
                type(failure).__name__,
            )
        return result

    def feed(self, version: Optional[str], observed_at: float) -> Optional[str]:
        """Record a version fetched by an activation and return the version the probe holds afterwards;
        a newer probe answer is kept and its TTL is not extended."""
        with self._lock:
            if not version or (self._value_at is not None and observed_at <= self._value_at):
                return self._value
            first = self._value is None
            self._value = str(version)
            self._value_at = observed_at
            self._last_success = max(self._last_success or observed_at, observed_at)
            if first:
                self._expires_at = observed_at + self.ttl_seconds
            return self._value
