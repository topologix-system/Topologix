"""Batfish network analysis service wrapper"""
import collections
import contextlib
import gc
import logging
import re
import sys
import threading
import time
import urllib.parse
from typing import Any, Callable, NoReturn
from pathlib import Path

import pandas as pd
import pybatfish
from pybatfish.client.session import Session

from services.snapshot_state_service import StagingVanishedError, tree_contains_symlink

try:
    import gevent
    from gevent import monkey as gevent_monkey
except ImportError:  # pragma: no cover - gevent is a runtime dependency but optional for tooling
    gevent = None
    gevent_monkey = None

from config import config
from models import (
    NetworkNode, NetworkEdge, InterfaceDetail, VLANInfo, RouteEntry,
    OSPFProcessConfig, OSPFAreaConfig, OSPFInterfaceConfig, OSPFSessionCompat,
    FileParseStatus, InitIssue, ParseWarning, ViConversionStatus, DuplicateRouterID,
    DefinedStructure, ReferencedStructure, NamedStructure,
    FlowTrace, ReachabilityTrace,
    NodeType, ProtocolType
)

logger = logging.getLogger(__name__)

# Deterministic question-content errors come back from the Batfish
# coordinator as HTTP 500, and pybatfish's module-level retry policy
# (total=10, backoff_factor=0.8) retries them for ~444 seconds. That wait
# happens while the Flask process holds the app-wide Batfish request lock,
# so every Batfish-backed endpoint freezes. Keep the upstream retry
# statuses but cap the retry budget to a couple of seconds.
_PYBATFISH_RETRY_TOTAL = 3
_PYBATFISH_RETRY_BACKOFF_FACTOR = 0.3


def _normalize_json_scalar(value: Any) -> Any:
    """Convert a pandas/NumPy scalar into a JSON-safe Python scalar."""
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass

    item = getattr(value, "item", None)
    if callable(item):
        try:
            return item()
        except (TypeError, ValueError):
            pass
    return value


def _join_text_values(values: Any) -> str | None:
    """Join a Batfish list cell into one comma-separated string."""
    if not isinstance(values, (list, tuple, set)) or not values:
        return None
    return ", ".join(str(value) for value in values)


# A Java stack frame target: an optional module or class-loader prefix such as
# 'java.base/' or 'app//', then the qualified method name, '<init>' or '<clinit>'
# included, and the opening parenthesis.
_JAVA_STACK_FRAME_TARGET = r"(?:[\w.$@+-]*/)*[A-Za-z_$][\w.$]*(?:<(?:cl)?init>)?\("
_JAVA_STACK_FRAME_LINE = re.compile(rf"^\s*at {_JAVA_STACK_FRAME_TARGET}")
JAVA_STACK_FRAME_IN_TEXT = re.compile(rf"\s+at\s+{_JAVA_STACK_FRAME_TARGET}")
_JAVA_OMITTED_FRAMES_LINE = re.compile(r"^\s*\.\.\. \d+ (?:more|common frames omitted)")
_JAVA_EXCEPTION_PREFIX = re.compile(r"^(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*(?:Exception|Error):\s*")
_JACKSON_SOURCE_LOCATION = re.compile(r"\s*at \[Source: [^\]]*\]")
_UUID_TEXT = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_COORDINATOR_ERROR_REASON_LIMIT = 500
_COORDINATOR_HTTP_ERROR = re.compile(r"Batfish coordinator returned HTTP (\d{3})(?:: (.*))?", re.DOTALL)
_LOST_NETWORK_REASON = re.compile(r"^Network '([^']+)' does not exist")
_LOST_SNAPSHOT_REASON = re.compile(r"^Missing snapshot '([^']+)' for network:? '([^']+)'")
_SNAPSHOT_NOT_FOUND_REASON = re.compile(r"^Snapshot (\S+) not found(?: in network (\S+))?$")
_SNAPSHOT_URL_PATH = re.compile(r"/v2/networks/([^/?#]+)/snapshots/([^/?#]+)")
_REDACTED_NAME_MARKERS = ("[id]", "[redacted]")
STATE_LOST_HINT = "Batfish no longer holds this snapshot; it is re-parsed on the next request or by Reload"
STATE_LOST_UNIDENTIFIED_HINT = (
    "Batfish reported a missing snapshot that could not be identified; retry, or reload the snapshot"
)
ACTIVATION_FAILURE_TTL_SECONDS = 60.0
LIVE_RETRY_SECONDS = 60.0
STATE_LOSS_LOG_SIZE = 64
LOST_NETWORK = object()
LOST_UNIDENTIFIED = object()

_call_state = threading.local()


def _coordinator_response_of(error: BaseException | None) -> Any:
    """Return the coordinator HTTP response carried by an exception or its causes, or None."""
    seen = set()
    pending = [error]
    while pending:
        current = pending.pop(0)
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        response = getattr(current, "response", None)
        if response is not None and hasattr(response, "status_code"):
            return response
        pending.extend([getattr(current, "__cause__", None), getattr(current, "__context__", None)])
        pending.extend(arg for arg in getattr(current, "args", ()) if isinstance(arg, BaseException))
    return None


def _wrap_init_network() -> None:
    """Record, per call, that pybatfish created a network because the coordinator did not hold it."""
    try:
        from pybatfish.client import restv2helper

        original = restv2helper.init_network
        if getattr(original, "_topologix_records_creation", False):
            return

        def init_network(session, new_network_name):
            result = original(session, new_network_name)
            _call_state.network_created = True
            return result

        init_network._topologix_records_creation = True
        restv2helper.init_network = init_network
    except Exception as e:
        logger.warning("Could not observe Batfish network creation: %s", e)


class RecordedActivationFailure(RuntimeError):
    """An activation failure replayed from the negative cache"""

    def __init__(self, message: str, error_type: str):
        super().__init__(message)
        self.error_type = error_type


class ActivationFailureCache:
    """Activation failures remembered for a short time"""

    def __init__(self, ttl_seconds: float = ACTIVATION_FAILURE_TTL_SECONDS, clock: Callable[[], float] = time.monotonic):
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._lock = threading.Lock()
        self._entries: dict[tuple, tuple[float, str, str, str | None, str]] = {}

    def record(self, key: tuple, error: BaseException, snapshot_id: str | None, snapshot_name: str) -> None:
        now = self.clock()
        with self._lock:
            for expired in [item for item, entry in self._entries.items() if entry[0] <= now]:
                del self._entries[expired]
            self._entries[key] = (now + self.ttl_seconds, str(error), type(error).__name__, snapshot_id, snapshot_name)

    def get(self, key: tuple) -> BaseException | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry[0] <= self.clock():
                del self._entries[key]
                return None
            return RecordedActivationFailure(entry[1], entry[2])

    def remove_snapshot(self, snapshot_id: str | None, snapshot_name: str) -> None:
        with self._lock:
            for key in [
                key for key, entry in self._entries.items()
                if (snapshot_id is not None and entry[3] == snapshot_id) or entry[4] == snapshot_name
            ]:
                del self._entries[key]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def _extract_coordinator_error_reason(body: str | None, redact: bool = True) -> str | None:
    """Reduce a Batfish coordinator error body to its innermost exception message without stack frames."""
    if not body or not body.strip():
        return None

    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in body.splitlines():
        stripped = line.strip()
        if _JAVA_STACK_FRAME_LINE.match(line) or _JAVA_OMITTED_FRAMES_LINE.match(line):
            current = None
            continue
        if stripped.startswith("Caused by: "):
            current = [stripped[len("Caused by: "):]]
            blocks.append(current)
        elif not blocks:
            current = [stripped]
            blocks.append(current)
        elif current is not None:
            current.append(stripped)

    if not blocks:
        return None

    reason = _JACKSON_SOURCE_LOCATION.sub("", " ".join(blocks[-1]))
    reason = _JAVA_EXCEPTION_PREFIX.sub("", reason.strip())
    reason = re.sub(r"^Invalid question \S+: ", "", reason)
    reason = " ".join(reason.split())
    if not redact:
        return reason or None
    reason = _UUID_TEXT.sub("[id]", reason)
    if not reason:
        return None
    if len(reason) > _COORDINATOR_ERROR_REASON_LIMIT:
        reason = reason[:_COORDINATOR_ERROR_REASON_LIMIT] + "..."
    return reason


def _coordinator_http_error_message(response: Any) -> str:
    """Describe a failed coordinator response by status code and Batfish reason."""
    message = f"Batfish coordinator returned HTTP {getattr(response, 'status_code', 'error')}"
    reason = _extract_coordinator_error_reason(getattr(response, "text", None))
    return f"{message}: {reason}" if reason else message


def _check_coordinator_response_status(response: Any) -> None:
    """Raise HTTPError for a failed coordinator response, carrying the Batfish reason instead of its stack trace."""
    from requests import HTTPError

    try:
        response.raise_for_status()
    except HTTPError as e:
        raise HTTPError(_coordinator_http_error_message(response), response=response) from e


def _configure_pybatfish_retries() -> None:
    """Cap pybatfish's HTTP retry policy."""
    try:
        from requests.adapters import HTTPAdapter
        from urllib3 import Retry

        from pybatfish.client import restv2helper

        http_sessions = (
            restv2helper._requests_session,
            restv2helper._requests_session_fail_fast,
        )
        if not callable(getattr(restv2helper, "_check_response_status", None)):
            raise AttributeError("pybatfish restv2helper._check_response_status is unavailable")

        retry = Retry(
            total=_PYBATFISH_RETRY_TOTAL,
            connect=_PYBATFISH_RETRY_TOTAL,
            read=_PYBATFISH_RETRY_TOTAL,
            backoff_factor=_PYBATFISH_RETRY_BACKOFF_FACTOR,
            allowed_methods=None,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,
        )
        restv2helper._check_response_status = _check_coordinator_response_status
        for http_session in http_sessions:
            adapter = HTTPAdapter(max_retries=retry)
            http_session.mount("http://", adapter)
            http_session.mount("https://", adapter)
    except Exception as e:
        logger.warning("Could not adjust pybatfish HTTP retry policy: %s", e)
        return

    logger.info(
        "Adjusted pybatfish HTTP retry policy: total=%s backoff_factor=%s",
        _PYBATFISH_RETRY_TOTAL,
        _PYBATFISH_RETRY_BACKOFF_FACTOR,
    )


_configure_pybatfish_retries()
_wrap_init_network()


BATFISH_NOT_INITIALIZED_MESSAGE = "Batfish session not initialized. Call initialize_network() first."


class BatfishQueryError(RuntimeError):
    """Structured Batfish query failure for API callers."""

    def __init__(
        self,
        query_name: str,
        message: str,
        error_type: str = "query_error",
        details: dict[str, Any] | None = None,
        hints: list[str] | None = None,
        status_code: int = 400,
    ):
        super().__init__(message)
        self.query_name = query_name
        self.message = message
        self.error_type = error_type
        self.details = details or {"query": query_name}
        self.hints = hints or []
        self.status_code = status_code
        self.state_loss: tuple[str | None, bool] | None = None
        self.from_coordinator_response = False


class BatfishSnapshotLoadError(RuntimeError):
    """Batfish work log of a snapshot that Batfish rejected while it was loaded for queries by name."""

    def __init__(self, snapshot_name: str, message: str):
        super().__init__(message)
        self.snapshot_name = snapshot_name


class BatfishService:
    """Service for interacting with Batfish network analysis"""

    _ROUTE_POLICY_QUERY_NAMES = {
        "searchRoutePolicies",
        "testRoutePolicies",
        "transferBDDValidation",
        "comparePeerGroupPolicies",
        "compareRoutePolicies",
    }

    # Batfish AS-path regexes range over sequences of numeric AS numbers, so
    # bare letters are never valid there. The coordinator answers such values
    # with HTTP 500 at question creation, which pybatfish retries, so reject
    # them before they reach Batfish. Escape pairs such as \d are removed
    # before this check so regex character classes stay usable.
    _ROUTE_POLICY_AS_PATH_REGEX_ALLOWED = re.compile(r"[0-9\s^$.*+?()\[\]{}|,_-]*")
    _BGP_STANDARD_COMMUNITY_LITERAL = re.compile(r"^(\d+):(\d+)$")
    _BGP_LARGE_COMMUNITY_LITERAL = re.compile(r"^(\d+):(\d+):(\d+)$")

    # HeaderConstraints fields that Batfish parses as IntegerSpace strings such as "0,8" or "0-8",
    # mapped to the largest value Batfish accepts for the field (the smallest is 0)
    _HEADER_INTEGER_SPACE_FIELDS = {
        "srcPorts": 65535,
        "dstPorts": 65535,
        "icmpCodes": 255,
        "icmpTypes": 255,
        "dscps": 63,
        "ecns": 3,
        "packetLengths": 65535,
        "fragmentOffsets": 8191,
    }
    # One IntegerSpace item: a value or a low-high range, optionally prefixed with '!' to exclude it
    _HEADER_INTEGER_SPACE_ATOM = re.compile(r"(!?)(\d+)(?:\s*-\s*(\d+))?")
    # Longest IntegerSpace bound converted to int
    _HEADER_INTEGER_SPACE_MAX_DIGITS = 10

    _SECRET_ERROR_KEY_PATTERN = re.compile(
        r"""(["']?[A-Za-z0-9_.-]*(?:password|secret|token|communities|community)[A-Za-z0-9_.-]*["']?)(\s*(?::|=)\s*|\s+)""",
        re.IGNORECASE,
    )

    def __init__(self):
        self._session: Session | None = None
        self.network_name = config.BATFISH_NETWORK
        self.current_snapshot_name: str | None = None
        self.reference_snapshot_name: str | None = None
        self._initialized = False
        self._query_snapshot_name: str | None = None
        self._batfish_version: str | None = None
        self.loaded_content_hash: str | None = None
        self.loaded_batfish_version: str | None = None
        self.loaded_clear_counter: int | None = None
        self.live_loaded: tuple | None = None
        self.activation_payload: dict[str, Any] | None = None
        self.last_upload_hash: str | None = None
        self.version_probe = None
        self.activation_failures = ActivationFailureCache()
        self.state_drop_count = 0
        self.state_loss_events = 0
        self.state_loss_log: collections.deque = collections.deque(maxlen=STATE_LOSS_LOG_SIZE)
        self._state_service = None

    @property
    def session(self) -> Session:
        """Create the pybatfish session on first use."""
        if self._session is None:
            logger.info("Creating Batfish session: %s:%s", config.BATFISH_HOST, config.BATFISH_PORT)
            self._session = Session(host=config.BATFISH_HOST, port=config.BATFISH_PORT)
        return self._session

    def attach_state_service(self, state_service) -> None:
        """Attach the snapshot state service that stages uploads and reads the result cache clear counter."""
        self._state_service = state_service

    def _reset_loaded_state(self) -> None:
        self.loaded_content_hash = None
        self.loaded_batfish_version = None
        self.loaded_clear_counter = None
        self.live_loaded = None
        self.activation_payload = None

    def _invalidate_loaded_state(self) -> None:
        self._initialized = False
        self.loaded_content_hash = None
        self.state_drop_count += 1

    def _note_state_loss(self, lost: Any) -> None:
        """Count a lost-state event; lost is a snapshot name, LOST_NETWORK or LOST_UNIDENTIFIED."""
        self.state_loss_events += 1
        self.state_loss_log.append((self.state_loss_events, lost))

    def _drop_loaded_state(self, lost: Any = None) -> None:
        """Forget that Batfish holds the active snapshot while keeping it selected."""
        lost_snapshot = self.current_snapshot_name if lost is None else lost
        self._invalidate_loaded_state()
        self._note_state_loss(lost_snapshot)

    def _lost_sides(self, sides: list) -> list:
        """Return (path, name) of the sides lost since they were available to the call."""
        lost = []
        for name, path, available_since, served_from_active in sides:
            if any(name == side for _, side in lost):
                continue
            for sequence, loss in self.state_loss_log:
                if sequence > available_since and (
                    loss is LOST_NETWORK or loss == name or (loss is LOST_UNIDENTIFIED and served_from_active)
                ):
                    lost.append((path, name))
                    break
        return lost

    def _reload_side(self, snapshot_dir: str | Path, snapshot_name: str) -> None:
        """Upload a lost side again; an active snapshot replaced this way no longer counts as loaded."""
        if snapshot_name == self.current_snapshot_name and self._initialized:
            self._invalidate_loaded_state()
        self._load_snapshot(snapshot_dir, snapshot_name)

    def snapshot_version_info(self) -> dict[str, Any]:
        """Describe the loaded content for the all-data response."""
        marker = self.live_loaded
        live = bool(
            self._initialized
            and marker is not None
            and marker[0] == self.network_name
            and marker[1] == self.current_snapshot_name
        )
        return {
            'content_hash': self.loaded_content_hash,
            'live': live,
            'live_hash': marker[2] if live else None,
        }

    @staticmethod
    def reset_query_failure_count() -> None:
        _call_state.query_failures = 0

    @staticmethod
    def query_failure_count() -> int:
        return getattr(_call_state, 'query_failures', 0)

    @staticmethod
    def _count_query_failure() -> None:
        _call_state.query_failures = getattr(_call_state, 'query_failures', 0) + 1

    def set_network_context(self, network_name: str) -> None:
        """Switch Batfish network namespace for the current request context."""
        if self.network_name == network_name:
            return

        logger.info("Switching Batfish network context: %s -> %s", self.network_name, network_name)
        self.network_name = network_name
        self.current_snapshot_name = None
        self.reference_snapshot_name = None
        self._initialized = False
        self._reset_loaded_state()

    def _set_network_observing_creation(self, session: Session) -> None:
        """Select the network; drop the active snapshot's state when the coordinator had to create the network."""
        _call_state.network_created = False
        session.set_network(self.network_name)
        created = getattr(_call_state, 'network_created', False)
        _call_state.network_created = False
        if not created:
            return
        if self._initialized or self.loaded_content_hash is not None:
            logger.warning(
                "Batfish network %s was created during a load; the active snapshot state is dropped",
                self.network_name,
            )
            self._drop_loaded_state(LOST_NETWORK)
        else:
            self._note_state_loss(LOST_NETWORK)

    def _fetch_batfish_version(self, session: Session) -> str | None:
        """Fetch the Batfish server version in this call, keeping the first one for health diagnostics."""
        try:
            components = session.get_component_versions()
            batfish_version = components.get("Batfish") if isinstance(components, dict) else None
            version = str(batfish_version) if batfish_version else None
        except Exception as e:
            logger.warning("Could not retrieve Batfish server version: %s", e)
            return None
        if self._batfish_version is None:
            self._batfish_version = version
        return version

    def _feed_version_probe(self, session: Session) -> str | None:
        """Fetch the version in this call and feed the probe; return the version that describes this parse."""
        probe = self.version_probe
        observed_at = probe.clock() if probe is not None else None
        version = self._fetch_batfish_version(session)
        if probe is None:
            return version
        return probe.feed(version, observed_at)

    def _prepare_upload(self, snapshot_path: Path) -> tuple[Path, str | None, Path | None]:
        """Return (upload path, staged content hash, staged dir): the staged consumable set, or the live directory
        without a state service or when staging fails and the tree holds no symlink."""
        state_service = self._state_service
        if state_service is None:
            return snapshot_path, None, None
        try:
            staged_dir, content_hash = state_service.stage_for_upload(snapshot_path)
            return staged_dir, content_hash, staged_dir
        except StagingVanishedError as e:
            logger.warning("%s; the upload is refused", e)
            raise
        except Exception as e:
            reason = type(e).__name__
        if tree_contains_symlink(snapshot_path):
            logger.warning(
                "Snapshot %s could not be staged (%s) and contains symlinks; the live directory is not uploaded",
                snapshot_path.name,
                reason,
            )
            raise RuntimeError(f"Snapshot '{snapshot_path.name}' could not be staged for upload")
        logger.warning(
            "Snapshot %s could not be staged (%s); uploading the live directory without caching its results",
            snapshot_path.name,
            reason,
        )
        return snapshot_path, None, None

    def _cleanup_upload(self, staged_dir: Path | None) -> None:
        if staged_dir is None or self._state_service is None:
            return
        try:
            self._state_service.cleanup_staging(staged_dir)
        except Exception as e:
            logger.warning("Staging copy could not be removed: %s", type(e).__name__)

    def _live_working_hash(self, snapshot_path: Path) -> str | None:
        try:
            return self._state_service.compute_manifest(snapshot_path).content_hash
        except Exception:
            return None

    def _read_clear_counter(self) -> int | None:
        if self._state_service is None:
            return None
        try:
            return self._state_service.read_clear_counter()
        except Exception:
            return None

    def initialize_network(self, snapshot_dir: str | Path, snapshot_name: str | None = None) -> dict[str, Any]:
        """Initialize Batfish network and snapshot"""
        staged_dir = None
        try:
            snapshot_path = Path(snapshot_dir)
            if not snapshot_path.exists():
                raise FileNotFoundError(f"Snapshot directory not found: {snapshot_dir}")

            if snapshot_name is None:
                snapshot_name = snapshot_path.name

            self.last_upload_hash = None
            clear_counter = self._read_clear_counter()
            upload_path, staged_hash, staged_dir = self._prepare_upload(snapshot_path)
            self.last_upload_hash = staged_hash
            live_hash = None
            if staged_dir is None and self._state_service is not None:
                live_hash = self._live_working_hash(snapshot_path)

            session = self.session
            self._set_network_observing_creation(session)
            logger.info(f"Network set to: {self.network_name}")

            parsed_version = self._feed_version_probe(session)

            init_result = session.init_snapshot(
                str(upload_path),
                name=snapshot_name,
                overwrite=True
            )
            logger.info(f"Snapshot initialized: {snapshot_name}")

            self.current_snapshot_name = snapshot_name
            self._initialized = True
            self.loaded_content_hash = staged_hash
            self.loaded_clear_counter = clear_counter
            self.loaded_batfish_version = parsed_version
            self.live_loaded = (
                (self.network_name, snapshot_name, live_hash, time.monotonic())
                if self._state_service is not None and staged_dir is None
                else None
            )

            file_status = self.get_file_parse_status()
            init_issues = self.get_init_issues()
            parse_warnings = self.get_parse_warnings()

            init_result_safe = {}
            if init_result:
                for key in ['summary', 'status', 'filecount']:
                    if hasattr(init_result, key):
                        value = getattr(init_result, key)
                        if not hasattr(value, '__class__') or 'FileLines' not in str(value.__class__):
                            init_result_safe[key] = value

            payload = {
                "status": "success",
                "network": self.network_name,
                "snapshot": snapshot_name,
                "file_parse_status": [s.to_dict() for s in file_status],
                "init_issues": [i.to_dict() for i in init_issues],
                "parse_warnings": [w.to_dict() for w in parse_warnings],
                "initialization_result": init_result_safe
            }
            self.activation_payload = payload
            return payload

        except Exception as e:
            logger.error(f"Failed to initialize network: {e}")
            raise
        finally:
            self._cleanup_upload(staged_dir)

    def _ensure_initialized(self):
        if not self._initialized and self._query_snapshot_name is None:
            raise RuntimeError(BATFISH_NOT_INITIALIZED_MESSAGE)

    def clear_active_snapshot(self) -> None:
        """Forget the active snapshot so analysis queries report an uninitialized session."""
        self.current_snapshot_name = None
        self._initialized = False
        self._reset_loaded_state()

    def _load_snapshot(self, snapshot_dir: str | Path, snapshot_name: str) -> None:
        """Parse a snapshot in Batfish without changing the active snapshot."""
        snapshot_path = Path(snapshot_dir)
        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot directory not found: {snapshot_dir}")

        upload_path, _, staged_dir = self._prepare_upload(snapshot_path)
        try:
            session = self.session
            previous_snapshot = session.snapshot
            self._set_network_observing_creation(session)
            self._feed_version_probe(session)
            try:
                session.init_snapshot(str(upload_path), name=snapshot_name, overwrite=True)
            except Exception as e:
                if "Work terminated abnormally" in str(e):
                    raise BatfishSnapshotLoadError(snapshot_name, str(e)) from e
                raise
            finally:
                session.snapshot = previous_snapshot
        finally:
            self._cleanup_upload(staged_dir)
        logger.info("Snapshot loaded without activation: %s", snapshot_name)

    def _load_snapshot_unless_active(self, snapshot_dir: str | Path, snapshot_name: str) -> bool:
        """Parse a snapshot for queries by name, reusing the active snapshot Batfish already holds.

        Returns True when the active snapshot was reused without loading.
        """
        if self._initialized and self.current_snapshot_name == snapshot_name:
            logger.debug("Using the active Batfish snapshot '%s' without reloading", snapshot_name)
            return True
        self._load_snapshot(snapshot_dir, snapshot_name)
        return False

    @contextlib.contextmanager
    def _query_snapshot_scope(self, snapshot_name: str):
        """Point queries at a loaded snapshot while the active snapshot state stays unchanged."""
        session = self.session
        previous_snapshot = session.snapshot
        previous_query_snapshot = self._query_snapshot_name
        session.snapshot = snapshot_name
        self._query_snapshot_name = snapshot_name
        try:
            yield
        finally:
            session.snapshot = previous_snapshot
            self._query_snapshot_name = previous_query_snapshot

    def get_snapshot_interface_properties(self, snapshot_dir: str | Path, snapshot_name: str) -> list[dict[str, Any]]:
        """Get interface properties of a snapshot without changing the active snapshot, querying once more after a lost
        Batfish state."""
        if self._initialized and self.current_snapshot_name == snapshot_name:
            logger.debug("Using the active Batfish snapshot '%s'", snapshot_name)
            events = self.state_loss_events
            try:
                interfaces = self.get_interface_properties(ospf_interfaces=[])
            except RuntimeError:
                if self.state_loss_events == events:
                    raise
                interfaces = None
            if self.state_loss_events == events:
                return interfaces
            for lost_dir, lost_name in self._lost_sides([(snapshot_name, snapshot_dir, events, True)]):
                logger.info("Reloading snapshot '%s' for interface lookup after Batfish lost it", lost_name)
                self._reload_side(lost_dir, lost_name)
            events = self.state_loss_events
            with self._query_snapshot_scope(snapshot_name):
                interfaces = self.get_interface_properties(ospf_interfaces=[])
            if self.state_loss_events != events:
                raise self._state_lost_failure("interfaceProperties")
            return interfaces

        logger.info("Loading snapshot '%s' for interface lookup without activating it", snapshot_name)
        self._load_snapshot(snapshot_dir, snapshot_name)
        events = self.state_loss_events
        with self._query_snapshot_scope(snapshot_name):
            interfaces = self.get_interface_properties(ospf_interfaces=[])
        if self.state_loss_events == events:
            return interfaces
        for lost_dir, lost_name in self._lost_sides([(snapshot_name, snapshot_dir, events, False)]):
            logger.info("Reloading snapshot '%s' for interface lookup after Batfish lost it", lost_name)
            self._reload_side(lost_dir, lost_name)
        events = self.state_loss_events
        with self._query_snapshot_scope(snapshot_name):
            interfaces = self.get_interface_properties(ospf_interfaces=[])
        if self.state_loss_events != events:
            raise self._state_lost_failure("interfaceProperties")
        return interfaces

    def get_batfish_version_info(self) -> dict[str, Any]:
        """Return cached version diagnostics without connecting to Batfish.

        Health checks call this, so it must stay non-blocking: the server
        version is only known after the first snapshot initialization has
        already opened a session.
        """
        return {
            "pybatfish_version": getattr(pybatfish, "__version__", None),
            "batfish_version": self._batfish_version,
        }

    @staticmethod
    def _query_timeout_context(query_name: str):
        """Bound one Batfish query under gevent workers.

        gevent.Timeout inherits from BaseException, so a raw expiry would
        bypass the `except Exception` error classification below. Passing a
        TimeoutError instance makes the expiry surface as a normal exception
        whose message matches the existing query_timeout classification.
        Outside gevent (unit tests, tooling) no bound is applied.
        """
        if gevent is None or gevent_monkey is None or not gevent_monkey.is_module_patched("socket"):
            return contextlib.nullcontext()

        timeout_seconds = config.BATFISH_QUERY_TIMEOUT_SECONDS
        return gevent.Timeout(
            timeout_seconds,
            TimeoutError(
                f"Batfish query '{query_name}' timed out after {timeout_seconds} seconds"
            ),
        )

    def _execute_query(
        self,
        query: Any,
        query_name: str,
        raise_on_error: bool = False,
        query_params: dict[str, Any] | None = None,
    ) -> pd.DataFrame | None:
        """Execute a Batfish query with error handling"""
        try:
            with self._query_timeout_context(query_name):
                result = query.answer().frame()
            if result.empty:
                logger.debug(f"Query '{query_name}' returned empty result")
                return None
            return result
        except Exception as e:
            query_error = self._refine_query_error(self._build_query_error(query_name, e, query_params=query_params))
            logger.warning("Query '%s' failed: %s", query_name, query_error.message)
            if raise_on_error:
                raise query_error from e
            self._count_query_failure()
            return None

    def _execute_query_factory(
        self,
        query_factory: Callable[[], Any],
        query_name: str,
        raise_on_error: bool = False,
        query_params: dict[str, Any] | None = None,
    ) -> pd.DataFrame | None:
        try:
            query = query_factory()
        except Exception as e:
            query_error = self._refine_query_error(self._build_query_error(query_name, e, query_params=query_params))
            logger.warning("Query '%s' failed before execution: %s", query_name, query_error.message)
            if raise_on_error:
                raise query_error from e
            self._count_query_failure()
            return None
        return self._execute_query(
            query,
            query_name,
            raise_on_error=raise_on_error,
            query_params=query_params,
        )

    def _sanitize_error_message(self, message: str) -> str:
        """Redact common secret-like values from Batfish exception strings."""
        return self._redact_secret_text(message)

    @classmethod
    def _redact_secret_text(cls, message: str) -> str:
        parts: list[str] = []
        cursor = 0
        search_pos = 0

        while True:
            match = cls._SECRET_ERROR_KEY_PATTERN.search(message, search_pos)
            if match is None:
                break

            if match.start() > 0 and (message[match.start() - 1].isalnum() or message[match.start() - 1] == "_"):
                search_pos = match.end()
                continue

            delimiter = match.group(2)
            value_start = match.end()
            if not cls._should_redact_secret_value(match.group(1), delimiter, message, value_start):
                search_pos = match.end()
                continue

            value_end = cls._secret_value_end(message, value_start)
            if value_end <= value_start:
                search_pos = match.end()
                continue

            parts.append(message[cursor:value_start])
            parts.append("[redacted]")
            cursor = value_end
            search_pos = value_end

        parts.append(message[cursor:])
        return cls._redact_standalone_bgp_communities("".join(parts))

    @staticmethod
    def _redact_standalone_bgp_communities(message: str) -> str:
        return re.sub(r"(?<![A-Za-z0-9_.:-])(?:\d{1,10}:){1,2}\d{1,10}(?![A-Za-z0-9_.:-])", "[redacted]", message)

    @staticmethod
    def _should_redact_secret_value(marker: str, delimiter: str, message: str, value_start: int) -> bool:
        if ":" in delimiter or "=" in delimiter:
            return True
        if value_start >= len(message):
            return False
        if message[value_start] in ("'", '"', "[", "{"):
            return True
        return "communit" in marker.lower() and BatfishService._starts_with_bgp_community(message, value_start)

    @staticmethod
    def _starts_with_bgp_community(message: str, value_start: int) -> bool:
        return re.match(r"(?:\d{1,10}:){1,2}\d{1,10}(?=$|[\s,;}\]])", message[value_start:]) is not None

    @classmethod
    def _secret_value_end(cls, message: str, start: int) -> int:
        if start >= len(message):
            return start

        first = message[start]
        if first in ("'", '"'):
            return cls._consume_quoted_value(message, start, first)
        if first in ("[", "{"):
            return cls._consume_balanced_value(message, start)

        index = start
        while index < len(message) and not message[index].isspace() and message[index] not in ",;}]":
            index += 1
        return index

    @staticmethod
    def _consume_quoted_value(message: str, start: int, quote: str) -> int:
        index = start + 1
        escaped = False
        while index < len(message):
            char = message[index]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                return index + 1
            index += 1
        return len(message)

    @classmethod
    def _consume_balanced_value(cls, message: str, start: int) -> int:
        pairs = {"[": "]", "{": "}"}
        stack = [pairs[message[start]]]
        index = start + 1
        quote: str | None = None
        escaped = False

        while index < len(message):
            char = message[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif char in pairs:
                stack.append(pairs[char])
            elif stack and char == stack[-1]:
                stack.pop()
                if not stack:
                    return index + 1
            index += 1

        return len(message)

    def _sanitize_error_detail(self, value: Any) -> Any:
        """Redact common secret-like values from structured error details."""
        if isinstance(value, str):
            return self._sanitize_error_message(value)
        if isinstance(value, list):
            return [self._sanitize_error_detail(item) for item in value]
        if isinstance(value, tuple):
            return [self._sanitize_error_detail(item) for item in value]
        if isinstance(value, dict):
            sanitized: dict[Any, Any] = {}
            for key, item in value.items():
                key_text = str(key).lower()
                if any(secret_key in key_text for secret_key in ("password", "secret", "token", "community", "communities")):
                    sanitized[key] = "[redacted]"
                else:
                    sanitized[key] = self._sanitize_error_detail(item)
            return sanitized
        return value

    @staticmethod
    def _extract_batfish_root_cause(message: str) -> str:
        """Reduce a Batfish work-log dump to its deepest root-cause line."""
        if "Work terminated abnormally" not in message:
            return message

        # Each cause ends at the next 'Caused by: '
        causes = re.findall(r"Caused by: ((?:(?!Caused by: )[^\n])+)", message)
        if not causes:
            return message

        root_cause = causes[-1].strip()
        # Cut at the first stack frame and drop the JSON quoting left at the boundary
        root_cause = JAVA_STACK_FRAME_IN_TEXT.split(root_cause)[0]
        root_cause = root_cause.rstrip().rstrip('",').rstrip()
        root_cause = re.sub(r"^(?:[A-Za-z0-9_.$]+(?:Exception|Error):\s*)+", "", root_cause)
        if not root_cause:
            return message
        if len(root_cause) > 500:
            root_cause = root_cause[:500] + "..."
        return f"Batfish work failed: {root_cause}"

    def _build_query_error(
        self,
        query_name: str,
        error: Exception,
        query_params: dict[str, Any] | None = None,
    ) -> BatfishQueryError:
        raw_message = str(error).strip() or error.__class__.__name__
        raw_message = self._extract_batfish_root_cause(raw_message)
        message = self._sanitize_error_message(raw_message)
        normalized = message.lower()
        error_type = "query_error"
        status_code = 400
        hints = [
            "Check that the active snapshot is initialized and the query inputs use Batfish syntax.",
        ]

        is_route_policy_query = query_name in self._ROUTE_POLICY_QUERY_NAMES
        is_node_specifier_parse_error = (
            ("nodespecifier" in normalized or "node specifier" in normalized)
            and ("error parsing" in normalized or "valid continuations" in normalized)
        )
        has_constraint_params = bool(query_params) and any(
            query_params.get(key) for key in ("inputConstraints", "outputConstraints")
        )
        coordinator_match = _COORDINATOR_HTTP_ERROR.search(message)
        coordinator_status = int(coordinator_match.group(1)) if coordinator_match else None
        coordinator_reason = (
            (coordinator_match.group(2) or "").strip() or None if coordinator_match else None
        )

        if coordinator_status is not None and coordinator_status >= 500:
            error_type = "batfish_coordinator_error"
            status_code = 502
            hints = [
                "Batfish rejected the request with a server error; details.reason carries the Batfish message.",
                "Verify the query parameters, especially route constraint syntax, before retrying.",
                "Check Batfish service health if this persists for valid inputs.",
            ]
        elif any(token in normalized for token in ("timed out", "timeout")):
            error_type = "query_timeout"
            status_code = 504
            hints = [
                "Reduce the query scope and retry.",
                "Check Batfish service health if the query repeatedly times out.",
            ]
        elif "max retries exceeded" in normalized or "too many 500 error responses" in normalized:
            error_type = "batfish_coordinator_error"
            status_code = 502
            hints = [
                "Batfish rejected the request with repeated server errors.",
                "Verify the query parameters, especially route constraint syntax, before retrying.",
                "Check Batfish service health if this persists for valid inputs.",
            ]
        elif "does not match any strings" in normalized or is_node_specifier_parse_error:
            if is_route_policy_query and has_constraint_params:
                error_type = "route_policy_constraint_no_match"
                hints = [
                    "An input/output constraint regex did not match any candidate strings.",
                    "Check the communities and asPath regexes in inputConstraints and outputConstraints.",
                    "Community regexes must be able to match values such as 65000:100; AS-path regexes match sequences of numeric AS numbers.",
                    "If the constraints look correct, inspect route-policy community and AS-path definitions in the snapshot configuration.",
                ]
            elif is_route_policy_query:
                error_type = "route_policy_specifier_no_match"
                hints = [
                    "Batfish could not resolve a specifier while evaluating route-policy analysis.",
                    "If the nodes parameter was provided, verify it matches existing Batfish node names or node regex, not an ASN.",
                    "If nodes is blank or valid, inspect route-policy AS-path, community, or policy references for values Batfish may interpret as specifiers.",
                    "Run Resolve Nodes and review parse warnings/init issues before retrying.",
                ]
            else:
                error_type = "specifier_no_match"
                hints = [
                    "Check node, policy, filter, or location specifiers before running the query.",
                    "For route policy tools, the nodes field must contain Batfish node names or node regex, not an ASN.",
                    "Leave the nodes field blank to query all nodes, or run Resolve Nodes first.",
                ]

        if is_route_policy_query:
            if error_type == "query_error":
                error_type = "route_policy_query_error"
            hints.append(
                "For route policy queries, verify policy names, route constraints, and BGP route-policy syntax in the active snapshot."
            )
            if (
                error_type not in ("route_policy_constraint_no_match", "batfish_coordinator_error")
                and ("as-path" in normalized or "as path" in normalized or "regex" in normalized)
            ):
                error_type = "route_policy_regex_conversion_error"
                hints.append(
                    "Some Batfish versions can fail when converting specific route-policy AS-path regex expressions; inspect parse warnings and retry after narrowing nodes or policies."
                )

        details: dict[str, Any] = {"query": query_name}
        if query_params:
            details["parameters"] = self._sanitize_error_detail(self._safe_serialize(query_params))
        if coordinator_status is not None:
            details["batfish_status_code"] = coordinator_status
            if coordinator_reason:
                details["reason"] = coordinator_reason

        query_error = BatfishQueryError(
            query_name=query_name,
            message=message,
            error_type=error_type,
            details=details,
            hints=hints,
            status_code=status_code,
        )
        try:
            response = _coordinator_response_of(error)
            query_error.from_coordinator_response = response is not None
            query_error.state_loss = self._classify_state_loss(response, coordinator_status, coordinator_reason)
        except Exception:
            query_error.from_coordinator_response = False
            query_error.state_loss = None
        return query_error

    @staticmethod
    def _classify_state_loss(response: Any, status: int | None, reason: str | None) -> tuple[str | None, bool] | None:
        """Return (snapshot name, network missing) when a coordinator error says Batfish lost its state."""
        text = None
        url = ""
        if response is not None:
            status = getattr(response, "status_code", status)
            try:
                text = response.text
            except Exception:
                text = None
            reason = _extract_coordinator_error_reason(text, redact=False) if text else None
            url = getattr(response, "url", None) or getattr(getattr(response, "request", None), "url", None) or ""
        if reason:
            if _LOST_NETWORK_REASON.match(reason):
                return None, True
            for pattern in (_LOST_SNAPSHOT_REASON, _SNAPSHOT_NOT_FOUND_REASON):
                match = pattern.match(reason)
                if match:
                    return match.group(1), False
        if status == 404 and response is not None and not (text or "").strip():
            match = _SNAPSHOT_URL_PATH.search(str(url))
            if match:
                return urllib.parse.unquote(match.group(2)), False
        return None

    def _record_state_loss(self, drop: bool, lost: Any = None) -> None:
        if drop:
            self._drop_loaded_state(lost)
        else:
            self._note_state_loss(lost)

    def _rebuilt_error(self, query_error: BatfishQueryError, error_type: str, hint: str) -> BatfishQueryError:
        rebuilt = BatfishQueryError(
            query_name=query_error.query_name,
            message=query_error.message,
            error_type=error_type,
            details=dict(query_error.details),
            hints=[hint],
            status_code=400,
        )
        rebuilt.state_loss = query_error.state_loss
        rebuilt.from_coordinator_response = query_error.from_coordinator_response
        return rebuilt

    def _state_lost(self, query_error: BatfishQueryError, drop: bool, identified: bool = True,
                    lost: Any = None) -> BatfishQueryError:
        self._record_state_loss(drop, lost)
        return self._rebuilt_error(
            query_error, "batfish_state_lost", STATE_LOST_HINT if identified else STATE_LOST_UNIDENTIFIED_HINT,
        )

    def _snapshot_not_loaded(self, query_error: BatfishQueryError, snapshot_name: str) -> BatfishQueryError:
        self._record_state_loss(drop=False, lost=snapshot_name)
        return self._rebuilt_error(
            query_error,
            "snapshot_not_loaded",
            f"Batfish does not hold snapshot '{snapshot_name}'; activate it once or run Compare with it to load it",
        )

    def _state_lost_failure(self, query_name: str) -> BatfishQueryError:
        return BatfishQueryError(
            query_name=query_name,
            message="Batfish lost the snapshot state again while the request was retried",
            error_type="batfish_state_lost",
            details={"query": query_name},
            hints=[STATE_LOST_HINT],
            status_code=400,
        )

    def _referenced_snapshots(self, answer_kwargs: dict[str, Any] | None) -> list[str]:
        kwargs = answer_kwargs or {}
        session_snapshot = self._session.snapshot if self._session is not None else None
        referenced = []
        for name in (kwargs.get("snapshot") or session_snapshot, kwargs.get("reference_snapshot")):
            if isinstance(name, str) and name and name not in referenced:
                referenced.append(name)
        return referenced

    def _missing_referenced_snapshot(self, referenced: list[str]) -> tuple[str, str | None] | None:
        """Check each referenced snapshot on the coordinator; return ('network', None), ('active', None),
        ('other', name) or None."""
        probe = self.version_probe
        if probe is None or self._state_service is None or not referenced:
            return None
        missing_other = None
        for name in referenced:
            status, body = probe.snapshot_status(self.network_name, name)
            if status != 404:
                continue
            reason = _extract_coordinator_error_reason(body, redact=False) if body else None
            if reason and _LOST_NETWORK_REASON.match(reason):
                return "network", None
            if name == self.current_snapshot_name:
                return "active", None
            if missing_other is None:
                missing_other = name
        return ("other", missing_other) if missing_other is not None else None

    def _refine_query_error(self, query_error: BatfishQueryError,
                            answer_kwargs: dict[str, Any] | None = None) -> BatfishQueryError:
        """Refine a coordinator error against the snapshots the query referenced, recording any lost state; never
        raises."""
        try:
            return self._refine(query_error, answer_kwargs)
        except Exception as e:
            logger.debug("Batfish state check after a query failure was skipped: %s", type(e).__name__)
            return query_error

    def _refine(self, query_error: BatfishQueryError, answer_kwargs: dict[str, Any] | None) -> BatfishQueryError:
        loss = query_error.state_loss
        if loss is not None:
            snapshot_name, network_missing = loss
            if network_missing:
                return self._state_lost(query_error, drop=True, lost=LOST_NETWORK)
            if snapshot_name and not any(marker in snapshot_name for marker in _REDACTED_NAME_MARKERS):
                if snapshot_name == self.current_snapshot_name:
                    return self._state_lost(query_error, drop=True)
                return self._snapshot_not_loaded(query_error, snapshot_name)
            try:
                missing = self._missing_referenced_snapshot(self._referenced_snapshots(answer_kwargs))
            except Exception:
                missing = None
            if missing is None:
                return self._state_lost(query_error, drop=False, identified=False, lost=LOST_UNIDENTIFIED)
            return self._missing_snapshot_error(query_error, missing)
        if not query_error.from_coordinator_response or self._state_service is None:
            return query_error
        try:
            missing = self._missing_referenced_snapshot(self._referenced_snapshots(answer_kwargs))
        except Exception:
            return query_error
        if missing is None:
            return query_error
        return self._missing_snapshot_error(query_error, missing)

    def _missing_snapshot_error(self, query_error: BatfishQueryError, missing: tuple) -> BatfishQueryError:
        if missing[0] == "network":
            return self._state_lost(query_error, drop=True, lost=LOST_NETWORK)
        if missing[0] == "active":
            return self._state_lost(query_error, drop=True)
        return self._snapshot_not_loaded(query_error, missing[1])

    def _aggregate_query_error_payload(self, data_key: str, error: BatfishQueryError) -> dict[str, Any]:
        """Create all-data metadata for a query failure while keeping array fallbacks compatible."""
        return {
            "data_key": data_key,
            "query": error.query_name,
            "code": error.error_type,
            "message": self._sanitize_error_message(error.message),
            "details": self._sanitize_error_detail(error.details),
            "hints": self._sanitize_error_detail(error.hints),
            "status_code": error.status_code,
        }

    def _set_aggregate_query_result(
        self,
        data: dict[str, Any],
        query_errors: list[dict[str, Any]],
        data_key: str,
        query_callable: Callable[[], Any],
        fallback: Any,
    ) -> None:
        try:
            data[data_key] = query_callable()
        except BatfishQueryError as e:
            safe_message = self._sanitize_error_message(e.message)
            logger.warning("Aggregate query '%s' failed: %s", data_key, safe_message)
            data[data_key] = fallback
            query_errors.append(self._aggregate_query_error_payload(data_key, e))

    def _convert_interfaces_to_strings(self, interfaces):
        """Convert Interface objects or lists to strings"""
        if not interfaces:
            return []
        if isinstance(interfaces, list):
            return [str(iface) if iface else "" for iface in interfaces]
        return [str(interfaces)]

    def _convert_ip_network_to_string(self, ip_obj):
        """Convert IP/Network objects to strings"""
        if not ip_obj:
            return None
        if isinstance(ip_obj, str):
            return ip_obj
        return str(ip_obj)

    def _safe_serialize(self, obj):
        """Safely convert any Batfish object to JSON-serializable format"""
        if obj is None:
            return None
        if isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, list):
            return [self._safe_serialize(item) for item in obj]
        if isinstance(obj, (set, frozenset)):
            return [self._safe_serialize(item) for item in obj]
        if isinstance(obj, tuple):
            return [self._safe_serialize(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self._safe_serialize(v) for k, v in obj.items()}
        if hasattr(obj, '__dict__'):
            return {k: self._safe_serialize(v) for k, v in vars(obj).items() if not k.startswith('_')}
        return str(obj)

    def _to_snake_case(self, value: str) -> str:
        """Convert Batfish column names to API-friendly snake_case."""
        normalized = re.sub(r"[^0-9A-Za-z]+", "_", value).strip("_")
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized).lower()

    def _dataframe_to_records(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        """Convert a Batfish DataFrame into JSON-safe dynamic records."""
        records: list[dict[str, Any]] = []
        for _, row in df.iterrows():
            records.append({
                self._to_snake_case(str(column)): self._safe_serialize(row.get(column))
                for column in df.columns
            })
        return records

    def _execute_query_records(
        self,
        query: Any,
        query_name: str,
        answer_kwargs: dict[str, Any] | None = None,
        query_params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a query and return dynamic records while preserving errors."""
        try:
            with self._query_timeout_context(query_name):
                result = query.answer(**(answer_kwargs or {})).frame()
            if result.empty:
                logger.debug(f"Query '{query_name}' returned empty result")
                return []
            return self._dataframe_to_records(result)
        except Exception as e:
            query_error = self._refine_query_error(
                self._build_query_error(query_name, e, query_params=query_params), answer_kwargs,
            )
            logger.warning("Query '%s' failed: %s", query_name, query_error.message)
            raise query_error from e

    def _execute_query_records_factory(
        self,
        query_factory: Callable[[], Any],
        query_name: str,
        answer_kwargs: dict[str, Any] | None = None,
        query_params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        try:
            query = query_factory()
        except Exception as e:
            query_error = self._refine_query_error(
                self._build_query_error(query_name, e, query_params=query_params), answer_kwargs,
            )
            logger.warning("Query '%s' failed before execution: %s", query_name, query_error.message)
            raise query_error from e
        return self._execute_query_records(
            query,
            query_name,
            answer_kwargs=answer_kwargs,
            query_params=query_params,
        )

    def _validate_route_policy_node_specifier(self, nodes: str | None, query_name: str) -> None:
        """Fail route-policy queries early when a provided node specifier resolves to no nodes."""
        if nodes is None:
            return

        query_params = {"nodes": nodes}
        try:
            df = self._execute_query_factory(
                lambda: self.session.q.resolveNodeSpecifier(nodes=nodes),
                f"{query_name}.resolveNodeSpecifier",
                raise_on_error=True,
            )
        except BatfishQueryError as e:
            if e.error_type != "specifier_no_match":
                raise BatfishQueryError(
                    query_name=query_name,
                    message=e.message,
                    error_type=e.error_type,
                    details={
                        "query": query_name,
                        "preflight": self._sanitize_error_detail(e.details),
                        "parameters": self._sanitize_error_detail(query_params),
                    },
                    hints=[
                        *e.hints,
                        "Node specifier preflight could not complete before running the route-policy query.",
                    ],
                    status_code=e.status_code,
                ) from e

            raise BatfishQueryError(
                query_name=query_name,
                message="The provided node specifier did not match any nodes in the active snapshot.",
                error_type="node_specifier_no_match",
                details={"query": query_name, "parameters": self._sanitize_error_detail(query_params)},
                hints=[
                    "The nodes field must match existing Batfish node names or node regex.",
                    "Do not enter an ASN in the nodes field; leave nodes blank to query all nodes.",
                    "Run Resolve Nodes first to confirm the node specifier.",
                ],
                status_code=400,
            ) from e

        if df is None or df.empty:
            raise BatfishQueryError(
                query_name=query_name,
                message="The provided node specifier did not match any nodes in the active snapshot.",
                error_type="node_specifier_no_match",
                details={"query": query_name, "parameters": self._sanitize_error_detail(query_params)},
                hints=[
                    "Use a Batfish node name or node regex in the nodes field.",
                    "If this value is an ASN, move it into route constraints instead of nodes.",
                    "Leave nodes blank to query all nodes.",
                ],
                status_code=400,
            )

        del df

    def _raise_invalid_route_policy_constraint(
        self,
        query_name: str,
        constraint_field: str,
        value_field: str,
        value: Any,
        reason: str,
    ) -> None:
        parameter_key = f"{constraint_field}.{value_field}"
        raise BatfishQueryError(
            query_name=query_name,
            message=f"Invalid {parameter_key} constraint: {reason}",
            error_type="route_policy_constraint_invalid",
            details={
                "query": query_name,
                "parameters": self._sanitize_error_detail({parameter_key: value}),
            },
            hints=[
                "Community constraints accept literal values such as 65000:100 or community regexes.",
                "AS-path constraints accept regexes over numeric AS numbers, such as ^8075$ or .*8075.*.",
                "Fix the constraint value and rerun the query.",
            ],
            status_code=400,
        )

    @staticmethod
    def _iter_constraint_values(raw_value: Any) -> list[Any]:
        """Normalize a BgpRouteConstraints field that accepts a string or a list."""
        if raw_value is None:
            return []
        if isinstance(raw_value, (list, tuple)):
            return list(raw_value)
        return [raw_value]

    def _validate_route_policy_constraints(
        self,
        query_name: str,
        input_constraints: Any,
        output_constraints: Any,
    ) -> None:
        """Reject constraint values Batfish fails on with server errors or internal exceptions."""
        for constraint_field, constraints in (
            ("inputConstraints", input_constraints),
            ("outputConstraints", output_constraints),
        ):
            if not isinstance(constraints, dict):
                continue

            for value in self._iter_constraint_values(constraints.get("asPath")):
                self._validate_as_path_constraint(query_name, constraint_field, value)
            for value in self._iter_constraint_values(constraints.get("communities")):
                self._validate_community_constraint(query_name, constraint_field, value)

    def _validate_as_path_constraint(self, query_name: str, constraint_field: str, value: Any) -> None:
        if not isinstance(value, str) or not value.strip():
            self._raise_invalid_route_policy_constraint(
                query_name, constraint_field, "asPath", value,
                "each asPath constraint must be a non-empty regex string",
            )
        try:
            re.compile(value)
        except re.error:
            self._raise_invalid_route_policy_constraint(
                query_name, constraint_field, "asPath", value,
                "the value is not a valid regular expression",
            )
        without_escape_pairs = re.sub(r"\\.", "", value)
        if not self._ROUTE_POLICY_AS_PATH_REGEX_ALLOWED.fullmatch(without_escape_pairs):
            self._raise_invalid_route_policy_constraint(
                query_name, constraint_field, "asPath", value,
                "AS-path regexes may contain only digits, whitespace, regex metacharacters, and escape sequences",
            )

    def _validate_community_constraint(self, query_name: str, constraint_field: str, value: Any) -> None:
        if not isinstance(value, str) or not value.strip():
            self._raise_invalid_route_policy_constraint(
                query_name, constraint_field, "communities", value,
                "each communities constraint must be a non-empty string",
            )
        try:
            re.compile(value)
        except re.error:
            self._raise_invalid_route_policy_constraint(
                query_name, constraint_field, "communities", value,
                "the value is not a valid regular expression",
            )

        standard = self._BGP_STANDARD_COMMUNITY_LITERAL.fullmatch(value)
        if standard and any(int(part) > 65535 for part in standard.groups()):
            self._raise_invalid_route_policy_constraint(
                query_name, constraint_field, "communities", value,
                "standard community parts must be within 0-65535",
            )

        large = self._BGP_LARGE_COMMUNITY_LITERAL.fullmatch(value)
        if large and any(int(part) > 4294967295 for part in large.groups()):
            self._raise_invalid_route_policy_constraint(
                query_name, constraint_field, "communities", value,
                "large community parts must be within 0-4294967295",
            )

    def _normalize_header_constraints(self, query_name: str, headers: Any) -> Any:
        """Validate HeaderConstraints integer fields and convert them into the comma-separated strings Batfish parses."""
        if not isinstance(headers, dict):
            return headers

        normalized = dict(headers)
        for field, maximum in self._HEADER_INTEGER_SPACE_FIELDS.items():
            value = normalized.get(field)
            if value is None:
                continue
            if isinstance(value, str) or self._is_non_negative_int(value):
                items = [value]
            elif isinstance(value, (list, tuple)):
                items = list(value)
            else:
                self._raise_invalid_header_constraint(query_name, field, value)

            atoms: list[str] = []
            included: list[tuple[int, int]] = []
            excluded: list[tuple[int, int]] = []
            for item in items:
                if self._is_non_negative_int(item):
                    raw_atoms = [str(item)]
                elif isinstance(item, str):
                    raw_atoms = item.split(",")
                else:
                    self._raise_invalid_header_constraint(query_name, field, value)
                for raw_atom in raw_atoms:
                    atom = raw_atom.strip()
                    if atom:
                        text, is_exclusion, low, high = self._validated_integer_space_atom(
                            query_name, field, value, atom, maximum
                        )
                        atoms.append(text)
                        (excluded if is_exclusion else included).append((low, high))
            if not atoms:
                del normalized[field]
                continue
            if self._integer_ranges_cover(excluded, included or [(0, maximum)]):
                self._raise_invalid_header_constraint(
                    query_name, field, value,
                    f"no value within the allowed range 0-{maximum} remains after the exclusions",
                )
            normalized[field] = ",".join(atoms)
        return normalized

    @staticmethod
    def _integer_ranges_cover(covering: list[tuple[int, int]], ranges: list[tuple[int, int]]) -> bool:
        """Return True when the inclusive integer ranges in covering contain every value of ranges."""
        merged: list[list[int]] = []
        for low, high in sorted(covering):
            if merged and low <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], high)
            else:
                merged.append([low, high])
        return all(
            any(merged_low <= low and high <= merged_high for merged_low, merged_high in merged)
            for low, high in ranges
        )

    def _validated_integer_space_atom(
        self,
        query_name: str,
        field: str,
        value: Any,
        atom: str,
        maximum: int,
    ) -> tuple[str, bool, int, int]:
        """Return one IntegerSpace item in canonical form with its exclusion flag and bounds.

        Raises BatfishQueryError when Batfish would reject the item.
        """
        match = self._HEADER_INTEGER_SPACE_ATOM.fullmatch(atom)
        shown = atom if len(atom) <= 40 else atom[:40] + "..."
        if match is None:
            self._raise_invalid_header_constraint(
                query_name, field, value,
                f"\"{shown}\" is not a value or range such as \"8\" or \"0-8\"",
            )
        exclusion, low_text, high_text = match.groups()
        low_text = low_text.lstrip("0") or "0"
        if high_text is not None:
            high_text = high_text.lstrip("0") or "0"
        if any(
            len(text) > self._HEADER_INTEGER_SPACE_MAX_DIGITS
            for text in (low_text, high_text)
            if text is not None
        ):
            self._raise_invalid_header_constraint(
                query_name, field, value,
                f"\"{shown}\" is outside the allowed range 0-{maximum}",
            )
        low = int(low_text)
        high = int(high_text) if high_text is not None else low
        if high > maximum:
            self._raise_invalid_header_constraint(
                query_name, field, value,
                f"\"{shown}\" is outside the allowed range 0-{maximum}",
            )
        if low > high:
            self._raise_invalid_header_constraint(
                query_name, field, value,
                f"range \"{shown}\" starts above its end",
            )
        text = f"{exclusion}{low}" if high_text is None else f"{exclusion}{low}-{high}"
        return text, bool(exclusion), low, high

    @staticmethod
    def _is_non_negative_int(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    def _raise_invalid_header_constraint(
        self,
        query_name: str,
        field: str,
        value: Any,
        reason: str | None = None,
    ) -> NoReturn:
        parameter_key = f"headers.{field}"
        maximum = self._HEADER_INTEGER_SPACE_FIELDS[field]
        raise BatfishQueryError(
            query_name=query_name,
            message=f"Invalid {parameter_key}: " + (
                reason
                or "expected a string such as \"0,8\" or \"0-8\", a non-negative integer, or a list of them"
            ),
            error_type="header_constraint_invalid",
            details={
                "query": query_name,
                "parameters": self._sanitize_error_detail({parameter_key: self._safe_serialize(value)}),
                "allowed_range": f"0-{maximum}",
            },
            hints=[
                "Send integer header fields as comma-separated values and ranges, for example \"0,8\" or \"1024-65535\".",
                f"Values of {parameter_key} must be within 0-{maximum}.",
            ],
            status_code=400,
        )

    def _unavailable_capability(
        self,
        capability: str,
        reason: str,
        alternatives: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return explicit metadata for Batfish capabilities unavailable in pybatfish."""
        logger.warning("%s is unavailable: %s", capability, reason)
        return [{
            "available": False,
            "capability": capability,
            "reason": reason,
            "alternatives": alternatives or [],
            "data": [],
        }]

    def get_node_properties(self) -> list[dict[str, Any]]:
        """Get node properties for all devices"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.nodeProperties(), "nodeProperties")
        if df is None:
            return []

        nodes = []
        for _, row in df.iterrows():
            node_data = {
                "node": row.get("Node", ""),
                "configuration_format": row.get("Configuration_Format"),
                "dns_servers": row.get("DNS_Servers", []),
                "dns_source_interface": str(row.get("DNS_Source_Interface")) if row.get("DNS_Source_Interface") else None,
                "domain_name": row.get("Domain_Name"),
                "hostname": row.get("Hostname", ""),
                "ipsec_vpns": row.get("IPsec_VPNs", []),
                "interfaces": self._convert_interfaces_to_strings(row.get("Interfaces", [])),
                "logging_servers": row.get("Logging_Servers", []),
                "logging_source_interface": str(row.get("Logging_Source_Interface")) if row.get("Logging_Source_Interface") else None,
                "ntp_servers": row.get("NTP_Servers", []),
                "ntp_source_interface": str(row.get("NTP_Source_Interface")) if row.get("NTP_Source_Interface") else None,
                "snmp_source_interface": str(row.get("SNMP_Source_Interface")) if row.get("SNMP_Source_Interface") else None,
                "snmp_trap_servers": row.get("SNMP_Trap_Servers", []),
                "tacacs_servers": row.get("TACACS_Servers", []),
                "tacacs_source_interface": str(row.get("TACACS_Source_Interface")) if row.get("TACACS_Source_Interface") else None,
                "vendor": row.get("Vendor", ""),
                "vrfs": row.get("VRFs", []),
                "zones": row.get("Zones", []),
            }
            nodes.append(node_data)

        del df
        return nodes

    def get_interface_properties(
        self, ospf_interfaces: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Get interface properties for all interfaces"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.interfaceProperties(), "interfaceProperties")
        if df is None:
            return []

        if ospf_interfaces is None:
            ospf_interfaces = [i.to_dict() for i in self.get_ospf_interface_configuration()]
        ospf_by_interface = {ospf.get("interface"): ospf for ospf in ospf_interfaces}

        interfaces = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            interface_str = str(interface_raw) if interface_raw else ""

            hostname = ""
            interface_name = ""

            if '[' in interface_str and ']' in interface_str:
                parts = interface_str.split('[', 1)
                hostname = parts[0]
                interface_name = parts[1].rstrip(']')
            else:
                interface_name = interface_str

            ospf = ospf_by_interface.get(interface_str, {})
            interface_data = {
                "hostname": hostname,
                "interface": interface_name,
                "access_vlan": row.get("Access_VLAN"),
                "active": row.get("Active", False),
                "admin_up": row.get("Admin_Up", False),
                "all_prefixes": [str(p) for p in row.get("All_Prefixes", [])] if row.get("All_Prefixes") else [],
                "allowed_vlans": row.get("Allowed_VLANs", []),
                "auto_state_vlan": row.get("Auto_State_VLAN", True),
                "bandwidth": row.get("Bandwidth"),
                "blacklisted": row.get("Blacklisted", False),
                "channel_group": row.get("Channel_Group"),
                "channel_group_members": [str(m) for m in row.get("Channel_Group_Members", [])] if row.get("Channel_Group_Members") else [],
                "declared_names": row.get("Declared_Names", []),
                "description": row.get("Description", ""),
                "encapsulation_vlan": row.get("Encapsulation_VLAN"),
                "hsrp_groups": row.get("HSRP_Groups", []),
                "hsrp_version": row.get("HSRP_Version"),
                "incoming_filter_name": row.get("Incoming_Filter_Name"),
                "interface_type": row.get("Interface_Type", ""),
                "mtu": row.get("MTU", 1500),
                "native_vlan": row.get("Native_VLAN"),
                "ospf_area_name": _normalize_json_scalar(ospf.get("ospf_area_name")),
                "ospf_cost": _normalize_json_scalar(ospf.get("ospf_cost")),
                "ospf_enabled": bool(_normalize_json_scalar(ospf.get("ospf_enabled"))),
                "ospf_network_type": _normalize_json_scalar(ospf.get("ospf_network_type")),
                "ospf_passive": bool(_normalize_json_scalar(ospf.get("ospf_passive"))),
                "outgoing_filter_name": row.get("Outgoing_Filter_Name"),
                "primary_address": self._convert_ip_network_to_string(row.get("Primary_Address")),
                "primary_network": self._convert_ip_network_to_string(row.get("Primary_Network")),
                "proxy_arp": row.get("Proxy_ARP", False),
                "rip_enabled": bool(_normalize_json_scalar(row.get("Rip_Enabled"))),
                "rip_passive": bool(_normalize_json_scalar(row.get("Rip_Passive"))),
                "speed": row.get("Speed"),
                "switchport": row.get("Switchport", False),
                "switchport_mode": row.get("Switchport_Mode", ""),
                "switchport_trunk_encapsulation": row.get("Switchport_Trunk_Encapsulation", ""),
                "vlan": self._interface_vlan(row),
                "vrf": row.get("VRF", "default"),
                "zone": _normalize_json_scalar(row.get("Zone_Name")),
            }
            interfaces.append(interface_data)

        del df
        return interfaces

    @staticmethod
    def _interface_vlan(row: Any) -> Any:
        """Return the access VLAN of an access-mode switchport, else the encapsulation VLAN of a subinterface, else None."""
        if str(row.get("Switchport_Mode") or "").upper() == "ACCESS":
            return _normalize_json_scalar(row.get("Access_VLAN"))
        return _normalize_json_scalar(row.get("Encapsulation_VLAN"))

    def get_routes(self) -> list[dict[str, Any]]:
        """Get routing table entries"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.routes(), "routes")
        if df is None:
            return []

        routes = []
        for _, row in df.iterrows():
            next_hop_interface_raw = row.get("Next_Hop_Interface")
            next_hop_interface = str(next_hop_interface_raw) if next_hop_interface_raw else ""

            next_hop_raw = row.get("Next_Hop", "")
            next_hop = str(next_hop_raw) if next_hop_raw else ""

            next_hop_ip_raw = row.get("Next_Hop_IP")
            next_hop_ip = str(next_hop_ip_raw) if next_hop_ip_raw else None

            route_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "network": row.get("Network", ""),
                "next_hop": next_hop,
                "next_hop_ip": next_hop_ip,
                "next_hop_interface": next_hop_interface,
                "protocol": row.get("Protocol", ""),
                "metric": row.get("Metric"),
                "admin_distance": row.get("Admin_Distance"),
                "tag": row.get("Tag"),
            }
            routes.append(route_data)

        del df
        return routes

    def get_ospf_process_configuration(self) -> list[OSPFProcessConfig]:
        """Get OSPF process configurations"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfProcessConfiguration(), "ospfProcessConfiguration")
        if df is None:
            return []

        processes = []
        for _, row in df.iterrows():
            process_id_raw = row.get("Process_ID", 0)
            try:
                process_id = int(process_id_raw) if process_id_raw != "default" else 0
            except (ValueError, TypeError):
                logger.warning(f"Invalid Process_ID '{process_id_raw}' for node {row.get('Node')}, using 0")
                process_id = 0

            process = OSPFProcessConfig(
                node=row.get("Node", ""),
                vrf=row.get("VRF", "default"),
                process_id=process_id,
                areas=row.get("Areas", []),
                reference_bandwidth=row.get("Reference_Bandwidth"),
                router_id=row.get("Router_ID"),
                export_policy_sources=row.get("Export_Policy_Sources", []),
                area_border_router=row.get("Area_Border_Router", False)
            )
            processes.append(process)

        del df
        return processes

    def get_ospf_area_configuration(self) -> list[OSPFAreaConfig]:
        """Get OSPF area configurations"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfAreaConfiguration(), "ospfAreaConfiguration")
        if df is None:
            return []

        areas = []
        for _, row in df.iterrows():
            active_interfaces_raw = row.get("Interfaces", [])
            active_interfaces = []
            if isinstance(active_interfaces_raw, list):
                for iface in active_interfaces_raw:
                    active_interfaces.append(str(iface))
            else:
                active_interfaces = [str(active_interfaces_raw)] if active_interfaces_raw else []

            passive_interfaces_raw = row.get("Passive_Interfaces", [])
            passive_interfaces = []
            if isinstance(passive_interfaces_raw, list):
                for iface in passive_interfaces_raw:
                    passive_interfaces.append(str(iface))
            else:
                passive_interfaces = [str(passive_interfaces_raw)] if passive_interfaces_raw else []

            process_id_raw = row.get("Process_ID", 0)
            try:
                process_id = int(process_id_raw) if process_id_raw != "default" else 0
            except (ValueError, TypeError):
                logger.warning(f"Invalid Process_ID '{process_id_raw}' for node {row.get('Node')}, using 0")
                process_id = 0

            area = OSPFAreaConfig(
                node=row.get("Node", ""),
                vrf=row.get("VRF", "default"),
                process_id=process_id,
                area=str(row.get("Area", "")),
                area_type=row.get("Area_Type", "NONE"),
                active_interfaces=active_interfaces,
                passive_interfaces=passive_interfaces
            )
            areas.append(area)

        del df
        return areas

    def get_ospf_interface_configuration(self) -> list[OSPFInterfaceConfig]:
        """Get OSPF interface configurations"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfInterfaceConfiguration(), "ospfInterfaceConfiguration")
        if df is None:
            return []

        interfaces = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            interface_str = str(interface_raw) if interface_raw else ""

            process_id_raw = row.get("Process_ID", 0)
            try:
                process_id = int(process_id_raw) if process_id_raw != "default" else 0
            except (ValueError, TypeError):
                logger.warning(f"Invalid Process_ID '{process_id_raw}' for interface {interface_str}, using 0")
                process_id = 0

            interface = OSPFInterfaceConfig(
                interface=interface_str,
                vrf=row.get("VRF", "default"),
                process_id=process_id,
                ospf_area_name=str(row.get("OSPF_Area_Name", "")),
                ospf_enabled=row.get("OSPF_Enabled", True),
                ospf_passive=row.get("OSPF_Passive", False),
                ospf_cost=row.get("OSPF_Cost"),
                ospf_network_type=row.get("OSPF_Network_Type"),
                ospf_hello_interval=row.get("OSPF_Hello_Interval"),
                ospf_dead_interval=row.get("OSPF_Dead_Interval")
            )
            interfaces.append(interface)

        del df
        return interfaces

    def get_ospf_session_compatibility(self) -> list[OSPFSessionCompat]:
        """Get OSPF session compatibility status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfSessionCompatibility(), "ospfSessionCompatibility")
        if df is None:
            return []

        sessions = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            session = OSPFSessionCompat(
                interface=str(interface_raw) if interface_raw else "",
                vrf=row.get("VRF", "default"),
                ip=row.get("IP", ""),
                area=str(row.get("Area", "")),
                remote_interface=str(remote_interface_raw) if remote_interface_raw else "",
                remote_vrf=row.get("Remote_VRF", "default"),
                remote_ip=row.get("Remote_IP", ""),
                remote_area=str(row.get("Remote_Area", "")),
                session_status=row.get("Session_Status", "UNKNOWN")
            )
            sessions.append(session)

        del df
        return sessions

    def get_ospf_edges(self) -> list[dict[str, Any]]:
        """Get OSPF topology edges"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ospfEdges(), "ospfEdges")
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            edge_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "ip": row.get("IP", ""),
                "remote_ip": row.get("Remote_IP", "")
            }
            edges.append(edge_data)

        del df
        return edges

    def get_edges(self) -> list[dict[str, Any]]:
        """Get layer 1 physical edges"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.edges(), "edges")
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            edge_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else ""
            }
            edges.append(edge_data)

        del df
        return edges

    def get_layer3_edges(self) -> list[dict[str, Any]]:
        """Get layer 3 edges"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.layer3Edges(), "layer3Edges")
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")

            edge_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "ips": [str(ip) for ip in row.get("IPs", [])] if row.get("IPs") else [],
                "remote_ips": [str(ip) for ip in row.get("Remote_IPs", [])] if row.get("Remote_IPs") else []
            }
            edges.append(edge_data)

        del df
        return edges

    def get_switched_vlan_properties(self) -> list[dict[str, Any]]:
        """Get switched VLAN properties"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.switchedVlanProperties(), "switchedVlanProperties")
        if df is None:
            return []

        vlans = []
        for _, row in df.iterrows():
            vlan_data = {
                "node": row.get("Node", ""),
                "vlan_id": row.get("VLAN_ID"),
                "interfaces": self._convert_interfaces_to_strings(row.get("Interfaces", [])),
                "interface_vlans": self._convert_interfaces_to_strings(row.get("Interface_VLANs", [])),
                "vxlan_vni": row.get("VXLAN_VNI")
            }
            vlans.append(vlan_data)

        del df
        return vlans

    def get_ip_owners(self) -> list[dict[str, Any]]:
        """Get IP address ownership mapping"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ipOwners(), "ipOwners")
        if df is None:
            return []

        owners = []
        for _, row in df.iterrows():
            owner_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "interface": row.get("Interface", ""),
                "ip": row.get("IP", ""),
                "mask": row.get("Mask", ""),
                "active": row.get("Active", False)
            }
            owners.append(owner_data)

        del df
        return owners

    def get_defined_structures(self) -> list[DefinedStructure]:
        """Get defined configuration structures"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.definedStructures(), "definedStructures")
        if df is None:
            return []

        structures = []
        for _, row in df.iterrows():
            source_lines_raw = row.get("Source_Lines", [])
            source_lines = []
            if source_lines_raw:
                if hasattr(source_lines_raw, '__class__') and 'FileLines' in str(source_lines_raw.__class__):
                    source_lines = [str(source_lines_raw)]
                elif isinstance(source_lines_raw, list):
                    for item in source_lines_raw:
                        if hasattr(item, '__class__') and 'FileLines' in str(item.__class__):
                            source_lines.append(str(item))
                        else:
                            source_lines.append(item if isinstance(item, str) else str(item))
                else:
                    source_lines = [str(source_lines_raw)]

            structure = DefinedStructure(
                structure_type=row.get("Structure_Type", ""),
                structure_name=row.get("Structure_Name", ""),
                source_lines=source_lines
            )
            structures.append(structure)

        del df
        return structures

    def get_referenced_structures(self) -> list[ReferencedStructure]:
        """Get referenced configuration structures"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.referencedStructures(), "referencedStructures")
        if df is None:
            return []

        structures = []
        for _, row in df.iterrows():
            source_lines_raw = row.get("Source_Lines", [])
            source_lines = []
            if source_lines_raw:
                if hasattr(source_lines_raw, '__class__') and 'FileLines' in str(source_lines_raw.__class__):
                    source_lines = [str(source_lines_raw)]
                elif isinstance(source_lines_raw, list):
                    for item in source_lines_raw:
                        if hasattr(item, '__class__') and 'FileLines' in str(item.__class__):
                            source_lines.append(str(item))
                        else:
                            source_lines.append(item if isinstance(item, str) else str(item))
                else:
                    source_lines = [str(source_lines_raw)]

            structure = ReferencedStructure(
                structure_type=row.get("Structure_Type", ""),
                structure_name=row.get("Structure_Name", ""),
                context=row.get("Context", ""),
                source_lines=source_lines
            )
            structures.append(structure)

        del df
        return structures

    def get_named_structures(self) -> list[NamedStructure]:
        """Get named structures with full definitions"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.namedStructures(), "namedStructures")
        if df is None:
            return []

        structures = []
        for _, row in df.iterrows():
            structure = NamedStructure(
                node=row.get("Node", ""),
                structure_type=row.get("Structure_Type", ""),
                structure_name=row.get("Structure_Name", ""),
                structure_definition=self._safe_serialize(row.get("Structure_Definition", {}))
            )
            structures.append(structure)

        del df
        return structures

    def get_file_parse_status(self) -> list[FileParseStatus]:
        """Get file parse status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.fileParseStatus(), "fileParseStatus")
        if df is None:
            return []

        statuses = []
        for _, row in df.iterrows():
            status = FileParseStatus(
                file_name=row.get("File_Name", ""),
                status=row.get("Status", ""),
                file_format=row.get("File_Format"),
                nodes=row.get("Nodes", [])
            )
            statuses.append(status)

        del df
        return statuses

    def get_init_issues(self) -> list[InitIssue]:
        """Get initialization issues"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.initIssues(), "initIssues")
        if df is None:
            return []

        issues = []
        for _, row in df.iterrows():
            source_lines_raw = row.get("Source_Lines", [])
            source_lines = []
            if source_lines_raw:
                if hasattr(source_lines_raw, '__class__') and 'FileLines' in str(source_lines_raw.__class__):
                    source_lines = [str(source_lines_raw)]
                elif isinstance(source_lines_raw, list):
                    source_lines = []
                    for item in source_lines_raw:
                        if hasattr(item, '__class__') and 'FileLines' in str(item.__class__):
                            source_lines.append(str(item))
                        else:
                            source_lines.append(item if isinstance(item, str) else str(item))
                else:
                    source_lines = [str(source_lines_raw)]

            issue = InitIssue(
                nodes=row.get("Nodes"),
                source_lines=source_lines,
                type=row.get("Type", ""),
                details=row.get("Details", ""),
                line_text=row.get("Line_Text", ""),
                parser_context=row.get("Parser_Context", "")
            )
            issues.append(issue)

        del df
        return issues

    def get_parse_warnings(self) -> list[ParseWarning]:
        """Get parse warnings"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.parseWarning(), "parseWarning")
        if df is None:
            return []

        warnings = []
        for _, row in df.iterrows():
            text_raw = row.get("Text", "")
            text = text_raw if isinstance(text_raw, str) else str(text_raw)

            parser_context_raw = row.get("Parser_Context", "")
            if hasattr(parser_context_raw, '__class__') and 'FileLines' in str(parser_context_raw.__class__):
                parser_context = str(parser_context_raw)
            else:
                parser_context = parser_context_raw if isinstance(parser_context_raw, str) else str(parser_context_raw)

            comment_raw = row.get("Comment", "")
            if hasattr(comment_raw, '__class__') and 'FileLines' in str(comment_raw.__class__):
                comment = str(comment_raw)
            else:
                comment = comment_raw if isinstance(comment_raw, str) else str(comment_raw)

            warning = ParseWarning(
                filename=row.get("Filename", ""),
                line=int(row.get("Line", 0)),
                text=text,
                parser_context=parser_context,
                comment=comment
            )
            warnings.append(warning)

        del df
        return warnings

    def get_vi_conversion_status(self) -> list[ViConversionStatus]:
        """Get vendor-independent conversion status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.viConversionStatus(), "viConversionStatus")
        if df is None:
            return []

        statuses = []
        for _, row in df.iterrows():
            status = ViConversionStatus(
                node=row.get("Node", ""),
                status=row.get("Status", "")
            )
            statuses.append(status)

        del df
        return statuses

    def get_reachability(
        self,
        headers: dict[str, Any] | None = None,
        pathConstraints: dict[str, Any] | None = None,
        actions: str | list[str] | None = None,
        maxTraces: int | None = None,
        invertSearch: bool | None = None,
        ignoreFilters: bool | None = None,
    ) -> list[FlowTrace]:
        """Get reachability analysis results"""
        self._ensure_initialized()
        headers = self._normalize_header_constraints("reachability", headers)

        query_params: dict[str, Any] = {}
        if headers is not None:
            query_params["headers"] = headers
        if pathConstraints is not None:
            query_params["pathConstraints"] = pathConstraints
        if actions is not None:
            query_params["actions"] = actions
        if maxTraces is not None:
            query_params["maxTraces"] = maxTraces
        if invertSearch is not None:
            query_params["invertSearch"] = invertSearch
        if ignoreFilters is not None:
            query_params["ignoreFilters"] = ignoreFilters

        query = self.session.q.reachability(**query_params)
        df = self._execute_query(query, "reachability")
        if df is None:
            return []

        flow_traces = []
        for _, row in df.iterrows():
            traces_raw = row.get("Traces", [])
            traces = []
            if traces_raw:
                for trace in traces_raw:
                    traces.append(str(trace))

            flow_trace = FlowTrace(
                flow=str(row.get("Flow", "")),
                traces=traces,
                trace_count=int(row.get("TraceCount", 0))
            )
            flow_traces.append(flow_trace)

        del df
        return flow_traces

    def get_search_route_policies(
        self,
        nodes: str | None = ".*",
        action: str = "permit",
        policies: str | None = None,
        inputConstraints: dict[str, Any] | None = None,
        outputConstraints: dict[str, Any] | None = None,
        perPath: bool | None = None,
        pathOption: str | None = None,
        raise_on_error: bool = True,
    ) -> list[dict[str, Any]]:
        """Search route policies"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {"action": action}
        if nodes is not None:
            query_params["nodes"] = nodes
        if policies is not None:
            query_params["policies"] = policies
        if inputConstraints is not None:
            query_params["inputConstraints"] = inputConstraints
        if outputConstraints is not None:
            query_params["outputConstraints"] = outputConstraints
        if perPath is not None:
            query_params["perPath"] = perPath
        if pathOption is not None:
            query_params["pathOption"] = pathOption

        try:
            self._validate_route_policy_constraints(
                "searchRoutePolicies", inputConstraints, outputConstraints
            )
            self._validate_route_policy_node_specifier(nodes, "searchRoutePolicies")
        except BatfishQueryError as e:
            if raise_on_error:
                raise
            logger.warning("searchRoutePolicies preflight failed: %s", self._sanitize_error_message(e.message))
            return []

        df = self._execute_query_factory(
            lambda: self.session.q.searchRoutePolicies(**query_params),
            "searchRoutePolicies",
            raise_on_error=raise_on_error,
            query_params=query_params,
        )
        if df is None:
            return []

        results = self._dataframe_to_records(df)
        del df
        return results

    def get_aaa_authentication_login(self) -> list[dict[str, Any]]:
        """Get AAA authentication login configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.aaaAuthenticationLogin(), "aaaAuthenticationLogin")
        if df is None:
            return []

        aaa_configs = []
        for _, row in df.iterrows():
            aaa_data = {
                "node": row.get("Node", ""),
                "methods": row.get("Methods", []),
                "list_name": row.get("List_Name", "default")
            }
            aaa_configs.append(aaa_data)

        del df
        return aaa_configs

    @staticmethod
    def _mask_snmp_community(community: str) -> str:
        """Mask an SNMP community string, keeping only its first character."""
        return f"{community[0]}***" if len(community) > 1 else "***"

    def get_snmp_community_clients(
        self, named_structures: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Get SNMP communities (masked) and the access list that limits their clients."""
        self._ensure_initialized()

        if named_structures is None:
            df = self._execute_query(self.session.q.namedStructures(structureTypes="VRF"), "namedStructures")
            if df is None:
                return []
            vrf_definitions = [(row.get("Node", ""), row.get("Structure_Definition")) for _, row in df.iterrows()]
            del df
        else:
            vrf_definitions = [
                (structure.get("node", ""), structure.get("structure_definition"))
                for structure in named_structures
                if structure.get("structure_type") == "VRF"
            ]

        snmp_configs = []
        for node, definition in vrf_definitions:
            snmp_server = definition.get("snmpServer") if isinstance(definition, dict) else None
            communities = snmp_server.get("communities") if isinstance(snmp_server, dict) else None
            for community_name, community in (communities.items() if isinstance(communities, dict) else ()):
                access_list = community.get("accessList") if isinstance(community, dict) else None
                snmp_data = {
                    "node": node,
                    "community": self._mask_snmp_community(str(community_name)),
                    "client_ips": [access_list] if isinstance(access_list, str) and access_list else [],
                }
                snmp_configs.append(snmp_data)

        return snmp_configs

    def get_bgp_edges(self, raise_on_error: bool = True) -> list[dict[str, Any]]:
        """Get BGP adjacencies/neighbors topology"""
        self._ensure_initialized()

        df = self._execute_query_factory(
            lambda: self.session.q.bgpEdges(),
            "bgpEdges",
            raise_on_error=raise_on_error,
        )
        if df is None:
            return []

        edges = []
        for _, row in df.iterrows():
            edge_data = {
                "node": row.get("Node", ""),
                "interface": str(row.get("Interface")) if row.get("Interface") else None,
                "remote_node": row.get("Remote_Node", ""),
                "remote_interface": str(row.get("Remote_Interface")) if row.get("Remote_Interface") else None,
                "remote_ip": row.get("Remote_IP", ""),
                "local_ip": _normalize_json_scalar(row.get("IP")),
                "remote_asn": _normalize_json_scalar(row.get("Remote_AS_Number")),
                "local_asn": _normalize_json_scalar(row.get("AS_Number")),
            }
            edges.append(edge_data)

        del df
        return edges

    def get_bgp_peer_configuration(self, raise_on_error: bool = True) -> list[dict[str, Any]]:
        """Get BGP peer settings and configurations"""
        self._ensure_initialized()

        df = self._execute_query_factory(
            lambda: self.session.q.bgpPeerConfiguration(),
            "bgpPeerConfiguration",
            raise_on_error=raise_on_error,
        )
        if df is None:
            return []

        peers = []
        for _, row in df.iterrows():
            peer_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "local_as": row.get("Local_AS"),
                "local_ip": row.get("Local_IP", ""),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "confederation": row.get("Confederation"),
                "remote_as": row.get("Remote_AS"),
                "remote_ip": row.get("Remote_IP", ""),
                "peer_address": row.get("Remote_IP", ""),
                "description": row.get("Description", ""),
                "ebgp_multihop": row.get("EBGP_Multihop", False),
                "peer_group": row.get("Peer_Group", ""),
                "import_policy": row.get("Import_Policy", []),
                "export_policy": row.get("Export_Policy", []),
                "send_community": row.get("Send_Community", False),
                "route_reflector_client": row.get("Route_Reflector_Client", False),
                "cluster_id": row.get("Cluster_ID"),
                "shutdown": row.get("Is_Shutdown", False),
                "passive": row.get("Is_Passive", False)
            }
            peers.append(peer_data)

        del df
        return peers

    def get_bgp_process_configuration(self, raise_on_error: bool = True) -> list[dict[str, Any]]:
        """Get BGP process-wide settings"""
        self._ensure_initialized()

        df = self._execute_query_factory(
            lambda: self.session.q.bgpProcessConfiguration(),
            "bgpProcessConfiguration",
            raise_on_error=raise_on_error,
        )
        if df is None:
            return []

        processes = []
        for _, row in df.iterrows():
            process_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "router_id": row.get("Router_ID", ""),
                "confederation_id": row.get("Confederation_ID"),
                "confederation_members": row.get("Confederation_Members", []),
                "multipath_equivalent_as_path_match_mode": row.get("Multipath_Equivalent_As_Path_Match_Mode", ""),
                "multipath_ebgp": row.get("Multipath_EBGP", False),
                "multipath_ibgp": row.get("Multipath_IBGP", False),
                "neighbors": row.get("Neighbors", []),
                "tie_breaker": row.get("Tie_Breaker", "")
            }
            processes.append(process_data)

        del df
        return processes

    def get_bgp_session_status(self, raise_on_error: bool = True) -> list[dict[str, Any]]:
        """Get BGP session operational status"""
        self._ensure_initialized()

        df = self._execute_query_factory(
            lambda: self.session.q.bgpSessionStatus(),
            "bgpSessionStatus",
            raise_on_error=raise_on_error,
        )
        if df is None:
            return []

        sessions = []
        for _, row in df.iterrows():
            session_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "local_as": row.get("Local_AS"),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "local_ip": row.get("Local_IP", ""),
                "remote_as": row.get("Remote_AS"),
                "remote_node": row.get("Remote_Node", ""),
                "remote_ip": row.get("Remote_IP", ""),
                "address_families": row.get("Address_Families", []),
                "session_type": row.get("Session_Type", ""),
                "established_status": row.get("Established_Status", "NOT_ESTABLISHED")
            }
            sessions.append(session_data)

        del df
        return sessions

    def get_bgp_session_compatibility(self, raise_on_error: bool = True) -> list[dict[str, Any]]:
        """Get BGP session configuration validation"""
        self._ensure_initialized()

        df = self._execute_query_factory(
            lambda: self.session.q.bgpSessionCompatibility(),
            "bgpSessionCompatibility",
            raise_on_error=raise_on_error,
        )
        if df is None:
            return []

        compatibility = []
        for _, row in df.iterrows():
            compat_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "local_as": row.get("Local_AS"),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "local_ip": row.get("Local_IP", ""),
                "remote_as": row.get("Remote_AS"),
                "remote_node": row.get("Remote_Node", ""),
                "remote_ip": row.get("Remote_IP", ""),
                "address_families": row.get("Address_Families", []),
                "session_type": row.get("Session_Type", ""),
                "configured_status": row.get("Configured_Status", "")
            }
            compatibility.append(compat_data)

        del df
        return compatibility

    def get_bgp_rib(self, raise_on_error: bool = True) -> list[dict[str, Any]]:
        """Get BGP Routing Information Base entries"""
        self._ensure_initialized()

        df = self._execute_query_factory(
            lambda: self.session.q.bgpRib(),
            "bgpRib",
            raise_on_error=raise_on_error,
        )
        if df is None:
            return []

        rib_entries = []
        for _, row in df.iterrows():
            originator_id = _normalize_json_scalar(row.get("Originator_Id"))
            rib_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "network": row.get("Network", ""),
                "next_hop_ip": row.get("Next_Hop_IP", ""),
                "protocol": row.get("Protocol", ""),
                "as_path": row.get("AS_Path", []),
                "local_preference": _normalize_json_scalar(row.get("Local_Pref")),
                "med": _normalize_json_scalar(row.get("Metric")),
                "origin_protocol": row.get("Origin_Protocol", ""),
                "origin_type": row.get("Origin_Type", ""),
                "originator_id": "" if originator_id is None else originator_id,
                "received_from_ip": row.get("Received_From_IP", ""),
                "tag": row.get("Tag"),
                "weight": row.get("Weight"),
                "communities": row.get("Communities", []),
                "cluster_list": row.get("Cluster_List", [])
            }
            rib_entries.append(rib_data)

        del df
        return rib_entries

    def test_filters(self, headers=None, nodes=None, filters=None, startLocation=None) -> list[dict[str, Any]]:
        """Test flows against ACLs/firewall rules"""
        self._ensure_initialized()
        headers = self._normalize_header_constraints("testFilters", headers)

        query_params: dict[str, Any] = {"headers": headers}
        if nodes is not None:
            query_params["nodes"] = nodes
        if filters is not None:
            query_params["filters"] = filters
        if startLocation is not None:
            query_params["startLocation"] = startLocation

        query = self.session.q.testFilters(**query_params)
        df = self._execute_query(query, "testFilters")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter_name": row.get("Filter_Name", ""),
                "flow": self._safe_serialize(row.get("Flow")),
                "action": row.get("Action", ""),
                "line_content": row.get("Line_Content", ""),
                "trace": self._safe_serialize(row.get("Trace"))
            }
            results.append(result_data)

        del df
        return results

    def get_filter_line_reachability(
        self,
        filters: str | None = None,
        nodes: str | None = None,
        ignoreComposites: bool | None = None,
    ) -> list[dict[str, Any]]:
        """Identify unreachable/shadowed ACL lines"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if filters is not None:
            query_params["filters"] = filters
        if nodes is not None:
            query_params["nodes"] = nodes
        if ignoreComposites is not None:
            query_params["ignoreComposites"] = ignoreComposites

        df = self._execute_query(
            self.session.q.filterLineReachability(**query_params),
            "filterLineReachability"
        )
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            sources_raw = row.get("Sources", [])
            node_name = ""
            filter_name = ""
            if sources_raw is not None:
                source_list = list(sources_raw) if not isinstance(sources_raw, (list, str)) else (
                    [sources_raw] if isinstance(sources_raw, str) else sources_raw
                )
                if source_list:
                    source_str = str(source_list[0]) if source_list[0] else ""
                    if ": " in source_str:
                        parts = source_str.split(": ", 1)
                        node_name = parts[0]
                        filter_name = parts[1]

            unreachable_line_obj = row.get("Unreachable_Line", "")
            unreachable_line_str = self._safe_serialize(unreachable_line_obj)
            if not isinstance(unreachable_line_str, str):
                unreachable_line_str = str(unreachable_line_str) if unreachable_line_str is not None else ""

            blocking_raw = row.get("Blocking_Lines", [])
            if blocking_raw is not None and not isinstance(blocking_raw, list):
                blocking_list = list(blocking_raw) if hasattr(blocking_raw, '__iter__') and not isinstance(blocking_raw, str) else [blocking_raw]
            else:
                blocking_list = blocking_raw if blocking_raw else []

            line_number = None
            for bl in blocking_list:
                bl_str = str(bl)
                if bl_str.startswith("Line "):
                    try:
                        line_number = int(bl_str.split(":")[0].replace("Line ", ""))
                        break
                    except (ValueError, IndexError):
                        pass

            result_data = {
                "node": node_name,
                "filter": filter_name,
                "sources": self._safe_serialize(sources_raw),
                "unreachable_line": unreachable_line_str,
                "unreachable_line_action": row.get("Unreachable_Line_Action", "") or "",
                "action": row.get("Unreachable_Line_Action", "") or "",
                "blocking_lines": [str(self._safe_serialize(bl)) for bl in blocking_list],
                "different_action": row.get("Different_Action", False),
                "reason": row.get("Reason", "") or "",
                "additional_info": row.get("Additional_Info", "") or "",
                "line": line_number
            }
            results.append(result_data)

        del df
        return results

    def search_filters(self, headers=None, action=None, filters=None, nodes=None) -> list[dict[str, Any]]:
        """Search for flows matching conditions (permit/deny)"""
        self._ensure_initialized()
        headers = self._normalize_header_constraints("searchFilters", headers)

        query = self.session.q.searchFilters(headers=headers, action=action, filters=filters, nodes=nodes)
        df = self._execute_query(query, "searchFilters")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter": row.get("Filter_Name", ""),
                "flow": self._safe_serialize(row.get("Flow")),
                "action": row.get("Action", ""),
                "line_content": row.get("Line_Content", ""),
                "trace": self._safe_serialize(row.get("Trace"))
            }
            results.append(result_data)

        del df
        return results

    def find_matching_filter_lines(self, headers=None, filters=None, nodes=None) -> list[dict[str, Any]]:
        """Find ACL lines matching specific flows"""
        self._ensure_initialized()
        headers = self._normalize_header_constraints("findMatchingFilterLines", headers)

        query = self.session.q.findMatchingFilterLines(headers=headers, filters=filters, nodes=nodes)
        df = self._execute_query(query, "findMatchingFilterLines")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter": row.get("Filter", ""),
                "flow": self._safe_serialize(row.get("Flow")),
                "action": row.get("Action", ""),
                "line_content": row.get("Line", ""),
                "line_index": row.get("Line_Index")
            }
            results.append(result_data)

        del df
        return results

    def traceroute(
        self,
        headers=None,
        startLocation=None,
        ignoreFilters=False,
        maxTraces=None,
    ) -> list[dict[str, Any]]:
        """Virtual traceroute through network"""
        self._ensure_initialized()
        headers = self._normalize_header_constraints("traceroute", headers)

        # Build query parameters — startLocation is mandatory for Batfish
        query_params: dict[str, Any] = {
            "headers": headers,
            "startLocation": startLocation if startLocation else "/.*/",
            "ignoreFilters": ignoreFilters
        }

        if maxTraces is not None:
            query_params["maxTraces"] = maxTraces

        query = self.session.q.traceroute(**query_params)
        df = self._execute_query(query, "traceroute", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Flow")),
                "traces": self._safe_serialize(row.get("Traces", [])),
            }
            results.append(result_data)

        del df
        return results

    def bidirectional_traceroute(
        self,
        headers=None,
        startLocation=None,
        ignoreFilters=False,
        maxTraces=None,
    ) -> list[dict[str, Any]]:
        """Bidirectional traceroute validation"""
        self._ensure_initialized()
        headers = self._normalize_header_constraints("bidirectionalTraceroute", headers)

        # Build query parameters — startLocation is mandatory for Batfish
        query_params: dict[str, Any] = {
            "headers": headers,
            "startLocation": startLocation if startLocation else "/.*/",
            "ignoreFilters": ignoreFilters
        }

        if maxTraces is not None:
            query_params["maxTraces"] = maxTraces

        query = self.session.q.bidirectionalTraceroute(**query_params)
        df = self._execute_query(query, "bidirectionalTraceroute", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Forward_Flow")),
                "forward_traces": self._safe_serialize(row.get("Forward_Traces", [])),
                "reverse_flow": self._safe_serialize(row.get("Reverse_Flow")),
                "reverse_traces": self._safe_serialize(row.get("Reverse_Traces", [])),
            }
            results.append(result_data)

        del df
        return results

    def get_unused_structures(self) -> list[dict[str, Any]]:
        """Find unused ACLs, route-maps, prefix-lists"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.unusedStructures(), "unusedStructures")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            source_lines = self._safe_serialize(row.get("Source_Lines", []))
            result_data = {
                "structure_type": row.get("Structure_Type", ""),
                "structure_name": row.get("Structure_Name", ""),
                "source_lines": source_lines
            }
            results.append(result_data)

        del df
        return results

    def get_undefined_references(self) -> list[dict[str, Any]]:
        """Find references to non-existent objects"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.undefinedReferences(), "undefinedReferences")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            source_lines = self._safe_serialize(row.get("Lines", []))
            result_data = {
                "structure_type": row.get("Struct_Type", ""),
                "structure_name": row.get("Ref_Name", ""),
                "context": row.get("Context", ""),
                "source_lines": source_lines
            }
            results.append(result_data)

        del df
        return results

    def resolve_filter_specifier(self, filters=None, nodes=None, grammarVersion=None) -> list[dict[str, Any]]:
        """Validate filter names"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if filters is not None:
            query_params["filters"] = filters
        if nodes is not None:
            query_params["nodes"] = nodes
        if grammarVersion is not None:
            query_params["grammarVersion"] = grammarVersion

        query = self.session.q.resolveFilterSpecifier(**query_params)
        df = self._execute_query(query, "resolveFilterSpecifier", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "filter": row.get("Filter_Name", "")
            }
            results.append(result_data)

        del df
        return results

    def resolve_node_specifier(self, nodes=None, grammarVersion=None) -> list[dict[str, Any]]:
        """Validate node patterns"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if nodes is not None:
            query_params["nodes"] = nodes
        if grammarVersion is not None:
            query_params["grammarVersion"] = grammarVersion

        query = self.session.q.resolveNodeSpecifier(**query_params)
        df = self._execute_query(query, "resolveNodeSpecifier", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", "")
            }
            results.append(result_data)

        del df
        return results

    def resolve_interface_specifier(self, interfaces=None, nodes=None, grammarVersion=None) -> list[dict[str, Any]]:
        """Validate interface specifications"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if interfaces is not None:
            query_params["interfaces"] = interfaces
        if nodes is not None:
            query_params["nodes"] = nodes
        if grammarVersion is not None:
            query_params["grammarVersion"] = grammarVersion

        query = self.session.q.resolveInterfaceSpecifier(**query_params)
        df = self._execute_query(query, "resolveInterfaceSpecifier", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else ""
            }
            results.append(result_data)

        del df
        return results

    def get_vrrp_properties(self) -> list[dict[str, Any]]:
        """VRRP configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.vrrpProperties(), "vrrpProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            group_id = _normalize_json_scalar(row.get("Group_Id"))
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "vrrp_group": None if group_id is None else int(group_id),
                "virtual_address": _join_text_values(row.get("Virtual_Addresses")),
                "priority": row.get("Priority"),
                "preempt": row.get("Preempt", False),
                "source_address": self._convert_ip_network_to_string(row.get("Source_Address"))
            }
            results.append(result_data)

        del df
        return results

    def get_hsrp_properties(self) -> list[dict[str, Any]]:
        """HSRP configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.hsrpProperties(), "hsrpProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            group_id = _normalize_json_scalar(row.get("Group_Id"))
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "hsrp_group": None if group_id is None else int(group_id),
                "group_number": None if group_id is None else int(group_id),
                "virtual_address": _join_text_values(row.get("Virtual_Addresses")),
                "priority": row.get("Priority"),
                "preempt": row.get("Preempt", False)
            }
            results.append(result_data)

        del df
        return results

    def get_mlag_properties(self) -> list[dict[str, Any]]:
        """MLAG configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.mlagProperties(), "mlagProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "id": row.get("MLAG_ID", ""),
                "local_interface": str(row.get("Local_Interface")) if row.get("Local_Interface") else None,
                "peer_address": row.get("Peer_Address", ""),
                "peer_interface": str(row.get("Peer_Interface")) if row.get("Peer_Interface") else None
            }
            results.append(result_data)

        del df
        return results

    def get_duplicate_router_ids(self) -> list[DuplicateRouterID]:
        """
        Detect duplicate router IDs in OSPF and BGP
        Returns list of sessions with DUPLICATE_ROUTER_ID status
        """
        self._ensure_initialized()

        results = []
        ospf_proc_df = None
        bgp_proc_df = None

        ospf_df = self._execute_query(
            self.session.q.ospfSessionCompatibility(),
            "ospfSessionCompatibility"
        )

        if ospf_df is not None:
            ospf_processes = {}  # key: (node, vrf), value: router_id
            ospf_proc_df = self._execute_query(
                self.session.q.ospfProcessConfiguration(),
                "ospfProcessConfiguration"
            )
            if ospf_proc_df is not None:
                for _, row in ospf_proc_df.iterrows():
                    node = row.get("Node", "")
                    vrf = row.get("VRF", "default")
                    router_id = row.get("Router_ID", "")
                    if node and router_id:
                        ospf_processes[(node, vrf)] = router_id

            for _, row in ospf_df.iterrows():
                status = row.get("Session_Status", "")
                if status == "DUPLICATE_ROUTER_ID":
                    interface = str(row.get("Interface", ""))
                    node = interface.split("[")[0] if "[" in interface else interface

                    remote_interface = str(row.get("Remote_Interface", ""))
                    remote_node = remote_interface.split("[")[0] if "[" in remote_interface else ""

                    vrf = row.get("VRF", "default")
                    area = str(row.get("Area", ""))

                    router_id = ospf_processes.get((node, vrf), "")

                    duplicate = DuplicateRouterID(
                        node=node,
                        vrf=vrf,
                        router_id=router_id,
                        protocol="OSPF",
                        area=area,
                        remote_node=remote_node,
                        session_status=status
                    )
                    results.append(duplicate)

        bgp_df = self._execute_query_factory(
            lambda: self.session.q.bgpSessionCompatibility(),
            "bgpSessionCompatibility",
            raise_on_error=True,
        )

        if bgp_df is not None:
            bgp_processes = {}  # key: (node, vrf), value: router_id
            bgp_proc_df = self._execute_query_factory(
                lambda: self.session.q.bgpProcessConfiguration(),
                "bgpProcessConfiguration",
                raise_on_error=True,
            )
            if bgp_proc_df is not None:
                for _, row in bgp_proc_df.iterrows():
                    node = row.get("Node", "")
                    vrf = row.get("VRF", "default")
                    router_id = row.get("Router_ID", "")
                    if node and router_id:
                        bgp_processes[(node, vrf)] = router_id

            for _, row in bgp_df.iterrows():
                status = row.get("Configured_Status", "") or row.get("Session_Status", "")
                if "DUPLICATE_ROUTER_ID" in status:
                    node = row.get("Node", "")
                    remote_node = row.get("Remote_Node", "")
                    vrf = row.get("VRF", "default")

                    router_id = bgp_processes.get((node, vrf), "")

                    duplicate = DuplicateRouterID(
                        node=node,
                        vrf=vrf,
                        router_id=router_id,
                        protocol="BGP",
                        area=None,
                        remote_node=remote_node,
                        session_status=status
                    )
                    results.append(duplicate)

        if ospf_df is not None:
            del ospf_df
        if ospf_proc_df is not None:
            del ospf_proc_df
        if bgp_df is not None:
            del bgp_df
        if bgp_proc_df is not None:
            del bgp_proc_df
        return results

    def get_detect_loops(self) -> list[dict[str, Any]]:
        """Detect routing loops"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.detectLoops(), "detectLoops")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            flow = row.get("Flow")
            result_data = {
                "node": getattr(flow, "ingressNode", None) or "",
                "vrf": getattr(flow, "ingressVrf", None) or "default",
                "loop": self._safe_serialize(row.get("Traces", []))
            }
            results.append(result_data)

        del df
        return results

    def get_multipath_consistency(self) -> list[dict[str, Any]]:
        """Multipath validation"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.multipathConsistency(), "multipathConsistency")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            flow = row.get("Flow")
            result_data = {
                "node": getattr(flow, "ingressNode", None) or "",
                "vrf": getattr(flow, "ingressVrf", None) or "default",
                "interface": getattr(flow, "ingressInterface", None) or None,
                "ip": getattr(flow, "srcIp", None) or "",
                "dip": getattr(flow, "dstIp", None) or "",
                "is_multipath_consistent": False
            }
            results.append(result_data)

        del df
        return results

    def get_loopback_multipath_consistency(self) -> list[dict[str, Any]]:
        """Loopback multipath validation"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.loopbackMultipathConsistency(), "loopbackMultipathConsistency")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            flow = row.get("Flow")
            result_data = {
                "node": getattr(flow, "ingressNode", None) or "",
                "vrf": getattr(flow, "ingressVrf", None) or "default",
                "loopback_ip": getattr(flow, "dstIp", None) or "",
                "is_loopback_multipath_consistent": False
            }
            results.append(result_data)

        del df
        return results

    def get_subnet_multipath_consistency(self, maxTraces=None) -> list[dict[str, Any]]:
        """Subnet multipath validation"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if maxTraces is not None:
            query_params["maxTraces"] = maxTraces

        df = self._execute_query(
            self.session.q.subnetMultipathConsistency(**query_params),
            "subnetMultipathConsistency"
        )
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Flow")),
                "traces": self._safe_serialize(row.get("Traces", [])),
                "trace_count": row.get("TraceCount", 0),
            }
            results.append(result_data)

        del df
        return results

    def compare_filters(
        self,
        filters=None,
        nodes=None,
        ignoreComposites=None,
        reference_snapshot: str | None = None,
        snapshot: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compare ACL behavior"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if filters is not None:
            query_params["filters"] = filters
        if nodes is not None:
            query_params["nodes"] = nodes
        if ignoreComposites is not None:
            query_params["ignoreComposites"] = ignoreComposites

        answer_kwargs: dict[str, Any] = {}
        if reference_snapshot:
            answer_kwargs["reference_snapshot"] = reference_snapshot
        if snapshot:
            answer_kwargs["snapshot"] = snapshot

        return self._execute_query_records(
            self.session.q.compareFilters(**query_params),
            "compareFilters",
            answer_kwargs=answer_kwargs or None,
        )

    def get_evpn_rib(self) -> list[dict[str, Any]]:
        """EVPN routing table"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.evpnRib(), "evpnRib")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "route_distinguisher": row.get("Route_Distinguisher", ""),
                "prefix": row.get("Network", ""),
                "next_hop": self._convert_ip_network_to_string(row.get("Next_Hop")),
                "originator_ip": row.get("Originator_Id", ""),
                "route_type": row.get("Route_Type", ""),
                "vni": row.get("VNI")
            }
            results.append(result_data)

        del df
        return results

    def get_vxlan_edges(self) -> list[dict[str, Any]]:
        """VXLAN tunnels"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.vxlanEdges(), "vxlanEdges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vni": row.get("VNI"),
                "vtep_address": row.get("VTEP_Address", ""),
                "remote_node": row.get("Remote_Node", ""),
                "remote_vtep_address": row.get("Remote_VTEP_Address", ""),
                "multicast_group": row.get("Multicast_Group", "")
            }
            results.append(result_data)

        del df
        return results

    def get_vxlan_vni_properties(self) -> list[dict[str, Any]]:
        """VXLAN VNI configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.vxlanVniProperties(), "vxlanVniProperties")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            udp_port = _normalize_json_scalar(row.get("VXLAN_Port"))
            result_data = {
                "node": row.get("Node", ""),
                "vni": row.get("VNI"),
                "vlan": row.get("VLAN"),
                "vrf": row.get("VRF", ""),
                "udp_port": None if udp_port is None else int(udp_port),
                "vtep_flood_list": row.get("VTEP_Flood_List", []),
                "multicast_group": row.get("Multicast_Group", "")
            }
            results.append(result_data)

        del df
        return results

    def get_eigrp_edges(self) -> list[dict[str, Any]]:
        """EIGRP adjacencies"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.eigrpEdges(), "eigrpEdges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "ip": row.get("IP", ""),
                "remote_ip": row.get("Remote_IP", "")
            }
            results.append(result_data)

        del df
        return results

    def get_eigrp_interface_configuration(self) -> list[dict[str, Any]]:
        """EIGRP interface configuration; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "eigrpInterfaces",
            "pybatfish does not provide eigrpInterfaces() in this runtime",
            ["eigrpEdges"],
        )

    def get_isis_edges(self) -> list[dict[str, Any]]:
        """IS-IS adjacencies"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.isisEdges(), "isisEdges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else "",
                "level": row.get("Level", "")
            }
            results.append(result_data)

        del df
        return results

    def get_isis_interface_configuration(self) -> list[dict[str, Any]]:
        """IS-IS interface configuration; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "isisInterfaces",
            "pybatfish does not provide isisInterfaces() in this runtime",
            ["isisEdges"],
        )

    def get_layer1_edges(self) -> list[dict[str, Any]]:
        """Physical connectivity"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.layer1Edges(), "layer1Edges")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            remote_interface_raw = row.get("Remote_Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "remote_interface": str(remote_interface_raw) if remote_interface_raw else ""
            }
            results.append(result_data)

        del df
        return results

    def get_user_provided_layer1_edges(self, nodes=None, remoteNodes=None) -> list[dict[str, Any]]:
        """Return Batfish-normalized user-provided Layer1 edges."""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if nodes is not None:
            query_params["nodes"] = nodes
        if remoteNodes is not None:
            query_params["remoteNodes"] = remoteNodes

        return self._execute_query_records(
            self.session.q.userProvidedLayer1Edges(**query_params),
            "userProvidedLayer1Edges",
        )

    def get_ipsec_session_status(self) -> list[dict[str, Any]]:
        """IPsec session status"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ipsecSessionStatus(), "ipsecSessionStatus")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vpn": row.get("VPN", ""),
                "remote_node": row.get("Remote_Node", ""),
                "remote_ip": row.get("Remote_Node_IP", ""),
                "local_ip": row.get("Node_IP", ""),
                "status": row.get("Status", ""),
                "tunnel_interfaces": row.get("Tunnel_Interfaces", [])
            }
            results.append(result_data)

        del df
        return results

    def get_ipsec_edges(self) -> list[dict[str, Any]]:
        """IPsec VPN tunnels"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.ipsecEdges(), "ipsecEdges")
        if df is None:
            return []

        def parse_interface(interface_obj) -> tuple[str, str]:
            """Parse 'node[interface]' format into (node, interface)"""
            interface_str = str(interface_obj) if interface_obj is not None else ""
            if not interface_str or '[' not in interface_str:
                return "", ""
            parts = interface_str.split('[', 1)
            node = parts[0]
            interface = parts[1].rstrip(']') if len(parts) > 1 else ""
            return node, interface

        results = []
        for _, row in df.iterrows():
            # Batfish returns: Source_Interface, Tunnel_Interface, Remote_Source_Interface, Remote_Tunnel_Interface
            # Format: "node[interface]" (e.g., "r9-remote-site2[ge-0/0/0.0]")
            source_interface = str(row.get("Source_Interface", ""))
            tunnel_interface = str(row.get("Tunnel_Interface", ""))
            remote_source_interface = str(row.get("Remote_Source_Interface", ""))
            remote_tunnel_interface = str(row.get("Remote_Tunnel_Interface", ""))

            node, local_iface = parse_interface(source_interface)
            remote_node, remote_iface = parse_interface(remote_source_interface)
            _, tunnel_iface = parse_interface(tunnel_interface)

            result_data = {
                "node": node,
                "remote_node": remote_node,
                "local_interface": local_iface,
                "remote_interface": remote_iface,
                "tunnel_interfaces": [tunnel_iface] if tunnel_iface else []
            }
            results.append(result_data)

        del df
        return results

    def get_ipsec_peer_configuration(self) -> list[dict[str, Any]]:
        """IPsec peer configuration; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "ipsecPeerConfiguration",
            "pybatfish does not provide ipsecPeerConfiguration() in this runtime",
            ["ipsecSessionStatus", "ipsecEdges"],
        )

    def get_bfd_session_status(self) -> list[dict[str, Any]]:
        """BFD session status; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "bfdSessionStatus",
            "pybatfish does not provide bfdSessionStatus() in this runtime",
        )

    def get_layer2_topology(self) -> list[dict[str, Any]]:
        """Layer 2 topology; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "layer2Topology",
            "pybatfish does not provide layer2Topology() in this runtime",
            ["switchedVlanProperties"],
        )

    def get_vi_model(self) -> list[dict[str, Any]]:
        """VI (Vendor Independent) model"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.viModel(), "viModel")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                str(column).lower(): self._safe_serialize(row.get(column))
                for column in df.columns
            }
            results.append(result_data)

        del df
        return results

    def get_switched_vlan_edges(self) -> list[dict[str, Any]]:
        """VLAN edges; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "switchedVlanEdges",
            "pybatfish does not provide switchedVlanEdges() in this runtime",
            ["switchedVlanProperties"],
        )

    def get_interface_mtu(self) -> list[dict[str, Any]]:
        """MTU analysis"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.interfaceMtu(), "interfaceMtu")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            interface_raw = row.get("Interface", "")
            result_data = {
                "interface": str(interface_raw) if interface_raw else "",
                "vrf": row.get("VRF", "default"),
                "mtu": row.get("MTU", 1500),
                "encapsulation_mtu": row.get("Encapsulation_MTU")
            }
            results.append(result_data)

        del df
        return results

    def get_ip_space_assignment(self) -> list[dict[str, Any]]:
        """IP space management; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "ipSpaceAssignment",
            "pybatfish does not provide ipSpaceAssignment() in this runtime",
            ["ipOwners"],
        )

    def get_lpm_routes(self, ip=None, nodes=None, vrfs=None) -> list[dict[str, Any]]:
        """Longest prefix match routing"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if ip is not None:
            query_params["ip"] = ip
        if nodes is not None:
            query_params["nodes"] = nodes
        if vrfs is not None:
            query_params["vrfs"] = vrfs

        query = self.session.q.lpmRoutes(**query_params)
        df = self._execute_query(query, "lpmRoutes", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            num_routes = _normalize_json_scalar(row.get("Num_Routes"))
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "ip": row.get("Ip", ""),
                "network": row.get("Network", ""),
                # Deprecated compatibility fields
                "next_hop": "",
                "next_hop_interface": None,
                "protocol": "",
                "num_routes": None if num_routes is None else int(num_routes)
            }
            results.append(result_data)

        del df
        return results

    def get_prefix_tracer(self, prefix=None, nodes=None) -> list[dict[str, Any]]:
        """Prefix advertisement trace"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if prefix is not None:
            query_params["prefix"] = prefix
        if nodes is not None:
            query_params["nodes"] = nodes

        query = self.session.q.prefixTracer(**query_params)
        df = self._execute_query(query, "prefixTracer", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "vrf": row.get("VRF", "default"),
                "prefix": row.get("Prefix", ""),
                "route_entry": self._safe_serialize(row.get("Route_Entry")),
                "trace": self._safe_serialize(row.get("Trace", []))
            }
            results.append(result_data)

        del df
        return results

    def get_differential_reachability(
        self,
        reference_snapshot: str,
        snapshot: str | None = None,
        headers=None,
        pathConstraints=None,
        actions=None,
        maxTraces=None,
        invertSearch=None,
        ignoreFilters=None,
        reference_snapshot_path: str | Path | None = None,
        snapshot_path: str | Path | None = None,
    ) -> list[dict[str, Any]]:
        """Compare reachability between snapshots"""
        self._ensure_initialized()

        if not reference_snapshot:
            raise RuntimeError("reference_snapshot is required for differential reachability")
        headers = self._normalize_header_constraints("differentialReachability", headers)

        query_params: dict[str, Any] = {}
        if headers is not None:
            query_params["headers"] = headers
        if pathConstraints is not None:
            query_params["pathConstraints"] = pathConstraints
        if actions is not None:
            query_params["actions"] = actions
        if maxTraces is not None:
            query_params["maxTraces"] = maxTraces
        if invertSearch is not None:
            query_params["invertSearch"] = invertSearch
        if ignoreFilters is not None:
            query_params["ignoreFilters"] = ignoreFilters

        started = self.state_loss_events
        active_side = (
            (self.current_snapshot_name, snapshot_path, started, True)
            if not snapshot and snapshot_path is not None and self._initialized and self.current_snapshot_name
            else None
        )
        sides: list[tuple] = []
        if reference_snapshot_path is not None:
            from_active = self._load_snapshot_unless_active(reference_snapshot_path, reference_snapshot)
            sides.append((reference_snapshot, reference_snapshot_path,
                          started if from_active else self.state_loss_events, from_active))
        if snapshot and snapshot_path is not None and (
            snapshot != reference_snapshot or reference_snapshot_path is None
        ):
            from_active = self._load_snapshot_unless_active(snapshot_path, snapshot)
            sides.append((snapshot, snapshot_path, started if from_active else self.state_loss_events, from_active))
        if active_side is not None:
            sides.append(active_side)

        query = self.session.q.differentialReachability(**query_params)

        answer_kwargs: dict[str, Any] = {"reference_snapshot": reference_snapshot}
        if snapshot:
            answer_kwargs["snapshot"] = snapshot
        for attempt in (1, 2):
            events = self.state_loss_events
            try:
                result = query.answer(**answer_kwargs).frame()

                if result.empty:
                    logger.debug("differentialReachability query returned empty result")
                    return []

                df = result
                break
            except Exception as e:
                query_error = self._refine_query_error(
                    self._build_query_error("differentialReachability", e, query_params=query_params),
                    answer_kwargs,
                )
                logger.warning("differentialReachability query failed: %s", query_error.message)
                if self.state_loss_events == events:
                    raise query_error from e
                if attempt == 2:
                    raise self._state_lost_failure("differentialReachability") from e
                for side_path, side_name in self._lost_sides(sides):
                    self._reload_side(side_path, side_name)

        results = []
        for _, row in df.iterrows():
            snapshot_traces = row.get("Snapshot_Traces", row.get("Delta_Traces", []))
            reference_traces = row.get("Reference_Traces", row.get("Base_Traces", []))
            result_data = {
                "flow": self._safe_serialize(row.get("Flow")),
                "snapshot_traces": self._safe_serialize(snapshot_traces),
                "reference_traces": self._safe_serialize(reference_traces),
                "snapshot_trace_count": row.get("Snapshot_TraceCount", row.get("Delta_TraceCount", 0)),
                "reference_trace_count": row.get("Reference_TraceCount", row.get("Base_TraceCount", 0)),
                "base_traces": self._safe_serialize(reference_traces),
                "delta_traces": self._safe_serialize(snapshot_traces),
                "change": row.get("Change", row.get("Key_Presence", "")),
            }
            results.append(result_data)

        del df
        return results

    def get_bidirectional_reachability(self, headers=None, pathConstraints=None, returnFlowType=None) -> list[dict[str, Any]]:
        """Bidirectional reachability"""
        self._ensure_initialized()
        headers = self._normalize_header_constraints("bidirectionalReachability", headers)

        query_params: dict[str, Any] = {}
        if headers is not None:
            query_params["headers"] = headers
        if pathConstraints is not None:
            query_params["pathConstraints"] = pathConstraints
        if returnFlowType is not None:
            query_params["returnFlowType"] = returnFlowType

        query = self.session.q.bidirectionalReachability(**query_params)
        df = self._execute_query(query, "bidirectionalReachability", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "flow": self._safe_serialize(row.get("Forward_Flow")),
                "forward_traces": self._safe_serialize(row.get("Forward_Traces", [])),
                "reverse_flow": self._safe_serialize(row.get("Reverse_Flow")),
                "reverse_traces": self._safe_serialize(row.get("Reverse_Traces", []))
            }
            results.append(result_data)

        del df
        return results

    def resolve_location_specifier(self, locations=None, grammarVersion=None) -> list[dict[str, Any]]:
        """Location validation"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if locations is not None:
            query_params["locations"] = locations
        if grammarVersion is not None:
            query_params["grammarVersion"] = grammarVersion

        query = self.session.q.resolveLocationSpecifier(**query_params)
        df = self._execute_query(query, "resolveLocationSpecifier", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "location": self._safe_serialize(row.get("Location", ""))
            }
            results.append(result_data)

        del df
        return results

    def resolve_ip_specifier(self, ips=None, grammarVersion=None) -> list[dict[str, Any]]:
        """IP validation"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if ips is not None:
            query_params["ips"] = ips
        if grammarVersion is not None:
            query_params["grammarVersion"] = grammarVersion

        query = self.session.q.resolveIpSpecifier(**query_params)
        df = self._execute_query(query, "resolveIpSpecifier", raise_on_error=True)
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "ip": row.get("IP_Space", "")
            }
            results.append(result_data)

        del df
        return results

    def resolve_ips_of_location_specifier(self, locations=None, grammarVersion=None) -> list[dict[str, Any]]:
        """Resolve location specifier to source IP spaces."""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if locations is not None:
            query_params["locations"] = locations
        if grammarVersion is not None:
            query_params["grammarVersion"] = grammarVersion

        return self._execute_query_records(
            self.session.q.resolveIpsOfLocationSpecifier(**query_params),
            "resolveIpsOfLocationSpecifier",
        )

    def get_f5_bigip_vip_configuration(self) -> list[dict[str, Any]]:
        """F5 VIP configuration"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.f5BigipVipConfiguration(), "f5BigipVipConfiguration")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            endpoint = row.get("VIP_Endpoint")
            address_port = endpoint.split(" ", 1)[0] if isinstance(endpoint, str) else ""
            address, _, port = address_port.rpartition(":")
            if not port.isdigit():
                address, port = address_port, ""
            result_data = {
                "node": row.get("Node", ""),
                "vip_name": row.get("VIP_Name", ""),
                "vip_address": address or None,
                "destination_port": int(port) if port else None,
                "pool": row.get("Pool", ""),
                "source_address_translation": row.get("Source_Address_Translation", "")
            }
            results.append(result_data)

        del df
        return results

    def get_a10_virtual_server_configuration(self, nodes=None, virtualServerIps=None) -> list[dict[str, Any]]:
        """A10 virtual server configuration."""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if nodes is not None:
            query_params["nodes"] = nodes
        if virtualServerIps is not None:
            query_params["virtualServerIps"] = virtualServerIps

        return self._execute_query_records(
            self.session.q.a10VirtualServerConfiguration(**query_params),
            "a10VirtualServerConfiguration",
        )

    def get_route_policies(self, nodes=None) -> list[dict[str, Any]]:
        """Route policy analysis; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "routePolicies",
            "pybatfish does not provide routePolicies() in this runtime",
            ["searchRoutePolicies", "testRoutePolicies"],
        )

    def test_route_policies(
        self,
        direction=None,
        inputRoutes=None,
        nodes=None,
        policies=None,
        bgpSessionProperties=None,
    ) -> list[dict[str, Any]]:
        """Test route policies"""
        self._ensure_initialized()

        query_params: dict[str, Any] = {
            "direction": direction,
            "inputRoutes": inputRoutes,
        }
        if nodes is not None:
            query_params["nodes"] = nodes
        if policies is not None:
            query_params["policies"] = policies
        if bgpSessionProperties is not None:
            query_params["bgpSessionProperties"] = bgpSessionProperties

        self._validate_route_policy_node_specifier(nodes, "testRoutePolicies")

        df = self._execute_query_factory(
            lambda: self.session.q.testRoutePolicies(**query_params),
            "testRoutePolicies",
            raise_on_error=True,
            query_params=query_params,
        )
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            result_data = {
                "node": row.get("Node", ""),
                "policy_name": row.get("Policy_Name", ""),
                "input_route": self._safe_serialize(row.get("Input_Route", row.get("Input_Routes"))),
                "input_routes": self._safe_serialize(row.get("Input_Routes", row.get("Input_Route"))),
                "action": row.get("Action", ""),
                "output_route": self._safe_serialize(row.get("Output_Route", row.get("Output_Routes"))),
                "output_routes": self._safe_serialize(row.get("Output_Routes", row.get("Output_Route"))),
                "trace": self._safe_serialize(row.get("Trace", []))
            }
            results.append(result_data)

        del df
        return results

    def get_transfer_bdd_validation(
        self,
        nodes=None,
        policies=None,
        retainAllPaths=None,
        seed=None,
    ) -> list[dict[str, Any]]:
        """Run symbolic route policy transfer BDD validation."""
        self._ensure_initialized()

        query_params: dict[str, Any] = {}
        if nodes is not None:
            query_params["nodes"] = nodes
        if policies is not None:
            query_params["policies"] = policies
        if retainAllPaths is not None:
            query_params["retainAllPaths"] = retainAllPaths
        if seed is not None:
            query_params["seed"] = seed

        self._validate_route_policy_node_specifier(nodes, "transferBDDValidation")

        return self._execute_query_records_factory(
            lambda: self.session.q.transferBDDValidation(**query_params),
            "transferBDDValidation",
            query_params=query_params,
        )

    def compare_peer_group_policies(
        self,
        reference_snapshot: str,
        snapshot: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compare BGP peer group policies."""
        self._ensure_initialized()

        answer_kwargs: dict[str, Any] = {"reference_snapshot": reference_snapshot}
        if snapshot:
            answer_kwargs["snapshot"] = snapshot

        return self._execute_query_records_factory(
            lambda: self.session.q.comparePeerGroupPolicies(),
            "comparePeerGroupPolicies",
            answer_kwargs=answer_kwargs,
            query_params=answer_kwargs,
        )

    def compare_route_policies(
        self,
        policy,
        referencePolicy,
        nodes=None,
        reference_snapshot: str | None = None,
        snapshot: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compare symbolic behavior of two route policies."""
        self._ensure_initialized()

        query_params: dict[str, Any] = {
            "policy": policy,
            "referencePolicy": referencePolicy,
        }
        if nodes is not None:
            query_params["nodes"] = nodes

        self._validate_route_policy_node_specifier(nodes, "compareRoutePolicies")

        answer_kwargs: dict[str, Any] | None = None
        if reference_snapshot:
            answer_kwargs = {"reference_snapshot": reference_snapshot}
            if snapshot:
                answer_kwargs["snapshot"] = snapshot

        return self._execute_query_records_factory(
            lambda: self.session.q.compareRoutePolicies(**query_params),
            "compareRoutePolicies",
            answer_kwargs=answer_kwargs,
            query_params={**query_params, **(answer_kwargs or {})},
        )

    def get_questions(self) -> list[dict[str, Any]]:
        """List available questions"""
        self._ensure_initialized()

        logger.warning("questions() method does not exist in this pybatfish version - returning static list")

        question_methods = [method for method in dir(self.session.q) if not method.startswith('_')]

        results = []
        for method_name in sorted(question_methods):
            if method_name in ['list', 'list_tags', 'load']:
                continue

            try:
                method = getattr(self.session.q, method_name)
                doc = method().__doc__ if callable(method) else ""
                description = doc.split('\n')[0] if doc else f"Batfish question: {method_name}"
            except Exception as e:
                logger.debug(f"Failed to get method documentation for {method_name}: {e}")
                description = f"Batfish question: {method_name}"

            result_data = {
                "name": method_name,
                "description": description,
                "instance_variables": {}
            }
            results.append(result_data)

        return results

    def get_node_roles(self) -> list[dict[str, Any]]:
        """Node role definitions; returns unavailable-capability metadata."""
        self._ensure_initialized()

        return self._unavailable_capability(
            "nodeRoles",
            "pybatfish does not provide nodeRoles() in this runtime",
        )

    def get_interface_blacklist(self) -> list[dict[str, Any]]:
        """Blacklisted interfaces"""
        self._ensure_initialized()

        df = self._execute_query(self.session.q.interfaceProperties(properties="Blacklisted"), "interfaceBlacklist")
        if df is None:
            return []

        results = []
        for _, row in df.iterrows():
            if row.get("Blacklisted", False):
                interface_raw = row.get("Interface", "")
                result_data = {
                    "interface": str(interface_raw) if interface_raw else "",
                    "blacklisted": True
                }
                results.append(result_data)

        del df
        return results

    def set_reference_snapshot(self, snapshot_name: str) -> dict[str, Any]:
        """Set reference snapshot for differential analysis"""
        try:
            self.session.set_reference_snapshot(snapshot_name)
            self.reference_snapshot_name = snapshot_name
            logger.info(f"Reference snapshot set to: {snapshot_name}")

            return {
                "status": "success",
                "reference_snapshot": snapshot_name
            }
        except Exception as e:
            logger.error(f"Failed to set reference snapshot: {e}")
            raise

    def get_reference_snapshot(self) -> dict[str, str | None]:
        """Get current reference snapshot name"""
        return {
            "reference_snapshot": self.reference_snapshot_name
        }

    def compare_snapshots(
        self,
        base_snapshot: str,
        comparison_snapshot: str,
        base_snapshot_path: str | Path | None = None,
        comparison_snapshot_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """
        Compare two snapshots comprehensively

        Compares nodes, edges, routes, and reachability between snapshots.
        """
        try:
            logger.info(f"Comparing snapshots: {base_snapshot} vs {comparison_snapshot}")

            def query_side(name: str):
                with self._query_snapshot_scope(name):
                    nodes = {node["node"]: node for node in self.get_node_properties()}
                    edges = {self._edge_key(edge): edge for edge in self.get_layer3_edges()}
                    routes = self.get_routes()
                return nodes, edges, routes

            events = self.state_loss_events
            logger.debug(f"Loading base snapshot: {base_snapshot}")
            base_path = Path(base_snapshot_path) if base_snapshot_path is not None else Path(config.SNAPSHOTS_DIR) / base_snapshot
            base_from_active = self._load_snapshot_unless_active(base_path, base_snapshot)
            base_since = events if base_from_active else self.state_loss_events
            base_nodes, base_edges, base_routes = query_side(base_snapshot)

            logger.debug(f"Loading comparison snapshot: {comparison_snapshot}")
            comparison_path = (
                Path(comparison_snapshot_path)
                if comparison_snapshot_path is not None
                else Path(config.SNAPSHOTS_DIR) / comparison_snapshot
            )
            comparison_from_active = self._load_snapshot_unless_active(comparison_path, comparison_snapshot)
            comparison_since = events if comparison_from_active else self.state_loss_events
            comparison_nodes, comparison_edges, comparison_routes = query_side(comparison_snapshot)

            if self.state_loss_events != events:
                logger.warning("Batfish lost snapshot state during the comparison; querying both sides again")
                for side_path, side_name in self._lost_sides([
                    (base_snapshot, base_path, base_since, base_from_active),
                    (comparison_snapshot, comparison_path, comparison_since, comparison_from_active),
                ]):
                    logger.info("Reloading snapshot '%s' for the comparison after Batfish lost it", side_name)
                    self._reload_side(side_path, side_name)
                events = self.state_loss_events
                base_nodes, base_edges, base_routes = query_side(base_snapshot)
                comparison_nodes, comparison_edges, comparison_routes = query_side(comparison_snapshot)
                if self.state_loss_events != events:
                    raise self._state_lost_failure("compareSnapshots")

            nodes_diff = self._compare_nodes_diff(base_nodes, comparison_nodes)

            edges_diff = self._compare_edges_diff(base_edges, comparison_edges)

            routes_diff = self._compare_routes_diff(base_routes, comparison_routes)

            reachability_diff, reachability_error = self._compare_reachability(base_snapshot, comparison_snapshot)

            result = {
                "base_snapshot": base_snapshot,
                "comparison_snapshot": comparison_snapshot,
                "nodes": nodes_diff,
                "edges": edges_diff,
                "routes": routes_diff,
                "reachability": reachability_diff,
                "reachability_error": reachability_error,
            }

            logger.info(f"Snapshot comparison completed successfully")
            return result

        except Exception as e:
            logger.error(f"Error comparing snapshots: {e}", exc_info=True)
            raise

    def _compare_reachability(
        self,
        base_snapshot: str,
        comparison_snapshot: str,
    ) -> tuple[list[dict[str, Any]], dict[str, str] | None]:
        """Run differential reachability for a comparison, reporting its failure instead of raising."""
        try:
            with self._query_snapshot_scope(comparison_snapshot):
                return self.get_differential_reachability(
                    reference_snapshot=base_snapshot,
                    snapshot=comparison_snapshot,
                ), None
        except Exception as e:
            cause = e.__cause__ if isinstance(e.__cause__, Exception) else e
            reason = self._build_query_error("differentialReachability", cause).message
            reason = reason.removeprefix("Batfish work failed: ")
            logger.warning(
                "Differential reachability unavailable for %s vs %s: %s",
                base_snapshot,
                comparison_snapshot,
                reason,
            )
            return [], {
                "message": "Differential reachability could not be computed for these snapshots",
                "reason": reason,
            }

    def _edge_key(self, edge: dict[str, Any]) -> str:
        """Generate unique key for edge comparison"""
        return f"{edge.get('interface', '')}->{edge.get('remote_interface', '')}"

    def _compare_nodes_diff(
        self,
        base_nodes: dict[str, dict],
        comparison_nodes: dict[str, dict]
    ) -> dict[str, list]:
        """Compare nodes between snapshots"""
        added = [
            node_id for node_id in comparison_nodes
            if node_id not in base_nodes
        ]
        removed = [
            node_id for node_id in base_nodes
            if node_id not in comparison_nodes
        ]

        return {
            "added": added,
            "removed": removed,
            "total_base": len(base_nodes),
            "total_comparison": len(comparison_nodes)
        }

    def _compare_edges_diff(
        self,
        base_edges: dict[str, dict],
        comparison_edges: dict[str, dict]
    ) -> dict[str, list]:
        """Compare edges (topology) between snapshots"""

        def transform_edge(edge: dict) -> dict:
            """
            Transform edge from Batfish format to frontend format
            Handles formats: "node[interface]", "node:interface", or plain strings
            """
            interface = edge.get('interface', '')
            remote_interface = edge.get('remote_interface', '')

            def parse_interface(iface_str: str) -> tuple[str, str]:
                """Parse interface string to extract node and interface name"""
                if '[' in iface_str and ']' in iface_str:
                    # Format: "node[interface]"
                    parts = iface_str.split('[', 1)
                    node = parts[0]
                    iface = parts[1].rstrip(']')
                    return (node, iface)
                elif ':' in iface_str:
                    # Format: "node:interface"
                    parts = iface_str.split(':', 1)
                    return (parts[0], parts[1])
                else:
                    return (iface_str, '')

            source_node, source_iface = parse_interface(interface)
            target_node, target_iface = parse_interface(remote_interface)

            return {
                'source': source_node,
                'target': target_node,
                'source_interface': source_iface,
                'target_interface': target_iface
            }

        added = [
            transform_edge(comparison_edges[edge_key])
            for edge_key in comparison_edges
            if edge_key not in base_edges
        ]
        removed = [
            transform_edge(base_edges[edge_key])
            for edge_key in base_edges
            if edge_key not in comparison_edges
        ]

        return {
            "added": added,
            "removed": removed,
            "total_base": len(base_edges),
            "total_comparison": len(comparison_edges)
        }

    def _compare_routes_diff(
        self,
        base_routes: list[dict],
        comparison_routes: list[dict]
    ) -> dict[str, Any]:
        """Compare routing tables between snapshots."""
        def route_key(route: dict) -> str:
            return f"{route.get('node', '')}-{route.get('vrf', '')}-{route.get('network', '')}"

        def group_routes(routes: list[dict]) -> dict[str, list[dict]]:
            grouped: dict[str, list[dict]] = {}
            for route in routes:
                grouped.setdefault(route_key(route), []).append(route)
            return grouped

        def sorted_values(routes: list[dict], field: str) -> list[str]:
            return sorted({str(route.get(field) or "") for route in routes})

        base_route_map = group_routes(base_routes)
        comparison_route_map = group_routes(comparison_routes)

        added = [
            route
            for key, routes in comparison_route_map.items()
            if key not in base_route_map
            for route in routes
        ]
        removed = [
            route
            for key, routes in base_route_map.items()
            if key not in comparison_route_map
            for route in routes
        ]

        modified = []
        for key, base_group in base_route_map.items():
            comparison_group = comparison_route_map.get(key)
            if comparison_group is None:
                continue
            base_next_hops = sorted_values(base_group, 'next_hop')
            comparison_next_hops = sorted_values(comparison_group, 'next_hop')
            base_protocols = sorted_values(base_group, 'protocol')
            comparison_protocols = sorted_values(comparison_group, 'protocol')
            if base_next_hops != comparison_next_hops or base_protocols != comparison_protocols:
                comp_route = comparison_group[0]
                modified.append({
                    "network": comp_route.get('network'),
                    "node": comp_route.get('node'),
                    "vrf": comp_route.get('vrf'),
                    "base_next_hop": ", ".join(base_next_hops),
                    "comparison_next_hop": ", ".join(comparison_next_hops),
                    "base_next_hops": base_next_hops,
                    "comparison_next_hops": comparison_next_hops,
                    "base_protocol": ", ".join(base_protocols),
                    "comparison_protocol": ", ".join(comparison_protocols),
                })

        return {
            "added": added,
            "removed": removed,
            "modified": modified,
            "total_base": len(base_routes),
            "total_comparison": len(comparison_routes)
        }

    def fetch_all_data(self) -> dict[str, Any]:
        """Fetch a fixed set of Batfish query results into one dictionary keyed by data type."""
        self._ensure_initialized()

        initial_memory = sys.getsizeof({})
        logger.info("Fetching all Batfish data (70 query types)...")

        query_errors: list[dict[str, Any]] = []
        data: dict[str, Any] = {"query_errors": query_errors}

        try:
            logger.debug("Fetching node_properties...")
            data["node_properties"] = self.get_node_properties()
            logger.debug("Fetching ospf_interface_configuration...")
            data["ospf_interface_configuration"] = [i.to_dict() for i in self.get_ospf_interface_configuration()]
            logger.debug("Fetching interface_properties...")
            data["interface_properties"] = self.get_interface_properties(data["ospf_interface_configuration"])
            logger.debug("Fetching routes...")
            data["routes"] = self.get_routes()

            logger.debug("Fetching ospf_process_configuration...")
            data["ospf_process_configuration"] = [p.to_dict() for p in self.get_ospf_process_configuration()]
            logger.debug("Fetching ospf_area_configuration...")
            data["ospf_area_configuration"] = [a.to_dict() for a in self.get_ospf_area_configuration()]
            logger.debug("Fetching ospf_session_compatibility...")
            data["ospf_session_compatibility"] = [s.to_dict() for s in self.get_ospf_session_compatibility()]

            logger.debug("Fetching ospf_edges...")
            data["ospf_edges"] = self.get_ospf_edges()
            logger.debug("Fetching edges...")
            data["edges"] = self.get_edges()
            logger.debug("Fetching layer3_edges...")
            data["layer3_edges"] = self.get_layer3_edges()

            logger.debug("Fetching switched_vlan_properties...")
            data["switched_vlan_properties"] = self.get_switched_vlan_properties()
            logger.debug("Fetching ip_owners...")
            data["ip_owners"] = self.get_ip_owners()

            logger.debug("Fetching defined_structures...")
            data["defined_structures"] = [s.to_dict() for s in self.get_defined_structures()]
            logger.debug("Fetching referenced_structures...")
            data["referenced_structures"] = [s.to_dict() for s in self.get_referenced_structures()]
            logger.debug("Fetching named_structures...")
            data["named_structures"] = [s.to_dict() for s in self.get_named_structures()]

            logger.debug("Fetching file_parse_status...")
            data["file_parse_status"] = [s.to_dict() for s in self.get_file_parse_status()]
            logger.debug("Fetching init_issues...")
            data["init_issues"] = [i.to_dict() for i in self.get_init_issues()]
            logger.debug("Fetching parse_warnings...")
            data["parse_warnings"] = [w.to_dict() for w in self.get_parse_warnings()]
            logger.debug("Fetching vi_conversion_status...")
            data["vi_conversion_status"] = [s.to_dict() for s in self.get_vi_conversion_status()]

            logger.debug("Fetching reachability...")
            data["reachability"] = [f.to_dict() for f in self.get_reachability()]
            logger.debug("Fetching search_route_policies...")
            self._set_aggregate_query_result(
                data,
                query_errors,
                "search_route_policies",
                lambda: self.get_search_route_policies(raise_on_error=True),
                [],
            )
            logger.debug("Fetching aaa_authentication_login...")
            data["aaa_authentication_login"] = self.get_aaa_authentication_login()
            logger.debug("Fetching snmp_community_clients...")
            data["snmp_community_clients"] = self.get_snmp_community_clients(data["named_structures"])

            logger.debug("Fetching bgp_edges...")
            self._set_aggregate_query_result(data, query_errors, "bgp_edges", self.get_bgp_edges, [])
            logger.debug("Fetching bgp_peer_configuration...")
            self._set_aggregate_query_result(data, query_errors, "bgp_peer_configuration", self.get_bgp_peer_configuration, [])
            logger.debug("Fetching bgp_process_configuration...")
            self._set_aggregate_query_result(data, query_errors, "bgp_process_configuration", self.get_bgp_process_configuration, [])
            logger.debug("Fetching bgp_session_status...")
            self._set_aggregate_query_result(data, query_errors, "bgp_session_status", self.get_bgp_session_status, [])
            logger.debug("Fetching bgp_session_compatibility...")
            self._set_aggregate_query_result(data, query_errors, "bgp_session_compatibility", self.get_bgp_session_compatibility, [])
            logger.debug("Fetching bgp_rib...")
            self._set_aggregate_query_result(data, query_errors, "bgp_rib", self.get_bgp_rib, [])

            logger.debug("Fetching filter_line_reachability...")
            data["filter_line_reachability"] = self.get_filter_line_reachability()

            logger.debug("Fetching unused_structures...")
            data["unused_structures"] = self.get_unused_structures()
            logger.debug("Fetching undefined_references...")
            data["undefined_references"] = self.get_undefined_references()
            logger.debug("Fetching vrrp_properties...")
            data["vrrp_properties"] = self.get_vrrp_properties()
            logger.debug("Fetching hsrp_properties...")
            data["hsrp_properties"] = self.get_hsrp_properties()
            logger.debug("Fetching mlag_properties...")
            data["mlag_properties"] = self.get_mlag_properties()
            logger.debug("Fetching detect_loops...")
            data["detect_loops"] = self.get_detect_loops()
            logger.debug("Fetching multipath_consistency...")
            data["multipath_consistency"] = self.get_multipath_consistency()
            logger.debug("Fetching loopback_multipath_consistency...")
            data["loopback_multipath_consistency"] = self.get_loopback_multipath_consistency()

            logger.debug("Fetching evpn_rib...")
            data["evpn_rib"] = self.get_evpn_rib()
            logger.debug("Fetching vxlan_edges...")
            data["vxlan_edges"] = self.get_vxlan_edges()
            logger.debug("Fetching vxlan_vni_properties...")
            data["vxlan_vni_properties"] = self.get_vxlan_vni_properties()
            logger.debug("Fetching eigrp_edges...")
            data["eigrp_edges"] = self.get_eigrp_edges()
            logger.debug("Fetching eigrp_interface_configuration...")
            data["eigrp_interface_configuration"] = self.get_eigrp_interface_configuration()
            logger.debug("Fetching isis_edges...")
            data["isis_edges"] = self.get_isis_edges()
            logger.debug("Fetching isis_interface_configuration...")
            data["isis_interface_configuration"] = self.get_isis_interface_configuration()
            logger.debug("Fetching layer1_edges...")
            data["layer1_edges"] = self.get_layer1_edges()
            logger.debug("Fetching switched_vlan_edges...")
            data["switched_vlan_edges"] = self.get_switched_vlan_edges()
            logger.debug("Fetching ipsec_edges...")
            data["ipsec_edges"] = self.get_ipsec_edges()
            logger.debug("Fetching interface_mtu...")
            data["interface_mtu"] = self.get_interface_mtu()
            logger.debug("Fetching ip_space_assignment...")
            data["ip_space_assignment"] = self.get_ip_space_assignment()

            logger.debug("Fetching f5_bigip_vip_configuration...")
            data["f5_bigip_vip_configuration"] = self.get_f5_bigip_vip_configuration()
            logger.debug("Fetching route_policies...")
            data["route_policies"] = self.get_route_policies()
            logger.debug("Fetching questions...")
            data["questions"] = self.get_questions()
            logger.debug("Fetching node_roles...")
            data["node_roles"] = self.get_node_roles()
            logger.debug("Fetching interface_blacklist...")
            data["interface_blacklist"] = self.get_interface_blacklist()

        except Exception as e:
            logger.error(f"Error in fetch_all_data: {e}", exc_info=True)
            raise

        gc.collect()

        data_size = sys.getsizeof(data)
        logger.info(f"All Batfish data fetched successfully (70 query types), data dict size: {data_size} bytes")

        return data
