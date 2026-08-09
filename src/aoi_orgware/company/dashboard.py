"""Loopback-only, read-only HTTP/SSE surface for the AOI Command Center."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from types import TracebackType
from typing import Any, Protocol
from urllib.parse import parse_qs, unquote, urlsplit

from .dashboard_company_os import legacy_console_html, serve_company_os


class CompanyDashboardError(RuntimeError):
    """The local read-only Dashboard cannot be served safely."""


class CompanyDashboardResetRequiredError(CompanyDashboardError):
    """The requested cursor is older than the bounded replay window."""


class CompanyDashboardHistoricalUnavailableError(CompanyDashboardError):
    """The requested cursor cannot name a committed company projection."""


class CompanyDashboardBusyError(CompanyDashboardError):
    """The bounded historical replay worker is already occupied."""


class CompanyDashboardInternalError(CompanyDashboardError):
    """Historical replay failed for an internal storage/integrity reason."""


class DashboardView(Protocol):
    def section(self, name: str) -> dict[str, Any]:
        """Return one versioned response envelope."""

    def events_after(
        self,
        cursor: int,
        *,
        limit: int = 256,
    ) -> tuple[dict[str, Any], ...]:
        """Return bounded transaction views after ``cursor``."""

    def snapshot_at(self, cursor: int) -> dict[str, Any]:
        """Return an exact read-only historical snapshot envelope."""

    def historical_replay_input(self) -> object:
        """Freeze immutable replay facts on the state-owner thread."""

    def snapshot_from_replay(
        self,
        replay: object,
        cursor: int,
    ) -> dict[str, Any]:
        """Render history from frozen replay facts only."""


class CompanyDashboardSnapshotCache:
    """Publish owner-thread snapshots to read-only HTTP worker threads.

    ``refresh`` must be called by the Supervisor/state-owner thread.  HTTP and
    SSE handlers consume deep copies from this cache and never open or mutate
    the active company ledger/read-model SQLite files.  A bounded historical
    worker may build an isolated temporary SQLite projection from frozen
    records without crossing the active state lock's ownership boundary.
    """

    def __init__(
        self,
        source: DashboardView,
        *,
        max_cached_events: int = 4096,
    ) -> None:
        if (
            not isinstance(max_cached_events, int)
            or isinstance(max_cached_events, bool)
            or max_cached_events < 256
            or max_cached_events > 65536
        ):
            raise CompanyDashboardError(
                "Dashboard event cache bound is invalid",
            )
        self._source = source
        self._max_cached_events = max_cached_events
        self._lock = threading.RLock()
        self._refresh_owner_thread_id: int | None = None
        self._snapshot: dict[str, Any] | None = None
        self._export: dict[str, Any] | None = None
        self._historical_replay: object | None = None
        self._historical_cache: dict[int, dict[str, Any]] = {}
        self._historical_cache_order: list[int] = []
        self._historical_gate = threading.BoundedSemaphore(1)
        self._events: tuple[dict[str, Any], ...] = ()
        self._event_floor_cursor = 0

    @staticmethod
    def _validated_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "schema_version",
            "company_id",
            "cursor",
            "generated_at",
            "completeness",
            "warnings",
            "data",
        }
        if set(value) != required:
            raise CompanyDashboardError(
                "Dashboard snapshot envelope has an invalid shape",
            )
        cursor = value["cursor"]
        if (
            not isinstance(cursor, int)
            or isinstance(cursor, bool)
            or cursor < 0
            or not isinstance(value["data"], Mapping)
        ):
            raise CompanyDashboardError(
                "Dashboard snapshot envelope has invalid values",
            )
        return deepcopy(dict(value))

    def refresh(self) -> int:
        """Read one state-owner snapshot and publish it atomically."""

        caller_thread_id = threading.get_ident()
        with self._lock:
            if self._refresh_owner_thread_id is None:
                self._refresh_owner_thread_id = caller_thread_id
            elif self._refresh_owner_thread_id != caller_thread_id:
                raise CompanyDashboardError(
                    "Dashboard cache refresh crossed the owner thread",
                )
        snapshot = self._validated_snapshot(
            self._source.section("snapshot"),
        )
        exported = self._validated_snapshot(
            self._source.section("export"),
        )
        if (
            exported["company_id"] != snapshot["company_id"]
            or exported["cursor"] != snapshot["cursor"]
        ):
            raise CompanyDashboardError(
                "Dashboard snapshot and export cursors differ",
            )
        snapshot_data = snapshot["data"]
        summary = (
            snapshot_data.get("export")
            if isinstance(snapshot_data, Mapping)
            else None
        )
        export_data = exported["data"]
        if not isinstance(summary, Mapping) or not isinstance(
            export_data,
            Mapping,
        ):
            raise CompanyDashboardError(
                "Dashboard export summary has an invalid shape",
            )
        comparable_export = deepcopy(dict(export_data))
        comparable_export["snapshot"] = None
        if dict(summary) != comparable_export:
            raise CompanyDashboardError(
                "Dashboard export summary differs from its cached bundle",
            )
        cursor = int(snapshot["cursor"])
        with self._lock:
            previous_snapshot = self._snapshot
            previous_cursor = (
                int(previous_snapshot["cursor"])
                if previous_snapshot is not None
                else 0
            )
            previous_replay = self._historical_replay
            previous_floor = self._event_floor_cursor
            previous_events = self._events
        if cursor < previous_cursor:
            raise CompanyDashboardError(
                "Dashboard snapshot cursor moved backwards",
            )
        event_floor = max(0, cursor - self._max_cached_events)
        if event_floor < previous_floor:
            raise CompanyDashboardError(
                "Dashboard event replay floor moved backwards",
            )
        if cursor == previous_cursor and previous_replay is not None:
            replay = previous_replay
        else:
            replay_provider = getattr(
                self._source,
                "historical_replay_input",
                None,
            )
            replay = (
                replay_provider()
                if callable(replay_provider)
                else None
            )
        if replay is not None:
            records = getattr(replay, "records", None)
            if not isinstance(records, tuple) or len(records) != cursor:
                raise CompanyDashboardError(
                    "Dashboard historical replay facts do not match snapshot cursor",
                )
        retained = [
            deepcopy(event)
            for event in previous_events
            if event_floor < int(event["cursor"]) <= previous_cursor
        ]
        expected_after = max(previous_cursor, event_floor)
        accepted: list[dict[str, Any]] = [*retained]
        while expected_after < cursor:
            observed = self._source.events_after(
                expected_after,
                limit=256,
            )
            if not observed:
                raise CompanyDashboardError(
                    "Dashboard event source ended before the snapshot cursor",
                )
            progressed = False
            for event in observed:
                event_cursor = event.get("cursor")
                if (
                    not isinstance(event_cursor, int)
                    or isinstance(event_cursor, bool)
                    or event_cursor != expected_after + 1
                ):
                    raise CompanyDashboardError(
                        "Dashboard event cache received a cursor gap",
                    )
                if event_cursor > cursor:
                    break
                accepted.append(deepcopy(dict(event)))
                expected_after = event_cursor
                progressed = True
                if expected_after == cursor:
                    break
            if not progressed:
                raise CompanyDashboardError(
                    "Dashboard event source did not reach the snapshot cursor",
                )
        with self._lock:
            current_snapshot = self._snapshot
            if (
                current_snapshot is not None
                and int(current_snapshot["cursor"]) > cursor
            ):
                raise CompanyDashboardError(
                    "Dashboard refresh lost a newer published snapshot",
                )
            self._events = tuple(accepted[-self._max_cached_events :])
            self._event_floor_cursor = event_floor
            self._snapshot = snapshot
            self._export = exported
            self._historical_replay = replay
        return cursor

    def section(self, name: str) -> dict[str, Any]:
        with self._lock:
            if self._snapshot is None or self._export is None:
                raise CompanyDashboardError(
                    "Dashboard snapshot cache has not been refreshed",
                )
            snapshot = deepcopy(self._snapshot)
            exported = deepcopy(self._export)
        if name == "export":
            return exported
        if name == "snapshot":
            return snapshot
        data = snapshot["data"]
        if not isinstance(data, Mapping) or name not in data:
            raise CompanyDashboardError(
                f"Dashboard snapshot lacks section: {name}",
            )
        snapshot["data"] = deepcopy(data[name])
        return snapshot

    def events_after(
        self,
        cursor: int,
        *,
        limit: int = 256,
    ) -> tuple[dict[str, Any], ...]:
        if (
            not isinstance(cursor, int)
            or isinstance(cursor, bool)
            or cursor < 0
            or not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
            or limit > 1024
        ):
            raise CompanyDashboardError(
                "Dashboard cached event bounds are invalid",
            )
        with self._lock:
            if self._snapshot is None:
                raise CompanyDashboardError(
                    "Dashboard snapshot cache has not been refreshed",
                )
            current_cursor = int(self._snapshot["cursor"])
            if cursor > current_cursor:
                raise CompanyDashboardError(
                    "Dashboard event cursor is ahead of the snapshot",
                )
            if cursor < self._event_floor_cursor:
                raise CompanyDashboardResetRequiredError(
                    "Dashboard event cursor is outside bounded replay",
                )
            return tuple(
                deepcopy(event)
                for event in self._events
                if int(event["cursor"]) > cursor
            )[:limit]

    def snapshot_at(self, cursor: int) -> dict[str, Any]:
        """Build and validate one non-current historical snapshot.

        Current sections remain served exclusively from the owner-published
        cache.  Historical replay is a bounded read-only operation implemented
        by the source view; it never updates the cached current projection.
        """

        if (
            not isinstance(cursor, int)
            or isinstance(cursor, bool)
            or cursor < 0
        ):
            raise CompanyDashboardError(
                "Dashboard historical cursor is invalid",
            )
        with self._lock:
            if self._snapshot is None:
                raise CompanyDashboardError(
                    "Dashboard snapshot cache has not been refreshed",
                )
            current = deepcopy(self._snapshot)
        current_cursor = int(current["cursor"])
        if cursor > current_cursor:
            raise CompanyDashboardHistoricalUnavailableError(
                "Dashboard historical cursor is ahead of the current snapshot",
            )
        if cursor == current_cursor:
            return current
        with self._lock:
            replay = self._historical_replay
            cached = self._historical_cache.get(cursor)
        if cached is not None:
            return deepcopy(cached)
        renderer = getattr(self._source, "snapshot_from_replay", None)
        if replay is None or not callable(renderer):
            raise CompanyDashboardHistoricalUnavailableError(
                "Dashboard source does not provide historical projection",
            )
        if not self._historical_gate.acquire(timeout=0.25):
            raise CompanyDashboardBusyError(
                "Dashboard historical replay capacity is occupied",
            )
        try:
            with self._lock:
                cached = self._historical_cache.get(cursor)
            if cached is not None:
                return deepcopy(cached)
            try:
                candidate = renderer(replay, cursor)
            except ValueError as exc:
                raise CompanyDashboardHistoricalUnavailableError(
                    "Dashboard historical cursor is unavailable",
                ) from exc
            except Exception as exc:
                raise CompanyDashboardInternalError(
                    "Dashboard historical projection failed internally",
                ) from exc
        finally:
            self._historical_gate.release()
        if not isinstance(candidate, Mapping):
            raise CompanyDashboardInternalError(
                "Dashboard historical projection has an invalid shape",
            )
        snapshot = self._validated_snapshot(candidate)
        if (
            snapshot["company_id"] != current["company_id"]
            or snapshot["cursor"] != cursor
        ):
            raise CompanyDashboardInternalError(
                "Dashboard historical projection does not match the request",
            )
        with self._lock:
            self._historical_cache[cursor] = deepcopy(snapshot)
            if cursor in self._historical_cache_order:
                self._historical_cache_order.remove(cursor)
            self._historical_cache_order.append(cursor)
            while len(self._historical_cache_order) > 4:
                evicted = self._historical_cache_order.pop(0)
                self._historical_cache.pop(evicted, None)
        return snapshot


class _ReadOnlyHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        view: CompanyDashboardSnapshotCache,
        stop_event: threading.Event,
    ) -> None:
        self.view = view
        self.stop_event = stop_event
        super().__init__(address, handler)


class _DashboardHandler(BaseHTTPRequestHandler):
    server: _ReadOnlyHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        del args

    def _security_headers(self, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'",
        )

    def _request_origin_is_valid(self) -> bool:
        host = self.headers.get("Host", "")
        allowed_hosts = {
            f"127.0.0.1:{self.server.server_port}",
            f"localhost:{self.server.server_port}",
        }
        if host not in allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin == f"http://{host}"

    def _write_bytes(
        self,
        status: HTTPStatus,
        payload: bytes,
        *,
        content_type: str,
    ) -> None:
        self.send_response(status)
        self._security_headers(content_type, len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def _write_json(
        self,
        status: HTTPStatus,
        value: Mapping[str, Any],
    ) -> None:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self._write_bytes(
            status,
            payload,
            content_type="application/json; charset=utf-8",
        )

    def _error(
        self,
        status: HTTPStatus,
        code: str,
        detail: str,
    ) -> None:
        self._write_json(
            status,
            {"error": code, "detail": detail, "read_only": True},
        )

    @staticmethod
    def _one_cursor(
        query: Mapping[str, Sequence[str]],
        *,
        default: int,
    ) -> int:
        values = query.get("cursor")
        if values is None:
            return default
        if len(values) != 1 or not values[0].isdigit():
            raise ValueError("cursor must be one non-negative integer")
        return int(values[0])

    def _current_cursor(self) -> int:
        value = self.server.view.section("meta").get("cursor")
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise CompanyDashboardError("view returned an invalid cursor")
        return value

    def _execution_detail(self, execution_id: str) -> None:
        envelope = self.server.view.section("execution")
        data = envelope.get("data")
        nodes = data.get("nodes") if isinstance(data, Mapping) else None
        orphans = data.get("orphans", []) if isinstance(data, Mapping) else None
        if not isinstance(nodes, list) or not isinstance(orphans, list):
            raise CompanyDashboardError(
                "execution projection has an invalid shape",
            )
        matches = [
            node
            for node in [*nodes, *orphans]
            if isinstance(node, Mapping)
            and node.get("execution_id") == execution_id
        ]
        if not matches:
            self._error(
                HTTPStatus.NOT_FOUND,
                "execution_not_found",
                "no projected execution has that immutable ID",
            )
            return
        if len(matches) != 1:
            self._error(
                HTTPStatus.CONFLICT,
                "execution_identity_ambiguous",
                "execution identity has conflicting projected nodes",
            )
            return
        result = dict(envelope)
        result["data"] = matches[0]
        self._write_json(HTTPStatus.OK, result)

    def _historical_snapshot(
        self,
        query: Mapping[str, Sequence[str]],
    ) -> None:
        current = self.server.view.section("snapshot")
        try:
            requested = self._one_cursor(
                query,
                default=int(current["cursor"]),
            )
        except (KeyError, TypeError, ValueError):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_cursor",
                "cursor must be one non-negative integer",
            )
            return
        try:
            snapshot = self.server.view.snapshot_at(requested)
        except CompanyDashboardHistoricalUnavailableError:
            self._error(
                HTTPStatus.CONFLICT,
                "historical_projection_unavailable",
                "the requested historical projection is unavailable",
            )
            return
        except CompanyDashboardBusyError:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "historical_projection_busy",
                "the bounded historical replay worker is occupied",
            )
            return
        except CompanyDashboardError:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "historical_projection_failed",
                "historical replay failed; inspect Supervisor health",
            )
            return
        self._write_json(HTTPStatus.OK, snapshot)

    def _history(self, query: Mapping[str, Sequence[str]]) -> None:
        try:
            cursor = self._one_cursor(query, default=0)
            events = self.server.view.events_after(cursor, limit=256)
        except ValueError:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_cursor",
                "cursor must be one non-negative integer",
            )
            return
        except CompanyDashboardResetRequiredError:
            self._error(
                HTTPStatus.CONFLICT,
                "reset_required",
                "requested history is outside bounded Dashboard replay",
            )
            return
        except CompanyDashboardError:
            self._error(
                HTTPStatus.CONFLICT,
                "cursor_unavailable",
                "requested cursor is not available in this snapshot",
            )
            return
        envelope = self.server.view.section("meta")
        envelope["data"] = {
            "after_cursor": cursor,
            "transactions": list(events),
        }
        self._write_json(HTTPStatus.OK, envelope)

    def _sse(self, query: Mapping[str, Sequence[str]]) -> None:
        header_cursor = self.headers.get("Last-Event-ID")
        try:
            if header_cursor is not None:
                if not header_cursor.isdigit():
                    raise ValueError
                cursor = int(header_cursor)
            else:
                cursor = self._one_cursor(
                    query,
                    default=self._current_cursor(),
                )
        except (ValueError, CompanyDashboardError):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_cursor",
                "SSE cursor must be one non-negative integer",
            )
            return

        try:
            self.server.view.events_after(cursor, limit=1)
        except CompanyDashboardResetRequiredError:
            self._error(
                HTTPStatus.CONFLICT,
                "reset_required",
                "SSE cursor is outside bounded Dashboard replay",
            )
            return
        except CompanyDashboardError:
            self._error(
                HTTPStatus.CONFLICT,
                "cursor_unavailable",
                "SSE cursor is not available in this snapshot",
            )
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            while not self.server.stop_event.is_set():
                events = self.server.view.events_after(cursor, limit=256)
                if events:
                    for event in events:
                        next_cursor = event.get("cursor")
                        if (
                            not isinstance(next_cursor, int)
                            or isinstance(next_cursor, bool)
                            or next_cursor <= cursor
                        ):
                            raise CompanyDashboardError(
                                "event stream returned a non-monotonic cursor",
                            )
                        data = json.dumps(
                            event,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        self.wfile.write(
                            (
                                f"id: {next_cursor}\n"
                                "event: company\n"
                                f"data: {data}\n\n"
                            ).encode("utf-8"),
                        )
                        cursor = next_cursor
                    self.wfile.flush()
                else:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                self.server.stop_event.wait(1.0)
        except CompanyDashboardResetRequiredError:
            payload = json.dumps(
                {
                    "cursor": cursor,
                    "reason": "bounded_replay_expired",
                },
                separators=(",", ":"),
            )
            self.wfile.write(
                (
                    "event: reset_required\n"
                    f"data: {payload}\n\n"
                ).encode("utf-8"),
            )
            self.wfile.flush()
            return
        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
        ):
            return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._request_origin_is_valid():
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_host_or_origin",
                "Dashboard accepts same-origin loopback requests only",
            )
            return
        parsed = urlsplit(self.path)
        query = parse_qs(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
        )
        if parsed.path in {"/", "/index.html"}:
            self._write_bytes(
                HTTPStatus.OK,
                legacy_console_html(),
                content_type="text/html; charset=utf-8",
            )
            return
        if serve_company_os(self, parsed.path):
            return
        if parsed.path == "/api/v1/events":
            self._sse(query)
            return
        if parsed.path.startswith("/api/v1/execution/"):
            encoded_execution_id = parsed.path.removeprefix(
                "/api/v1/execution/",
            )
            # Only one URL path segment names an execution.  A slash is legal
            # inside an immutable ID only when the client percent-encodes it.
            if not encoded_execution_id or "/" in encoded_execution_id:
                self._error(
                    HTTPStatus.NOT_FOUND,
                    "not_found",
                    "unknown read-only Dashboard route",
                )
                return
            execution_id = unquote(encoded_execution_id)
            if not execution_id:
                self._error(
                    HTTPStatus.NOT_FOUND,
                    "not_found",
                    "unknown read-only Dashboard route",
                )
                return
            self._execution_detail(execution_id)
            return
        if parsed.path == "/api/v1/history":
            self._history(query)
            return
        if parsed.path == "/api/v1/snapshot":
            self._historical_snapshot(query)
            return
        section_by_path = {
            "/api/v1/bootstrap": "meta",
            "/api/v1/meta": "meta",
            "/api/v1/company": "company",
            "/api/v1/departments": "departments",
            "/api/v1/execution": "execution",
            "/api/v1/jobs": "jobs",
            "/api/v1/evidence": "evidence",
            "/api/v1/usage": "usage",
            "/api/v1/work": "work",
            "/api/v1/optimizer": "optimizer",
            "/api/v1/alerts": "alerts",
            "/api/v1/export": "export",
        }
        section = section_by_path.get(parsed.path)
        if section is None:
            self._error(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "unknown read-only Dashboard route",
            )
            return
        self._write_json(HTTPStatus.OK, self.server.view.section(section))

    def _reject_mutation(self) -> None:
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET")
        payload = json.dumps(
            {
                "error": "read_only",
                "detail": "Dashboard has no mutation endpoints",
                "read_only": True,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self._security_headers(
            "application/json; charset=utf-8",
            len(payload),
        )
        self.end_headers()
        self.wfile.write(payload)

    do_POST = _reject_mutation
    do_PUT = _reject_mutation
    do_PATCH = _reject_mutation
    do_DELETE = _reject_mutation
    do_OPTIONS = _reject_mutation


class CompanyDashboardServer:
    """Own one loopback HTTP server without any company mutation authority."""

    def __init__(
        self,
        view: CompanyDashboardSnapshotCache,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if not isinstance(view, CompanyDashboardSnapshotCache):
            raise CompanyDashboardError(
                "Dashboard server requires an owner-thread snapshot cache",
            )
        if host != "127.0.0.1":
            raise CompanyDashboardError(
                "Dashboard must bind exactly to 127.0.0.1",
            )
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or port < 0
            or port > 65535
        ):
            raise CompanyDashboardError("Dashboard port is invalid")
        self._stop_event = threading.Event()
        self._server = _ReadOnlyHTTPServer(
            (host, port),
            _DashboardHandler,
            view=view,
            stop_event=self._stop_event,
        )
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}/"

    def start(self) -> str:
        if self._thread is not None:
            if not self._thread.is_alive():
                raise CompanyDashboardError(
                    "Dashboard server cannot be restarted after termination",
                )
            return self.url
        thread = threading.Thread(
            target=self._server.serve_forever,
            name="aoi-company-dashboard",
            daemon=True,
        )
        self._thread = thread
        thread.start()
        return self.url

    def close(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            self._server.shutdown()
            thread.join(timeout=5.0)
            if thread.is_alive():
                raise CompanyDashboardError(
                    "Dashboard server did not stop within five seconds",
                )
        self._server.server_close()

    def __enter__(self) -> CompanyDashboardServer:
        self.start()
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()


__all__ = [
    "CompanyDashboardBusyError",
    "CompanyDashboardError",
    "CompanyDashboardHistoricalUnavailableError",
    "CompanyDashboardInternalError",
    "CompanyDashboardResetRequiredError",
    "CompanyDashboardServer",
    "CompanyDashboardSnapshotCache",
    "DashboardView",
]
