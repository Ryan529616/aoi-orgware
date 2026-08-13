from __future__ import annotations

from typing import Any
from urllib.request import ProxyHandler, Request

import pytest

from aoi_orgware.company import service


def test_authenticated_loopback_open_disables_environment_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    class Response:
        pass

    class Opener:
        def open(self, request: Request, *, timeout: float) -> Response:
            observed["request"] = request
            observed["timeout"] = timeout
            return Response()

    def build(*handlers: Any) -> Opener:
        observed["handlers"] = handlers
        return Opener()

    monkeypatch.setenv("HTTP_PROXY", "http://AOI-SYNTHETIC-FIXTURE-V1.invalid:9999")
    monkeypatch.setenv("HTTPS_PROXY", "http://AOI-SYNTHETIC-FIXTURE-V1.invalid:9999")
    monkeypatch.setattr(service, "build_opener", build)
    request = Request(
        "http://127.0.0.1:43123/control/v1/legacy-bridge/ingest",
        headers={"Authorization": "Bearer " + "a" * 64},
    )

    response = service._open_local(request, timeout_seconds=1.25)

    assert isinstance(response, Response)
    handlers = observed["handlers"]
    proxy_handlers = [item for item in handlers if isinstance(item, ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}
    assert any(isinstance(item, service._NoRedirectHandler) for item in handlers)
    assert observed["request"] is request
    assert observed["timeout"] == 1.25
