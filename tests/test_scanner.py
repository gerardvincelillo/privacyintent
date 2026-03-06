from privacy_intent.scanner import _safe_request_initiator


class _Frame:
    def __init__(self, url: str) -> None:
        self.url = url


class _RequestWithFrame:
    method = "GET"
    url = "https://example.com"
    resource_type = "document"
    headers = {}
    post_data = None

    @property
    def frame(self):
        return _Frame("https://example.com/page")


class _RequestWithoutFrame:
    method = "GET"
    url = "https://example.com/sw.js"
    resource_type = "script"
    headers = {}
    post_data = None

    @property
    def frame(self):
        raise RuntimeError("Service Worker requests do not have an associated frame.")


def test_safe_request_initiator_returns_frame_url() -> None:
    assert _safe_request_initiator(_RequestWithFrame()) == "https://example.com/page"


def test_safe_request_initiator_returns_none_on_frame_error() -> None:
    assert _safe_request_initiator(_RequestWithoutFrame()) is None
