"""AC: no real connectors are invoked. Backends capture without executing.

Verifies the SAFETY CONSTRAINT: mock backends never touch a real DB driver, the
real filesystem, or the network — even when handed an attack payload. They only
record the payload and return a canned response.
"""

import socket

import pytest

from instrumental_escape.backends import MockDB, MockFS, MockHTTP, make_backend


def test_mock_db_captures_without_executing():
    db = MockDB({"mode": "auth_fail", "message": "denied"})
    resp = db.query(sql="DROP TABLE users")
    assert resp["status"] == 403
    assert db.captured == [{"sql": "DROP TABLE users"}]


def test_mock_fs_never_reads_real_path(tmp_path):
    # Hand it a path traversal payload; assert nothing on the real FS is read.
    fs = MockFS({"mode": "ok", "content": "canned"})
    resp = fs.read(path="../../../etc/passwd")
    assert resp["status"] == 200
    assert resp["content"] == "canned"          # canned, not the real file
    assert resp["captured"]["path"] == "../../../etc/passwd"


def test_mock_fs_does_not_open_files(monkeypatch):
    # If MockFS ever called open(), this would trip.
    calls = []
    import builtins
    real_open = builtins.open

    def tracking_open(*a, **k):
        calls.append(a[0] if a else None)
        return real_open(*a, **k)

    monkeypatch.setattr(builtins, "open", tracking_open)
    fs = MockFS({"mode": "ok"})
    fs.read(path="/etc/shadow")
    assert "/etc/shadow" not in calls


def test_mock_http_no_socket(monkeypatch):
    # Any attempt to open a socket during a mock request is a hard failure.
    def forbidden(*a, **k):
        raise AssertionError("network egress attempted by mock backend")

    monkeypatch.setattr(socket, "socket", forbidden)
    http = MockHTTP({"mode": "ok", "body": {"ok": True}})
    resp = http.request(url="http://169.254.169.254/latest/meta-data/")
    assert resp["status"] == 200
    assert resp["captured"]["url"].endswith("meta-data/")


def test_no_real_db_driver_imported():
    # The backends package must not pull in a real DB/HTTP client.
    import sys
    import instrumental_escape.backends  # noqa: F401

    for forbidden in ("psycopg2", "pymysql", "sqlite3", "requests", "httpx", "urllib3"):
        assert forbidden not in sys.modules, f"{forbidden} should not be imported by backends"


def test_factory_rejects_unknown_backend():
    with pytest.raises(ValueError):
        make_backend("smtp")


def test_core_does_not_import_litellm():
    # The deterministic core must run without the optional LLM dependency.
    import sys
    # Import the full deterministic path.
    import instrumental_escape.classify  # noqa: F401
    import instrumental_escape.engine  # noqa: F401
    import instrumental_escape.report  # noqa: F401
    assert "litellm" not in sys.modules
