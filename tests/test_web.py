"""Web interface. Skipped when the ``web`` extra is not installed."""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from taintpy.web.app import app  # noqa: E402

client = TestClient(app)

CROSS = ('import os\ndef get():\n    return input()\ndef run(c):\n    os.system(c)\n'
         'def main():\n    run(get())\n')


def test_index_is_served():
    r = client.get("/")
    assert r.status_code == 200 and "<title>taintpy</title>" in r.text


def test_analyze_returns_structured_path():
    r = client.post("/api/analyze", json={"code": CROSS})
    assert r.status_code == 200
    body = r.json()
    assert body["engine"] == "interproc" and body["count"] == 1
    f = body["findings"][0]
    assert (f["line"], f["source_line"]) == (5, 3)
    assert [s["kind"] for s in f["path"]][0] == "source"
    assert [s["kind"] for s in f["path"]][-1] == "sink"


def test_engine_toggle():
    r = client.post("/api/analyze", json={"code": CROSS, "engine": "intra"})
    assert r.json()["count"] == 0


def test_unknown_calls_option():
    code = "import os\nos.system(mystery(input()))\n"
    assert client.post("/api/analyze", json={"code": code}).json()["count"] == 0
    r = client.post("/api/analyze", json={"code": code, "unknown_calls": "propagate"})
    assert r.json()["count"] == 1


def test_syntax_error_reports_line():
    r = client.post("/api/analyze", json={"code": "x = 1\ndef (:\n"})
    assert r.status_code == 400
    assert r.json()["detail"]["line"] == 2


def test_rejects_bad_options_and_oversized_code():
    assert client.post("/api/analyze", json={"code": "x=1", "engine": "magic"}).status_code == 422
    big = "x = 1\n" * 50_000
    assert client.post("/api/analyze", json={"code": big}).status_code == 422
