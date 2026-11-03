"""Validate the editorial data contract before publishing."""
import json
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
ROOT = Path(__file__).resolve().parents[1] / "site/data"


def valid_date(value):
    parsed = date.fromisoformat(value)
    assert parsed <= datetime.now(timezone.utc).date(), "Future observation or incident"


def link(value):
    parsed = urlparse(value)
    assert parsed.scheme == "https" and parsed.hostname and not parsed.username


def validate():
    status, incidents, counts, live = [json.loads((ROOT / (name + ".json")).read_text()) for name in ("status", "incidents", "reported-counts", "shodan")]
    assert status["answer"] in ("Yes.", "No.")
    valid_date(status["reviewedAt"])
    assert incidents and any(row["major"] for row in incidents)
    assert len({row["id"] for row in incidents}) == len(incidents)
    assert incidents == sorted(incidents, key=lambda row: row["date"])
    for row in incidents:
        valid_date(row["date"])
        valid_date(row["reportedAt"])
        assert type(row["major"]) is bool
        assert row["title"] and row["summary"] and row["sources"]
        for source in row["sources"]:
            link(source["url"])
    for row in counts:
        valid_date(row["date"])
        assert type(row["count"]) is int and row["count"] >= 0
        assert row["metric"] == "services" and row["provider"] == "Shodan"
        link(row["url"])
    assert live["status"] in ("awaiting_key", "ok", "error")
    assert live["query"] == 'http.title:"Danfoss StoreView"'
    assert live["history"] == sorted(live["history"], key=lambda row: row["date"])
    assert len({row["date"] for row in live["history"]}) == len(live["history"])
    for row in live["history"]:
        valid_date(row["date"])
        assert row["collectedAt"].startswith(row["date"])
        assert type(row["count"]) is int and row["count"] >= 0
        assert all(type(n) is int and 0 <= n <= row["count"] for n in row["countries"].values())
    if live["status"] == "ok":
        assert live["history"] and live["lastSuccessAt"] == live["history"][-1]["collectedAt"]
    print("Editorial and measurement data validated.")


if __name__ == "__main__":
    validate()
