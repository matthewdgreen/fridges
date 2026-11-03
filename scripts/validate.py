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
    firmware = json.loads((ROOT / 'versions.json').read_text())
    assert firmware['schemaVersion'] == 1
    assert firmware['methodVersion'] == 'storeview-last-modified-v1'
    assert firmware['query'] == live['query']
    assert firmware['status'] in ('pending', 'awaiting_key', 'ok', 'error')
    link(firmware['fingerprintSource'])
    assert firmware['history'] == sorted(firmware['history'], key=lambda row: row['date'])
    assert len({row['date'] for row in firmware['history']}) == len(firmware['history'])
    for row in firmware['history']:
        valid_date(row['date'])
        assert row['collectedAt'].startswith(row['date'])
        for scope in ('all', 'excludingHoneypots'):
            sample = row[scope]
            assert type(sample['total']) is int and sample['total'] >= 0
            assert 'Unknown/unmapped' in sample['versions']
            assert all(type(n) is int and n >= 0 for n in sample['versions'].values())
            assert sum(sample['versions'].values()) == sample['total']
        assert row['honeypotServicesExcluded'] == row['all']['total'] - row['excludingHoneypots']['total'] >= 0
        assert set(row['all']['versions']) == set(row['excludingHoneypots']['versions'])
        assert all(n <= row['all']['versions'][v] for v,n in row['excludingHoneypots']['versions'].items())
    if firmware['status'] == 'ok':
        assert firmware['history'] and firmware['lastSuccessAt'] == firmware['history'][-1]['collectedAt']
    hosts = json.loads((ROOT / 'hosts.json').read_text())
    assert hosts['methodVersion'] == 'shodan-ip-facet-cardinality-v1'
    assert hosts['query'] == live['query']
    assert hosts['status'] in ('pending', 'awaiting_key', 'ok', 'error')
    assert hosts['history'] == sorted(hosts['history'], key=lambda row: row['date'])
    assert len({row['date'] for row in hosts['history']}) == len(hosts['history'])
    for row in hosts['history']:
        valid_date(row['date'])
        assert row['collectedAt'].startswith(row['date'])
        for scope in ('all', 'excludingTaggedServices'):
            sample = row[scope]
            assert type(sample['uniqueIPs']) is int and 0 <= sample['uniqueIPs'] <= sample['services']
            assert sample['cardinalityMethod'] in ('complete-facet', 'singleton-tail')
        assert row['all']['uniqueIPs'] >= row['excludingTaggedServices']['uniqueIPs']
        assert row['taggedServicesExcluded'] == row['all']['services'] - row['excludingTaggedServices']['services'] >= 0
    if hosts['status'] == 'ok':
        assert hosts['history'] and hosts['lastSuccessAt'] == hosts['history'][-1]['collectedAt']
    print("Editorial and measurement data validated.")


if __name__ == "__main__":
    validate()
