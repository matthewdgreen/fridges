"""Collect Shodan aggregate counts only; never connect to discovered equipment."""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "site/data/shodan.json"
QUERY = 'http.title:"Danfoss StoreView"'


def fetch_count(key):
    params = urlencode({"key": key, "query": QUERY, "facets": "country:100"})
    request = Request("https://api.shodan.io/shodan/host/count?" + params,
                      headers={"User-Agent": "AreTheFridgesOK/1.0"})
    with urlopen(request, timeout=30) as response:
        result = json.load(response)
    total = result.get("total")
    if type(total) is not int or total < 0:
        raise ValueError("Invalid total")
    countries = {}
    for item in result.get("facets", {}).get("country", []):
        code, count = item.get("value"), item.get("count")
        if not isinstance(code, str) or len(code) != 2 or not code.isalpha():
            raise ValueError("Invalid country")
        if type(count) is not int or not 0 <= count <= total:
            raise ValueError("Invalid country count")
        countries[code] = count
    return total, countries


def refresh(data, key, now, fetch=fetch_count):
    if data["query"] != QUERY:
        raise ValueError("Changing queries requires a new historical series")
    data["lastAttemptAt"] = now
    if not key:
        data["status"] = "awaiting_key"
        return data, False
    try:
        total, countries = fetch(key)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError, TypeError):
        # Never print exceptions: HTTP exceptions can include the API key URL.
        data["status"] = "error"
        return data, True
    data["status"] = "ok"
    data["lastSuccessAt"] = now
    row = {"date": now[:10], "collectedAt": now, "count": total, "countries": countries}
    # A rerun replaces today's sample. Failed/missing-key runs never invent a zero.
    data["history"] = sorted([r for r in data["history"] if r["date"] != row["date"]] + [row],
                             key=lambda r: r["date"])
    return data, False


def main():
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    data, failed = refresh(json.loads(DATA.read_text()), os.environ.get("SHODAN_API_KEY"), now)
    temporary = DATA.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(DATA)
    print("Shodan refresh:", data["status"])
    if failed:
        print("::warning::Shodan count request failed; previous successful samples retained.")
    return 0  # Publish the failure state too; check the final workflow health step.


if __name__ == "__main__":
    sys.exit(main())
