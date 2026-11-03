"""Daily aggregate firmware mix; only Shodan's credit-free count API is used.

Run from the repository root: python -m scripts.refresh_versions
Use --prompt-key for a local one-off run without placing credentials in files.
"""
import argparse
import getpass
import json
import os
import time
from collections import Counter
from datetime import datetime
from email.utils import format_datetime
from pathlib import Path
from scripts.collect_versions import BUILDS, SOURCE, Shodan, utcnow

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'site/data/versions.json'
QUERY = 'http.title:"Danfoss StoreView"'
METHOD = 'storeview-last-modified-v1'


def empty_data():
    return {'schemaVersion':1, 'methodVersion':METHOD, 'query':QUERY,
            'metric':'services', 'scope':'worldwide', 'fingerprintSource':SOURCE,
            'status':'pending', 'lastAttemptAt':None, 'lastSuccessAt':None,
            'history':[]}


def total(api, query):
    value = api.request('/shodan/host/count', query=query).get('total')
    if type(value) is not int or value < 0:
        raise ValueError('Invalid count')
    return value


def fingerprint_query(base, stamp):
    header = format_datetime(datetime.fromisoformat(stamp.replace('Z','+00:00')), usegmt=True)
    return base + ' "Last-Modified: ' + header + '"'


def collect_snapshot(api, now, pause=time.sleep):
    scopes = {'all':QUERY, 'excludingHoneypots':QUERY+' -tag:honeypot'}
    snapshot = {'date':now[:10], 'collectedAt':now}
    for scope, base in scopes.items():
        count = total(api, base)
        versions = Counter()
        for stamp, version in BUILDS.items():
            versions[version] += total(api, fingerprint_query(base, stamp))
            pause(0.25)
        final_count = total(api, base)
        if final_count != count:
            raise ValueError('Index total changed during collection')
        if sum(versions.values()) > count:
            raise ValueError('Overlapping fingerprints or index drift')
        versions['Unknown/unmapped'] = count - sum(versions.values())
        snapshot[scope] = {'total':count, 'versions':dict(versions)}
    all_counts, filtered = snapshot['all'], snapshot['excludingHoneypots']
    if filtered['total'] > all_counts['total']:
        raise ValueError('Inconsistent honeypot exclusion')
    for version, count in filtered['versions'].items():
        if count > all_counts['versions'][version]:
            raise ValueError('Inconsistent version populations')
    snapshot['honeypotServicesExcluded'] = all_counts['total'] - filtered['total']
    snapshot['finishedAt'] = utcnow()
    return snapshot


def refresh(data, key, now, collect=collect_snapshot):
    if data['query'] != QUERY or data['methodVersion'] != METHOD:
        raise ValueError('Fingerprint changes require a new historical series')
    data['lastAttemptAt'] = now
    if not key:
        data['status'] = 'awaiting_key'
        return data, False
    try:
        snapshot = collect(Shodan(key), now)
    except (RuntimeError, ValueError, TypeError, KeyError, OSError):
        data['status'] = 'error'
        return data, True
    data['status'] = 'ok'
    data['lastSuccessAt'] = now
    data['history'] = sorted([r for r in data['history'] if r['date'] != snapshot['date']] + [snapshot], key=lambda r:r['date'])
    return data, False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prompt-key', action='store_true')
    args = parser.parse_args()
    key = getpass.getpass('Shodan key (hidden): ') if args.prompt_key else os.environ.get('SHODAN_API_KEY')
    data = json.loads(DATA.read_text()) if DATA.exists() else empty_data()
    data, failed = refresh(data, key, utcnow())
    temporary = DATA.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, indent=2)+'\n')
    temporary.replace(DATA)
    print('Firmware mix refresh:', data['status'])
    if failed:
        print('::warning::Firmware mix collection failed validation; previous snapshot retained.')
    elif data['history']:
        sample = data['history'][-1]
        print(json.dumps(sample, indent=2))
    # Publish errors and retained history too; the workflow health job alerts.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
