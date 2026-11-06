"""Daily counts excluding the two manually identified high-multiplicity IPs.

Preserve the original aggregate history, and label the new population boundary.
Private exclusion addresses never appear in saved data or console output.
"""
import argparse
import getpass
import json
import os
from pathlib import Path

from scripts import refresh, refresh_hosts, refresh_versions
from scripts.collect_versions import utcnow
from scripts.measurement_scope import POLICY_ID, excluded_addresses, scoped_query

ROOT = Path(__file__).resolve().parents[1] / 'site/data'


def update_data(data, key, now, name, query):
    for row in data['history']:
        row.setdefault('populationPolicy', 'original-title-query')
    if name == 'shodan':
        data, failed = refresh.refresh(data, key, now,
                                      fetch=lambda credential: refresh.fetch_count(credential, query=query))
    elif name == 'versions':
        data, failed = refresh_versions.refresh(data, key, now,
            collect=lambda api, stamp: refresh_versions.collect_snapshot(api, stamp, base_query=query))
    else:
        data, failed = refresh_hosts.refresh(data, key, now,
            collect=lambda api, stamp: refresh_hosts.collect_snapshot(api, stamp, base_query=query))
    if data.get('lastSuccessAt') == now:
        data['history'][-1]['populationPolicy'] = POLICY_ID
        data['history'][-1]['manuallyExcludedIPs'] = 2
    data['populationPolicy'] = {'id': POLICY_ID, 'effectiveDate': '2026-11-06',
        'excludedIPs': 2, 'reason': 'Two manually identified high-multiplicity addresses; suspected emulation.',
        'historicalCorrection': 'Earlier observations are preserved. Exact per-IP contributions were not retained.'}
    return data, failed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prompt-key', action='store_true')
    args = parser.parse_args()
    try:
        addresses = excluded_addresses()
        query = scoped_query(refresh.QUERY, addresses)
    except (ValueError, TypeError, OSError):
        raise SystemExit('Required two-address exclusion configuration is unavailable or invalid') from None
    now = utcnow()
    key = getpass.getpass('Shodan key (hidden): ') if args.prompt_key else os.environ.get('SHODAN_API_KEY')
    archive = ROOT / 'archive/pre-manual-exclusions-2026-11-06'
    archive.mkdir(parents=True, exist_ok=True)
    for name in ('shodan', 'versions', 'hosts'):
        path = ROOT / (name + '.json')
        original = path.read_text()
        backup = archive / path.name
        if not backup.exists():
            backup.write_text(original)
        data, failed = update_data(json.loads(original), key, now, name, query)
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(data, indent=2) + '\n')
        temporary.replace(path)
        print('Screened ' + name + ' collection: ' + data['status'], flush=True)
        if failed:
            print('::warning::Screened collection failed; previous successful data was retained.', flush=True)


if __name__ == '__main__':
    main()
