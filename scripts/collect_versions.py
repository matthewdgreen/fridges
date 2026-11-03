"""One-off, passive StoreView version census using existing Shodan search data.

Only api.shodan.io is contacted. Raw banners, addresses and credentials stay in
memory; the output contains aggregate statistics only. Does not alter the site
or the daily schedule. Uses search credits (approximately one per 100 results).
"""
import argparse
import getpass
import ipaddress
import json
import math
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

SOURCE = 'https://censys.com/blog/frostbitten-in-france-a-danfoss-storeview-internet-exposure-report'
QUERIES = ['http.title:"Danfoss StoreView"', 'http.title:"StoreView Web"']
# Exact UTC index.html timestamps published by Censys after firmware inspection.
# A shared timestamp identifies a family, never an invented exact firmware.
BUILDS = {
    '2020-08-11T19:00:25Z': 'SMG09.000.116 (0135)',
    '2020-09-03T18:39:16Z': 'SMG09.000.116/118/129 (ambiguous)',
    '2021-03-15T16:39:58Z': 'SMG09.000.135 (0176)',
    '2021-05-05T13:18:46Z': 'SMG09.000.135 (0179)',
    '2021-09-29T11:43:19Z': 'SMG09.000.141',
    '2022-05-04T08:11:59Z': '3.0.12',
    '2022-09-07T10:21:34Z': '3.1.11',
    '2022-12-14T12:36:59Z': '3.2.6',
    '2023-05-19T13:40:11Z': '3.3.0',
    '2024-06-06T17:38:01Z': '4.0.14',
    '2024-07-26T07:15:22Z': '4.1.4',
    '2025-03-04T11:55:41Z': '4.2.4',
    '2025-07-31T08:18:58Z': '4.3.1',
    '2026-04-07T09:55:04Z': '5.0.19',
    '2026-04-07T15:55:13Z': '5.0.19',
    '2026-05-29T12:51:03Z': '5.1.1',
    '2026-05-29T15:45:52Z': '5.1.1',
    '2026-09-18T11:59:19Z': '5.3.2',
    '2026-09-24T06:23:34Z': '5.3.2',
}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def modified_values(row):
    values = []
    headers = row.get('http', {}).get('headers', {}) or {}
    for key, value in headers.items():
        if key.lower().replace('_', '-') == 'last-modified':
            values.extend(value if isinstance(value, list) else [value])
    if not values:
        values = re.findall(r'^Last-Modified:\s*([^\r\n]+)', row.get('data', ''), re.I | re.M)
    normalized = set()
    for value in values:
        try:
            stamp = parsedate_to_datetime(str(value))
            if stamp.tzinfo is None:
                continue
            normalized.add(stamp.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        except (ValueError, TypeError, OverflowError):
            pass
    return normalized


def infer(row):
    values = modified_values(row)
    if not values:
        return 'Unknown: missing/invalid header', None
    if len(values) != 1:
        return 'Unknown: conflicting headers', None
    stamp = next(iter(values))
    return BUILDS.get(stamp, 'Unknown: unmapped build'), stamp


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Shodan:
    def __init__(self, key):
        self.key = key
        self.opener = build_opener(NoRedirect())
        self.search_requests = 0

    def request(self, route, **params):
        assert route in ('/api-info', '/shodan/host/count', '/shodan/host/search')
        params['key'] = self.key
        request = Request('https://api.shodan.io' + route + '?' + urlencode(params),
                          headers={'User-Agent': 'AreTheFridgesOK-passive-census/1.0'})
        for attempt in range(3):
            try:
                if route == '/shodan/host/search':
                    self.search_requests += 1
                with self.opener.open(request, timeout=40) as response:
                    result = json.load(response)
                if not isinstance(result, dict) or 'error' in result:
                    raise RuntimeError('Shodan returned an error or invalid response')
                return result
            except HTTPError as error:
                if (error.code == 429 or error.code >= 500) and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f'Shodan API HTTP {error.code}; credential-bearing details suppressed') from None
            except (URLError, TimeoutError, OSError, ValueError):
                if attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError('Shodan connection or response failure; details suppressed') from None


def aggregate(records, started, query_reports, api, failure):
    by_version = Counter()
    by_scope = {q: Counter() for q in QUERIES}
    ip_versions = defaultdict(set)
    unmapped = Counter()
    observations = []
    freshness = Counter()
    title_types = Counter()
    honeypots = 0
    now = datetime.now(timezone.utc)
    for identity, record in records.items():
        by_version[record['version']] += 1
        ip_versions[identity[0]].add(record['version'])
        for query in record['queries']:
            by_scope[query][record['version']] += 1
        if record['version'] == 'Unknown: unmapped build':
            unmapped[record['modified']] += 1
        title_types[record['title_type']] += 1
        honeypots += record['honeypot']
        try:
            observed = datetime.fromisoformat(record['observed'].replace('Z', '+00:00'))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            observations.append(observed)
            age = (now-observed).total_seconds()/86400
            freshness['future timestamp' if age < 0 else '0–7 days' if age <= 7 else '8–30 days' if age <= 30 else 'over 30 days'] += 1
        except (ValueError, TypeError):
            freshness['unknown'] += 1
    ips_by_version = Counter()
    for versions in ip_versions.values():
        ips_by_version.update(versions)
    coverage_gaps = any(r.get('finalCount', r['initialCount']) != r.get('uniqueServicesFetched', 0) for r in query_reports)
    return {
        'startedAt': started, 'completedAt': utcnow(),
        'collectionStatus': 'partial' if failure else 'completed_with_coverage_gap' if coverage_gaps else 'completed', 'failure': failure,
        'method': 'Existing Shodan search banners only. Exact Last-Modified mapping; no controller connections or new scans.',
        'fingerprintSource': SOURCE, 'queryReports': query_reports,
        'searchRequests': api.search_requests,
        'services': len(records), 'uniqueIPs': len(ip_versions),
        'ipsWithMultipleVersionLabels': sum(len(v)>1 for v in ip_versions.values()),
        'servicesByInferredVersion': dict(by_version.most_common()),
        'uniqueIPsByInferredVersion': dict(ips_by_version.most_common()),
        'servicesByQueryAndVersion': {q:dict(c.most_common()) for q,c in by_scope.items()},
        'unmappedBuildTimestamps': dict(unmapped.most_common()),
        'interfaceTitleTypes': dict(title_types),
        'shodanTaggedHoneypotServices': honeypots,
        'observationAge': dict(freshness),
        'oldestObservation': min(observations).isoformat() if observations else None,
        'newestObservation': max(observations).isoformat() if observations else None,
        'limitations': [
            'Services and unique IPs are not counts of physical fridges or controllers.',
            'Shodan pagination is not an atomic snapshot; index changes can affect coverage.',
            'Headers identify inferred builds, not verified installed firmware or current security.',
            'Old shared build timestamps are explicitly ambiguous; unknown builds remain unknown.',
            'Unique-IP version groups overlap when one IP has multiple version labels.',
            'The StoreView Web supplement is separate from the existing website query.',
            'No raw addresses or banners are persisted.'
        ]
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--max-pages', type=int, default=200)
    args = parser.parse_args()
    key = os.environ.get('SHODAN_API_KEY') or getpass.getpass('Shodan key (hidden): ')
    api = Shodan(key)
    records, reports = {}, []
    started = utcnow()
    failure = None
    try:
        info = api.request('/api-info')
        credits = info.get('query_credits')
        print('Available query credits:', credits, flush=True)
        plans = [(q, api.request('/shodan/host/count', query=q)['total']) for q in QUERIES]
        pages_needed = sum(math.ceil(n/100) for _,n in plans)
        print('Scope:', json.dumps(plans), 'Estimated search pages:', pages_needed, flush=True)
        if pages_needed > args.max_pages:
            raise RuntimeError('Result set exceeds configured page budget')
        if isinstance(credits, (int,float)) and credits >= 0 and credits < pages_needed:
            raise RuntimeError('Insufficient query credits for the full census')
        for query, initial in plans:
            report = {'query':query,'initialCount':initial,'pagesExpected':math.ceil(initial/100),
                      'pagesFetched':0,'recordsFetched':0,'duplicatesWithinQuery':0,
                      'recordsWithoutIdentity':0,'totalsSeen':[], 'allPlannedPagesFetched':False}
            reports.append(report)
            seen = set()
            for page in range(1, report['pagesExpected']+1):
                result = api.request('/shodan/host/search', query=query, page=page, minify='false',
                    fields='ip_str,ipv6,port,transport,http.title,http.headers,data,timestamp,tags')
                rows = result.get('matches')
                if not isinstance(rows, list):
                    raise RuntimeError('Missing search records')
                report['pagesFetched'] += 1
                report['recordsFetched'] += len(rows)
                total = result.get('total')
                if total not in report['totalsSeen']:
                    report['totalsSeen'].append(total)
                if not rows:
                    raise RuntimeError('Search ended before all planned pages were retrieved')
                for row in rows:
                    address = row.get('ip_str') or row.get('ipv6')
                    try:
                        address = str(ipaddress.ip_address(address))
                    except (ValueError, TypeError):
                        report['recordsWithoutIdentity'] += 1
                        continue
                    port = row.get('port')
                    if type(port) is not int:
                        report['recordsWithoutIdentity'] += 1
                        continue
                    identity = (address,port,row.get('transport','tcp'))
                    if identity in seen:
                        report['duplicatesWithinQuery'] += 1
                    seen.add(identity)
                    version, modified = infer(row)
                    title = row.get('http',{}).get('title','')
                    normalized = re.sub(r'\s+', ' ', title.replace('–','-').replace('—','-')).strip().lower()
                    title_type = 'classic' if normalized == 'danfoss storeview' else 'StoreView Web' if normalized == 'danfoss - storeview web' else 'other matching title'
                    previous = records.get(identity)
                    query_set = (previous['queries'] if previous else set()) | {query}
                    current = {'version':version,'modified':modified,'observed':row.get('timestamp'),
                               'title_type':title_type,'honeypot':'honeypot' in (row.get('tags') or []), 'queries':query_set}
                    if previous and (previous.get('observed') or '') > (current.get('observed') or ''):
                        previous['queries'] = query_set
                    else:
                        records[identity] = current
                if page == 1 or page % 10 == 0 or page == report['pagesExpected']:
                    print(f'Query {len(reports)}: page {page}/{report["pagesExpected"]}; {report["recordsFetched"]} cached records processed', flush=True)
                time.sleep(1)
            report['allPlannedPagesFetched'] = True
            report['uniqueServicesFetched'] = len(seen)
            report['finalCount'] = api.request('/shodan/host/count', query=query)['total']
        after = api.request('/api-info')
        print('Remaining query credits:', after.get('query_credits'), flush=True)
    except RuntimeError as error:
        failure = str(error)
        print(failure, flush=True)
    except Exception:
        failure = 'Unexpected parsing error; details suppressed to avoid exposing raw data'
        print(failure, flush=True)
    summary = aggregate(records, started, reports, api, failure)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(summary,indent=2,ensure_ascii=False), flush=True)
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
