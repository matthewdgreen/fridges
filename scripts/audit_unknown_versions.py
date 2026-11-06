"""Manual cached-data audit. Only Shodan is contacted; only aggregates are saved."""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from scripts.collect_versions import BUILDS, infer, utcnow
from scripts.measure_hosts import API
from scripts.refresh_hosts import cardinality
from scripts.refresh_versions import QUERY, fingerprint_query


PHRASES = [fingerprint_query('', stamp).strip() for stamp in BUILDS]
UNKNOWN_QUERY = QUERY + ' ' + ' '.join('-' + phrase for phrase in PHRASES)


def concentration(counts):
    values = sorted(counts, reverse=True)
    return {'groups': len(values), 'services': sum(values),
            'largestGroupServices': values[0] if values else 0,
            'top5GroupsServices': sum(values[:5]),
            'top10GroupsServices': sum(values[:10]),
            'groupSizeHistogram': dict(sorted(Counter(values).items()))}


def facet_summary(result):
    facets = result.get('facets', {})
    summary = {'services': result['total']}
    try:
        summary.update(cardinality(result))
    except ValueError:
        summary['uniqueIPs'] = None
        summary['cardinalityMethod'] = 'unproven-truncated-or-inconsistent-facet'
    for key in ('ip', 'asn'):
        summary[key + 'Concentration'] = concentration([r['count'] for r in facets.get(key, [])])
    # ASN identities and IPs stay in memory; countries and port numbers are safe aggregates.
    summary['returnedPortGroups'] = len(facets.get('port', []))
    summary['returnedPortServiceSum'] = sum(r['count'] for r in facets.get('port', []))
    summary['top20Ports'] = {str(r['value']): r['count'] for r in facets.get('port', [])[:20]
                        if type(r['value']) is int and 0 < r['value'] < 65536}
    summary['countries'] = {r['value']: r['count'] for r in facets.get('country', [])
                            if isinstance(r['value'], str) and re.fullmatch('[A-Z]{2}', r['value'])}
    return summary


def classify(row):
    headers = row.get('http', {}).get('headers') or {}
    raw = []
    for key, value in headers.items():
        if key.lower().replace('_', '-') == 'last-modified':
            raw.extend(value if isinstance(value, list) else [value])
    if not raw:
        raw = re.findall(r'^Last-Modified:\s*([^\r\n]+)', row.get('data', ''), re.I | re.M)
    version, stamp = infer(row)
    if not raw:
        return 'missing_header', None
    if version == 'Unknown: missing/invalid header':
        return 'invalid_header', None
    if version == 'Unknown: conflicting headers':
        return 'conflicting_headers', None
    if version == 'Unknown: unmapped build':
        return 'unmapped_timestamp', stamp
    return 'known_timestamp_search_mismatch', stamp


def is_candidate(row):
    title = re.sub('[^a-z0-9]+', ' ', (row.get('http', {}).get('title') or '').lower())
    if 'danfoss' not in title or 'storeview' not in title:
        return False
    banner = (row.get('data') or '').casefold()
    return not any(phrase[1:-1].casefold() in banner for phrase in PHRASES)


def aggregate_records(records):
    report = {}
    for scope, selected in [('all', records), ('excludingTaggedServices',
                            [r for r in records if not r['tagged']])]:
        reasons, timestamps, per_ip, per_asn, ports = Counter(), Counter(), Counter(), Counter(), Counter()
        reason_ips, timestamp_ips = defaultdict(set), defaultdict(set)
        ages = Counter()
        for row in selected:
            reasons[row['reason']] += 1
            reason_ips[row['reason']].add(row['ip'])
            if row['stamp']:
                timestamps[row['stamp']] += 1
                timestamp_ips[row['stamp']].add(row['ip'])
            per_ip[row['ip']] += 1
            if row['asn']:
                per_asn[row['asn']] += 1
            ports[str(row['port'])] += 1
            # Only normalized ISO date, never attacker-controlled text.
            if re.fullmatch(r'\d{4}-\d{2}-\d{2}', row['date']):
                ages[row['date']] += 1
        report[scope] = {'services': len(selected), 'uniqueIPs': len(per_ip),
                         'reasons': dict(reasons),
                         'reasonUniqueIPs': {k: len(v) for k, v in reason_ips.items()},
                         'timestamps': {k: {'services': v, 'uniqueIPs': len(timestamp_ips[k])}
                                        for k, v in timestamps.most_common()},
                         'ipConcentration': concentration(per_ip.values()),
                         'asnConcentration': concentration(per_asn.values()),
                         'ports': dict(ports.most_common()), 'observedDates': dict(sorted(ages.items()))}
    return report


def run(api, max_hosts, private_output=None, public_key=None):
    report = {'schemaVersion': 1, 'startedAt': utcnow(), 'status': 'collecting',
              'method': 'Shodan cached count facets and host metadata only; no search or scan requests.',
              'query': UNKNOWN_QUERY, 'facetObservations': {}, 'hostLookupFailures': 0,
              'limitations': ['Service records are not physical controllers or fridges.',
                              'Sequential index queries and cached host metadata are not an atomic snapshot.',
                              'Unknown candidates are a local title and raw-header approximation to the search query.',
                              'No raw IPs, banners, organization identities or credentials are retained.',
                              'Concentrations from truncated facets describe returned groups only.',
                              'Tagged service exclusion does not remove every honeypot.']}
    scopes = {'allServices': QUERY, 'untaggedServices': QUERY + ' -tag:honeypot',
              'unknown': UNKNOWN_QUERY, 'unknownUntagged': UNKNOWN_QUERY + ' -tag:honeypot',
              'v431': fingerprint_query(QUERY, '2025-07-31T08:18:58Z'),
              'v431Untagged': fingerprint_query(QUERY + ' -tag:honeypot', '2025-07-31T08:18:58Z')}
    unknown_ips, all_ips = {}, {}
    for name, query in scopes.items():
        result = api.request('/shodan/host/count', query=query, facets='ip:1000,asn:1000,port:1000,country:100')
        report['facetObservations'][name] = facet_summary(result)
        if name == 'unknown':
            unknown_ips = {str(ipaddress.ip_address(r['value'])): r['count']
                           for r in result.get('facets', {}).get('ip', [])}
        if name == 'allServices':
            all_ips = {str(ipaddress.ip_address(r['value'])): r['count']
                       for r in result.get('facets', {}).get('ip', [])}
        print('Completed aggregate scope:', name, flush=True)
    report['unknownFacetComplete'] = sum(unknown_ips.values()) == report['facetObservations']['unknown']['services']
    # Shodan's negative text terms need not behave as an exact phrase complement.
    # Always inspect high-multiplicity addresses, even if the complement is empty.
    combined_ips = dict(all_ips)
    combined_ips.update(unknown_ips)
    targets = sorted(combined_ips, key=lambda address: (address not in unknown_ips, -combined_ips[address], address))[:max_hosts]
    report['hostSelection'] = 'Unknown-query IPs first, then highest-multiplicity all-service IPs; bounded sample.'
    report['hostsPlanned'] = len(targets)
    report['selectedAdvertisedServices'] = sum(all_ips.get(address, 0) for address in targets)
    records, seen = [], set()
    banner_versions, banner_ip_counts, host_tagged_counts = Counter(), Counter(), Counter()
    busiest = sorted(all_ips, key=all_ips.get, reverse=True)[:2]
    private_addresses, busiest_details = [], []
    for index, address in enumerate(targets):
        try:
            host = api.request('/shodan/host/' + address, history='false', minify='false')
        except RuntimeError:
            report['hostLookupFailures'] += 1
            continue
        if address in busiest:
            private_addresses.append(address)
            detail = {'advertisedServices': all_ips[address], 'cachedServices': len(host.get('data', [])),
                      'cachedPorts': len(set(r.get('port') for r in host.get('data', []))),
                      'hostTaggedHoneypot': 'honeypot' in (host.get('tags') or []),
                      'storeViewVersions': dict(Counter(infer(r)[0] for r in host.get('data', [])
                                                       if 'storeview' in (r.get('http', {}).get('title') or '').lower())),
                      'observedDates': dict(Counter(str(r.get('timestamp') or '')[:10] for r in host.get('data', [])
                                                   if re.match(r'^\d{4}-\d{2}-\d{2}', str(r.get('timestamp') or ''))))}
            busiest_details.append(detail)
        for row in host.get('data', []):
            identity = (address, row.get('port'), row.get('transport', 'tcp'))
            title = re.sub('[^a-z0-9]+', ' ', (row.get('http', {}).get('title') or '').lower())
            if identity in seen or type(row.get('port')) is not int or 'danfoss' not in title or 'storeview' not in title:
                continue
            seen.add(identity)
            banner_versions[infer(row)[0]] += 1
            banner_ip_counts[address] += 1
            if 'honeypot' in (host.get('tags') or []):
                host_tagged_counts[address] += 1
            if not is_candidate(row):
                continue
            reason, stamp = classify(row)
            asn = row.get('asn') or host.get('asn')
            records.append({'ip': address, 'port': row['port'], 'reason': reason, 'stamp': stamp,
                            'tagged': 'honeypot' in (row.get('tags') or []),
                            'asn': asn if isinstance(asn, str) and re.fullmatch(r'AS\d+', asn) else None,
                            'date': str(row.get('timestamp') or '')[:10]})
        if (index + 1) % 20 == 0:
            print('Cached hosts processed:', index + 1, 'of', len(targets), flush=True)
    report['cachedCandidates'] = aggregate_records(records)
    report['inspectedStoreViewBanners'] = sum(banner_versions.values())
    report['inspectedVersions'] = dict(banner_versions)
    report['inspectedIPConcentration'] = concentration(banner_ip_counts.values())
    report['hostTaggedStoreViewBanners'] = sum(host_tagged_counts.values())
    report['busiestAddresses'] = busiest_details
    if private_output and public_key:
        # Only an encrypted address list leaves the runner; no plaintext artifact/log.
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / 'public.pem'
            key_path.write_text(public_key)
            private_output.write_bytes(subprocess.run(
                ['openssl', 'pkeyutl', '-encrypt', '-pubin', '-inkey', str(key_path),
                 '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256'],
                input=json.dumps({'addresses': private_addresses}).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout)
    report['finalUnknownTotal'] = api.request('/shodan/host/count', query=UNKNOWN_QUERY)['total']
    report['status'] = 'bounded_sample' if not report['hostLookupFailures'] else 'partial'
    report['completedAt'] = utcnow()
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-hosts', type=int, default=100)
    args = parser.parse_args()
    if not 0 <= args.max_hosts <= 500:
        raise SystemExit('Maximum host budget is 500')
    key = os.environ.get('SHODAN_API_KEY')
    if not key:
        raise SystemExit('Shodan credential is unavailable')
    try:
        public_key = os.environ.get('AUDIT_PUBLIC_KEY')
        report = run(API(key), args.max_hosts,
                     args.output.with_suffix('.enc') if public_key else None, public_key)
    except (RuntimeError, ValueError, TypeError, KeyError, OSError):
        raise SystemExit('Cached audit failed; response and credential details suppressed') from None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('Saved aggregate audit:', report['status'], flush=True)


if __name__ == '__main__':
    main()
