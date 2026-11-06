"""One-off cached-IP census and optionally one ordinary landing-page GET per IP.

Raw addresses and pages remain in memory. Only aggregate results are persisted.
The live phase has no retries, redirects, authentication, JS, or other requests.
Run from the repository root with python3 -m scripts.measure_hosts --live.
"""
import argparse
import concurrent.futures
import getpass
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from scripts.collect_versions import infer, utcnow
from scripts.measurement_scope import excluded_addresses, scoped_query

QUERY = 'http.title:"Danfoss StoreView"'
CAP = 1000


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, key):
        self.key = key
        self.opener = build_opener(NoRedirect())
        self.calls = 0
        self.search_calls = 0
        self.last = 0
        self.facet_drift = []

    def request(self, route, **params):
        assert route in ('/api-info', '/shodan/host/count', '/shodan/host/search') or re.fullmatch(r'/shodan/host/[0-9a-fA-F:.]+', route)
        time.sleep(max(0, 1.05 - (time.monotonic()-self.last)))
        params['key'] = self.key
        request = Request('https://api.shodan.io'+route+'?'+urlencode(params), headers={'User-Agent':'AreTheFridgesOK-cached-inventory/1.0'})
        for attempt in range(3):
            try:
                self.calls += 1
                self.search_calls += route == '/shodan/host/search'
                self.last = time.monotonic()
                with self.opener.open(request, timeout=20) as response:
                    result = json.load(response)
                if not isinstance(result, dict) or 'error' in result:
                    raise RuntimeError('Invalid Shodan response')
                return result
            except HTTPError as error:
                if (error.code == 429 or error.code >= 500) and attempt < 2:
                    time.sleep(2**(attempt+1))
                    continue
                try:
                    detail=json.loads(error.read()).get('error','')
                    detail=re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b','[IP]',str(detail).replace(self.key,'[REDACTED]'))[:160]
                except Exception:
                    detail='details suppressed'
                raise RuntimeError(f'Shodan HTTP {error.code}: {detail}') from None
            except (URLError, TimeoutError, OSError, ValueError):
                if attempt < 2:
                    time.sleep(2**(attempt+1))
                    continue
                raise RuntimeError('Shodan request failed; details suppressed') from None

    def ips(self, query, network=None):
        scoped = query + (f' net:{network}' if network else '')
        result = self.request('/shodan/host/count',query=scoped,facets=f'ip:{CAP}')
        total = result['total']
        entries = result.get('facets',{}).get('ip',[])
        print('IP facet:', {'scoped':network is not None,'total':total,'rows':len(entries),'sum':sum(x['count'] for x in entries),'last_count':entries[-1]['count'] if entries else None},flush=True)
        values = {}
        for item in entries:
            address = str(ipaddress.ip_address(item['value']))
            values[address] = item['count']
        if sum(values.values()) == total:
            return values, total
        if len(entries) < CAP:
            raise RuntimeError('Incomplete IP facets; cannot assert inventory completeness')
        net = ipaddress.ip_network(network or '0.0.0.0/0')
        if net.prefixlen >= net.max_prefixlen:
            raise RuntimeError('Inconsistent leaf facet')
        combined = {}
        subtotal = 0
        for child in net.subnets():
            child_values, child_total = self.ips(query, str(child))
            if set(combined).intersection(child_values):
                raise RuntimeError('Overlapping IP partitions')
            combined.update(child_values)
            subtotal += child_total
        if subtotal != total:
            self.facet_drift.append({'advertisedServices':total,'partitionedServices':subtotal})
        return combined, total


def is_storeview(row):
    title = row.get('http',{}).get('title','') or ''
    normalized = re.sub(r'[^a-z0-9]+',' ',title.lower())
    return 'danfoss' in normalized and 'storeview' in normalized


def endpoint(row):
    if (row.get('ip_str') or row.get('ipv6')) in excluded_addresses(required=False):
        return None
    address = row.get('ip_str') or row.get('ipv6')
    try:
        ip = ipaddress.ip_address(address)
    except (TypeError, ValueError):
        return None
    if not ip.is_global or not is_storeview(row) or 'honeypot' in (row.get('tags') or []):
        return None
    org = (row.get('org') or '') + ' ' + (row.get('isp') or '')
    if re.search(r'\b(military|defen[cs]e|army|navy|air force|dod)\b',org,re.I):
        return None
    port = row.get('port')
    if type(port) is not int or not 1 <= port <= 65535 or row.get('transport','tcp') != 'tcp':
        return None
    scheme = 'https' if isinstance(row.get('ssl'),dict) else 'http'
    if scheme == 'http' and port in (443,8443):
        return None  # Missing protocol evidence, rather than guessing.
    host = f'[{ip}]' if ip.version == 6 else str(ip)
    return {'url':f'{scheme}://{host}:{port}/', 'version':infer(row)[0], 'observed':row.get('timestamp') or '', 'scheme':scheme}


def choose(current, candidate):
    if candidate is None:
        return current
    if current is None:
        return candidate
    return max((current,candidate), key=lambda x:(x['observed'],x['scheme']=='https'))


LIVE_OPENER = build_opener(NoRedirect(), ProxyHandler({}))


def read_page(target):
    request = Request(target['url'], headers={
        'User-Agent':'AreTheFridgesOK-measurement/1.0 (+https://arethefridgesok.org/#method)',
        'Accept':'text/html','Accept-Encoding':'identity','Connection':'close'})
    outcome = {'status':'connection_failed','cachedVersion':target['version'],
               'sharesIPWithTaggedService':target.get('sharesIPWithTaggedService',False)}
    phase = 'connect_or_headers'
    try:
        try:
            response = LIVE_OPENER.open(request, timeout=3)
        except HTTPError as error:
            response = error
        with response:
            outcome['httpStatus'] = response.status
            phase = 'body'
            if 300 <= response.status < 400:
                outcome['status'] = 'redirect_not_followed'
                return outcome
            if response.status in (401,403):
                outcome['status'] = 'access_denied'
                return outcome
            if response.status != 200:
                outcome['status'] = 'other_http_response'
                return outcome
            outcome['inferredVersion'] = infer({'http':{'headers':dict(response.headers)}})[0]
            content_type = response.headers.get('Content-Type','').lower()
            if 'html' not in content_type and content_type:
                outcome['status'] = 'non_html_response'
                return outcome
            # Read a small bounded prefix only; no cookies, resources or scripts.
            # read(n) may wait for n bytes or EOF even after the title arrived.
            # Read available chunks and stop as soon as the title is complete.
            raw = bytearray()
            body_started = time.monotonic()
            while len(raw) < 16384 and time.monotonic() - body_started < 3:
                chunk = response.read1(min(4096, 16384 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if re.search(br'</title\s*>', raw, re.I):
                    break
            text = raw.decode('utf-8',errors='replace')
            title = re.search(r'<title\b[^>]*>(.*?)</title>',text,re.I|re.S)
            title_text = re.sub('<[^>]*>',' ',title.group(1)) if title else ''
            outcome['status'] = 'storeview_landing_page' if is_storeview({'http':{'title':title_text}}) else 'other_landing_page'
            # A displayed UI version is not promoted to controller firmware.
            matches = re.findall(r'(?:version|ver)\s*[=:>\s\"\x27]+([A-Za-z0-9]*\d+\.\d+\.\d+)', text, re.I)
            outcome['uiVersionVisible'] = bool(matches)
    except (ssl.SSLError, ssl.CertificateError):
        outcome['status'] = 'tls_verification_failed'
    except (TimeoutError, socket.timeout):
        outcome['status'] = 'timeout'
        outcome['failurePhase'] = phase
    except URLError as error:
        outcome['status'] = 'tls_verification_failed' if isinstance(error.reason,ssl.SSLError) else 'timeout' if isinstance(error.reason,(TimeoutError,socket.timeout)) else 'connection_failed'
    except http.client.HTTPException:
        outcome['status'] = 'http_protocol_error'
        outcome['failurePhase'] = phase
    except (OSError,ValueError):
        outcome['status'] = 'connection_failed'
    if outcome['status'] in ('timeout', 'connection_failed', 'tls_verification_failed'):
        outcome.setdefault('failurePhase', phase)
    return outcome


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--live',action='store_true')
    parser.add_argument('--output',type=Path,default=Path('research/host-measurement.json'))
    args=parser.parse_args()
    # Fail before any network activity if the configured exclusions are missing.
    try:
        addresses = excluded_addresses()
    except (ValueError, TypeError, OSError):
        raise SystemExit('Required two-address exclusion configuration is unavailable or invalid') from None
    api=API(getpass.getpass('Shodan key (hidden): '))
    started=utcnow()
    info=api.request('/api-info')
    remaining=info.get('query_credits',0)
    private_query = scoped_query(QUERY, addresses)
    all_ips, all_services=api.ips(private_query)
    filtered, filtered_services=api.ips(private_query+' -tag:honeypot')
    tagged, tagged_services=api.ips(private_query+' tag:honeypot')
    print(json.dumps({'allServices':all_services,'allUniqueIPs':len(all_ips),'filteredServices':filtered_services,'filteredUniqueIPs':len(filtered),'queryCredits':remaining}),flush=True)
    report={'startedAt':started,'query':QUERY,'allServices':all_services,'allUniqueIPs':len(all_ips),'filteredServices':filtered_services,'filteredUniqueIPs':len(filtered),'observedIPUnion':len(set(all_ips)|set(filtered)),'filteredIPsAbsentFromEarlierAllSnapshot':len(set(filtered)-set(all_ips)),'ipFacetDrift':api.facet_drift,'cachedEndpoints':0,'cachedVersionByIP':{},'liveRequested':args.live,'liveStatus':'not_started','liveOutcomes':{},'limitations':['Unique IPs are not physical controllers; one address may represent multiple controllers.','Tagged service records are excluded; IPs with both tagged and untagged records and unidentified decoys can remain.','One landing-page request per eligible IP cannot establish whether the device is vulnerable or compromised.','No credentials, controller changes, redirects, retries, port scans, or JS execution are used.','A timeout or TLS error is not evidence that equipment is offline.','Only aggregates are retained; no raw IP addresses or page contents are persisted.']}
    report['IPsWithTaggedMatchingServices']=len(tagged)
    report['filteredIPsAlsoWithTaggedMatchingServices']=len(set(filtered)&set(tagged))
    report['taggedMatchingServices']=tagged_services
    # The inventory itself is complete and useful even if later metadata is unavailable.
    def save():
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+'\n')
    save()
    targets={}
    multi={ip for ip,count in filtered.items() if max(count,all_ips.get(ip,0))>1}
    single=set(filtered)-multi
    # Divide a long exclusion query into network partitions before searching.
    # Every returned row is still checked against the deduplicated inventory.
    plans=[]
    def plan(net):
        singles_here={ip for ip in single if ipaddress.ip_address(ip) in net}
        if not singles_here:
            return
        multi_here={ip for ip in multi if ipaddress.ip_address(ip) in net}
        query=QUERY+' net:'+str(net)
        if multi_here:
            query+=' -ip:'+','.join(sorted(multi_here))
        if len(query)>2400 and net.prefixlen<32:
            for child in net.subnets():
                plan(child)
        else:
            plans.append((query,len(singles_here)))
    plan(ipaddress.ip_network('0.0.0.0/0'))
    print(f'Cached metadata plan: {len(single)} single-service IPs, {len(multi)} multi-service IPs, {len(plans)} search partitions.',flush=True)
    budget=remaining
    for query,expected in sorted(plans,key=lambda item:item[1],reverse=True):
        try:
            single_count=api.request('/shodan/host/count',query=query)['total']
        except RuntimeError:
            continue
        pages=math.ceil(single_count/100)
        if abs(single_count-expected)>5 or pages>budget:
            continue
        print(f'Retrieving {pages} cached search pages for approximately {expected} single-service IPs.',flush=True)
        for page in range(1,pages+1):
            if budget<=0:
                break
            budget-=1
            try:
                data=api.request('/shodan/host/search',query=query,page=page,minify='false',fields='ip_str,ipv6,port,transport,http.title,http.headers,data,timestamp,tags,org,isp,ssl')
            except RuntimeError as error:
                print('Cached search partition unavailable:',str(error),flush=True)
                break
            for row in data.get('matches',[]):
                ip=row.get('ip_str') or row.get('ipv6')
                if ip in single:
                    targets[ip]=choose(targets.get(ip),endpoint(row))
            if page%5==0 or page==pages:
                print(f'Cached search pages {page}/{pages}',flush=True)
    pending=set(filtered)-set(targets)
    print(f'Cached per-IP lookups remaining: {len(pending)}',flush=True)
    # Shodan lookups read already collected data; they do not trigger device scans.
    for index,ip in enumerate(sorted(pending),1):
        try:
            data=api.request('/shodan/host/'+ip,minify='false')
            for row in data.get('data',[]):
                row.setdefault('ip_str',ip)
                row.setdefault('org',data.get('org',''))
                row.setdefault('isp',data.get('isp',''))
                targets[ip]=choose(targets.get(ip),endpoint(row))
        except RuntimeError:
            targets[ip]=None
        if index%25==0 or index==len(pending):
            print(f'Cached IP lookups {index}/{len(pending)}',flush=True)
    selected=[dict(t,sharesIPWithTaggedService=ip in tagged) for ip,t in targets.items() if t]
    report['selectedIPsAlsoWithTaggedMatchingServices']=sum(t['sharesIPWithTaggedService'] for t in selected)
    report['cachedEndpoints']=len(selected)
    report['noEligibleCachedEndpoint']=len(filtered)-len(selected)
    report['cachedVersionByIP']=dict(Counter(t['version'] for t in selected))
    report['cachedPhaseCompletedAt']=utcnow()
    report['searchRequests']=api.search_calls
    save()
    print(f'Eligible cached endpoints: {len(selected)}/{len(filtered)}',flush=True)
    if args.live:
        counts=Counter();versions=Counter();changes=Counter();failure_phases=Counter();http_statuses=Counter();tagged_outcomes=Counter();ui=0
        report['liveStatus']='running';save()
        # At most six concurrent connections, at most four new IPs per second.
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures=[];future_tagged={}
            for target in selected:
                future=executor.submit(read_page,target)
                futures.append(future)
                future_tagged[future]=target['sharesIPWithTaggedService']
                time.sleep(0.25)
                if len(futures)%100==0:
                    completed=sum(f.done() for f in futures)
                    print(f'Landing-page checks queued {len(futures)}/{len(selected)}; completed {completed}',flush=True)
            for index,future in enumerate(concurrent.futures.as_completed(futures),1):
                try: result=future.result()
                except Exception: result={'status':'measurement_error','sharesIPWithTaggedService':future_tagged[future]}
                counts[result['status']]+=1
                if result.get('sharesIPWithTaggedService'):
                    tagged_outcomes[result['status']]+=1
                if 'failurePhase' in result:
                    failure_phases[result['failurePhase']]+=1
                if 'httpStatus' in result:
                    http_statuses[str(result['httpStatus'])]+=1
                if result['status']=='storeview_landing_page':
                    version=result.get('inferredVersion','Unknown')
                    versions[version]+=1
                    changes['same inferred version' if version==result.get('cachedVersion') else 'different/unknown inferred version']+=1
                    ui+=result.get('uiVersionVisible',False)
                if index%100==0:
                    report['liveOutcomes']=dict(counts);save()
        report.update({'liveStatus':'completed','liveOutcomes':dict(counts),'liveOutcomesSharingIPWithTaggedMatchingService':dict(tagged_outcomes),'liveFailurePhases':dict(failure_phases),'liveHTTPStatuses':dict(http_statuses),'liveStoreViewInferredVersions':dict(versions),'cachedVsLiveInference':dict(changes),'livePagesWithVisibleUIVersion':ui,'liveCompletedAt':utcnow()})
    report['completedAt']=utcnow();report['apiRequests']=api.calls;save()
    print(json.dumps(report,indent=2),flush=True)


if __name__=='__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Stopped; any saved aggregate checkpoint is retained.')
    except Exception as error:
        import traceback
        print('Measurement stopped:', type(error).__name__, str(error) if isinstance(error,RuntimeError) else 'details suppressed')
        print('Failure location:', [(f.name,f.lineno) for f in traceback.extract_tb(error.__traceback__)][-3:])
        raise SystemExit(1)
