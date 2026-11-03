"""Daily distinct-IP counts from cached Shodan facets; no equipment contacted."""
import argparse
import getpass
import ipaddress
import json
import os
import time
from pathlib import Path
from scripts.collect_versions import Shodan, utcnow

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'site/data/hosts.json'
QUERY='http.title:"Danfoss StoreView"'
METHOD='shodan-ip-facet-cardinality-v1'
CAP=1000


def cardinality(result,cap=CAP):
    total=result.get('total')
    entries=result.get('facets',{}).get('ip',[])
    if type(total) is not int or total<0 or len(entries)>cap:
        raise ValueError('Invalid facet data')
    counts=[row['count'] for row in entries]
    addresses=[str(ipaddress.ip_address(row['value'])) for row in entries]
    if len(set(addresses))!=len(addresses) or any(type(n) is not int or n<=0 for n in counts) or counts!=sorted(counts,reverse=True):
        raise ValueError('Invalid IP facet ordering or values')
    covered=sum(counts)
    if covered>total:
        raise ValueError('Facet counts exceed the total')
    if covered==total:
        count,method=len(entries),'complete-facet'
    elif len(entries)==cap and counts[-1]==1:
        # Facets return the top counts. If the last is one, every omitted
        # positive count must also be one: the omitted services are unique IPs.
        count,method=len(entries)+total-covered,'singleton-tail'
    else:
        raise ValueError('Truncated facet cannot establish distinct IP count')
    return {'services':total,'uniqueIPs':count,'cardinalityMethod':method,'facetRows':len(entries),'facetServices':covered}


def empty_data():
    return {'schemaVersion':1,'methodVersion':METHOD,'query':QUERY,'metric':'unique_ip_addresses','scope':'worldwide','status':'pending','lastAttemptAt':None,'lastSuccessAt':None,'history':[]}


def collect_snapshot(api,now):
    row={'date':now[:10],'collectedAt':now}
    for scope,query in [('all',QUERY),('excludingTaggedServices',QUERY+' -tag:honeypot')]:
        row[scope]=cardinality(api.request('/shodan/host/count',query=query,facets=f'ip:{CAP}'))
        time.sleep(1.05)
    if row['all']['uniqueIPs']<row['excludingTaggedServices']['uniqueIPs'] or row['all']['services']<row['excludingTaggedServices']['services']:
        raise ValueError('Inconsistent populations; index may have changed')
    row['taggedServicesExcluded']=row['all']['services']-row['excludingTaggedServices']['services']
    return row


def refresh(data,key,now,collect=collect_snapshot):
    if data['query']!=QUERY or data['methodVersion']!=METHOD:
        raise ValueError('Method changes require a new series')
    data['lastAttemptAt']=now
    if not key:
        data['status']='awaiting_key';return data,False
    try:
        row=collect(Shodan(key),now)
    except (RuntimeError,ValueError,TypeError,KeyError,OSError):
        data['status']='error';return data,True
    data['status']='ok';data['lastSuccessAt']=now
    data['history']=sorted([old for old in data['history'] if old['date']!=row['date']]+[row],key=lambda old:old['date'])
    return data,False


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prompt-key',action='store_true');args=parser.parse_args()
    key=getpass.getpass('Shodan key (hidden): ') if args.prompt_key else os.environ.get('SHODAN_API_KEY')
    data=json.loads(DATA.read_text()) if DATA.exists() else empty_data()
    data,failed=refresh(data,key,utcnow())
    temp=DATA.with_suffix('.tmp');temp.write_text(json.dumps(data,indent=2)+'\n');temp.replace(DATA)
    print('Distinct-IP refresh:',data['status'])
    if failed:print('::warning::Distinct-IP collection failed; previous successful observation retained.')
    elif data['history']:print(json.dumps(data['history'][-1],indent=2))


if __name__=='__main__':main()
