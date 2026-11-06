"""Private runtime exclusions, with a public identifier for the population change."""
import ipaddress
import json
import os
from pathlib import Path

POLICY_ID = 'exclude-two-high-multiplicity-ips-2026-11-06'
PRIVATE_PATH = Path.home() / '.config/fridges/excluded-ips.json'


def excluded_addresses(required=True):
    raw = os.environ.get('EXCLUDED_STOREVIEW_IPS')
    if raw is None and PRIVATE_PATH.exists():
        raw = PRIVATE_PATH.read_text()
    if not raw:
        if required:
            raise ValueError('The two-address exclusion configuration is unavailable')
        return set()
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) != 2:
        raise ValueError('Exactly two excluded addresses are required')
    addresses = {str(ipaddress.ip_address(value)) for value in values}
    if len(addresses) != 2:
        raise ValueError('Excluded addresses must be distinct')
    return addresses


def scoped_query(base, addresses):
    if len(addresses) != 2:
        raise ValueError('Exactly two excluded addresses are required')
    return base + ' -ip:' + ','.join(sorted(addresses))
