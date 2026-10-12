"""Read-only targeted assessment GETs plus current metadata, saved privately.

A 404 describes only the requested cluster-scoped address. It does not exclude
virtual-resource or per-finding assessments elsewhere. Run the full collectors
too. No workload, plan, policy, tag, deadline, or assessment is written to Azure.
"""
import argparse
from datetime import datetime, timezone
import json
import re
import sys
from urllib.parse import urlsplit

from collect_assessments import (AzureCliError, DEFAULT_ASSESSMENT_KEYS, GUID, az_json,
                                 validate_capture_scope, write_private_capture)

API_VERSION = '2021-06-01'


def validate_probe_url(url, subscription, cluster_id):
    validate_capture_scope(subscription, cluster_id, 'nls-kspm-controller-lab')
    parsed = urlsplit(url)
    paths = (re.escape(cluster_id) + r'/providers/Microsoft\.Security/assessments/',
             r'/providers/Microsoft\.Security/assessmentMetadata/')
    if (parsed.scheme != 'https' or parsed.netloc.lower() != 'management.azure.com'
            or parsed.username or parsed.password or parsed.fragment
            or parsed.query != 'api-version=' + API_VERSION):
        raise ValueError('Probe URL is outside the supported read scope')
    if not any(re.fullmatch(prefix + r'[0-9a-f-]{36}', parsed.path, re.IGNORECASE) for prefix in paths):
        raise ValueError('Probe URL is outside the selected cluster or metadata scope')
    if not GUID.fullmatch(parsed.path.rsplit('/', 1)[1]):
        raise ValueError('Probe requires a GUID assessment key')
    return parsed.path


def probe_get(url, subscription, cluster_id, reader=None):
    expected_id = validate_probe_url(url, subscription, cluster_id)
    started = datetime.now(timezone.utc).isoformat()
    reader = az_json if reader is None else reader
    result = {'url': url, 'startedUtc': started}
    try:
        response = reader(['rest', '--method', 'get', '--subscription', subscription, '--url', url])
    except AzureCliError as error:
        result.update(responseState=('not-found-at-requested-url' if error.http_status == 404
                                     and not error.transient and not error.timed_out else 'error'),
                      error=error.redacted())
    except Exception:
        result.update(responseState='error', error={'category': 'unclassified-read-failure'})
    else:
        expected_type = ('microsoft.security/assessmentmetadata' if '/assessmentmetadata/' in expected_id.lower()
                         else 'microsoft.security/assessments')
        if (not isinstance(response, dict) or not isinstance(response.get('properties'), dict)
                or str(response.get('id', '')).lower() != expected_id.lower()
                or str(response.get('type', '')).lower() != expected_type):
            result.update(responseState='error', error={'category': 'unexpected-resource-response'})
        else:
            response = dict(response, properties=dict(response['properties']))
            # The metadata API defines partnerData.secret as write-only; don't retain partner data.
            response['properties'].pop('partnerData', None)
            result.update(responseState='found', response=response)
    result['completedUtc'] = datetime.now(timezone.utc).isoformat()
    return result


def collect_probes(subscription, cluster_id, assessment_keys=(), reader=None):
    validate_capture_scope(subscription, cluster_id, 'nls-kspm-controller-lab', assessment_keys=assessment_keys)
    keys = sorted(set(DEFAULT_ASSESSMENT_KEYS) | {key.lower() for key in assessment_keys})
    rows = []
    for key in keys:
        assessment_url = (f'https://management.azure.com{cluster_id}'
                          f'/providers/Microsoft.Security/assessments/{key}?api-version={API_VERSION}')
        metadata_url = (f'https://management.azure.com/providers/Microsoft.Security/'
                        f'assessmentMetadata/{key}?api-version={API_VERSION}')
        rows.append({'assessmentKey': key,
                     'assessment': probe_get(assessment_url, subscription, cluster_id, reader),
                     'metadata': probe_get(metadata_url, subscription, cluster_id, reader)})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--cluster-id', required=True)
    parser.add_argument('--assessment-key', action='append', default=[])
    parser.add_argument('--phase', choices=['preflight', 'baseline', 'scaled', 'rolled', 'remediated'], default='baseline')
    args = parser.parse_args()
    try:
        validate_capture_scope(args.subscription, args.cluster_id, 'nls-kspm-controller-lab',
                               assessment_keys=args.assessment_key)
    except ValueError as error:
        parser.error(str(error))
    account = az_json(['account', 'show', '--subscription', args.subscription])
    if not isinstance(account, dict) or str(account.get('id', '')).lower() != args.subscription.lower():
        raise ValueError('Azure subscription mismatch')
    rows = collect_probes(args.subscription, args.cluster_id, args.assessment_key)
    errors = sum(row[part]['responseState'] == 'error' for row in rows for part in ('assessment', 'metadata'))
    found = sum(row['assessment']['responseState'] == 'found' for row in rows)
    missing_addresses = sum(row['assessment']['responseState'] == 'not-found-at-requested-url' for row in rows)
    payload = {'source': 'TargetedARMReadOnlyProbes', 'capturedUtc': datetime.now(timezone.utc).isoformat(),
               'subscriptionId': args.subscription, 'clusterId': args.cluster_id, 'phase': args.phase,
               'probes': rows, 'allProbesAnswered': errors == 0,
               'limitations': [
                   'A 404 applies only to the requested address, not feature or workload finding absence.',
                   'Cluster-scoped addresses do not enumerate virtual-resource or per-finding identities.',
                   'Use complete ARM/ARG exports and corroborating views to resolve actual finding identity.',
                   'A matching reused ARM path does not establish freshness or the current cluster instance.',
                   'Metadata presence does not prove assessment execution or controller-scope rollout.']}
    path, digest = write_private_capture(payload, f'{args.phase}-targeted-assessment-probes')
    print(json.dumps({'file': path.name, 'sha256': digest, 'probedKeys': len(rows),
                      'assessmentsFound': found, 'assessmentAddressesNotFound': missing_addresses,
                      'failedReads': errors, 'allProbesAnswered': errors == 0}))
    return 1 if errors else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Targeted assessment probe failed; diagnostics omitted and no absence claimed.', file=sys.stderr)
        sys.exit(1)
