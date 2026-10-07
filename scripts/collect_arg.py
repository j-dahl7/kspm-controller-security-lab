"""Read-only Azure Resource Graph assessment capture; raw evidence stays private.

POST invokes Resource Graph's query operation, not an Azure resource mutation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

from collect_assessments import GUID, az_json, ensure_private_directory, schema_paths

ARG_URL = 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
QUERY = ('securityresources '
         '| where type =~ "microsoft.security/assessments" '
         '| project id, name, type, subscriptionId, properties')


def request_page(body, subscription, folder):
    """Pass JSON through a private file; never interpolate it into shell code."""
    path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=folder,
                                         prefix='arg-request-', suffix='.json',
                                         delete=False) as stream:
            path = Path(stream.name)
            json.dump(body, stream)
        return az_json(['rest', '--method', 'post', '--subscription', subscription,
                        '--url', ARG_URL, '--headers', 'Content-Type=application/json',
                        '--body', '@' + str(path)])
    finally:
        if path is not None:
            path.unlink(missing_ok=True)


def truncation_state(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ('true', 'false'):
        return value.lower() == 'true'
    raise ValueError('Missing or invalid ARG truncation state; capture is incomplete')


def capture_pages(fetch, subscription, max_pages=1000):
    if not isinstance(subscription, str) or not GUID.fullmatch(subscription):
        raise ValueError('Subscription must be a GUID')
    if max_pages < 1:
        raise ValueError('Page limit must be positive')
    pages, seen_tokens, token = [], set(), None
    while True:
        if len(pages) >= max_pages:
            raise RuntimeError('ARG page limit reached; capture is incomplete')
        options = {'resultFormat': 'objectArray', '$top': 1000}
        if token is not None:
            if token in seen_tokens:
                raise RuntimeError('ARG pagination loop; capture is incomplete')
            seen_tokens.add(token)
            options['$skipToken'] = token
        body = {'subscriptions': [subscription], 'query': QUERY, 'options': options}
        page = fetch(body)
        if not isinstance(page, dict) or not isinstance(page.get('data'), list):
            raise ValueError('Unexpected ARG response shape')
        for record in page['data']:
            if not isinstance(record, dict):
                raise ValueError('Unexpected ARG assessment row shape')
            row_subscription = record.get('subscriptionId')
            if (not isinstance(row_subscription, str)
                    or row_subscription.lower() != subscription.lower()):
                raise ValueError('ARG returned an assessment outside the requested subscription')
            if (not isinstance(record.get('type'), str)
                    or record['type'].lower() != 'microsoft.security/assessments'):
                raise ValueError('ARG returned an unexpected resource type')
        if 'count' in page and (type(page['count']) is not int or page['count'] != len(page['data'])):
            raise ValueError('ARG row count does not match its data')
        truncated = truncation_state(page.get('resultTruncated'))
        next_token = page.get('$skipToken')
        if next_token is not None and (not isinstance(next_token, str) or not next_token.strip()):
            raise ValueError('Invalid ARG pagination token')
        if truncated and next_token is None:
            raise RuntimeError('ARG results truncated without a continuation token; capture is incomplete')
        pages.append(page)
        if next_token is None:
            return pages
        token = next_token


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--cluster-id', required=True)
    parser.add_argument('--namespace', default='nls-kspm-controller-lab')
    parser.add_argument('--phase', choices=['preflight', 'baseline', 'scaled', 'rolled', 'remediated'], required=True)
    args = parser.parse_args()
    if not GUID.fullmatch(args.subscription):
        parser.error('subscription must be a GUID')
    cluster_pattern = (rf'/subscriptions/{re.escape(args.subscription)}/resourcegroups/[^/]+'
                       r'/providers/microsoft\.containerservice/managedclusters/[^/]+')
    if not re.fullmatch(cluster_pattern, args.cluster_id, flags=re.IGNORECASE):
        parser.error('cluster-id must identify an AKS cluster in the selected subscription')
    if not args.namespace.strip():
        parser.error('namespace must not be empty')
    account = az_json(['account', 'show', '--subscription', args.subscription])
    if not isinstance(account, dict) or account.get('id', '').lower() != args.subscription.lower():
        raise RuntimeError('Azure subscription mismatch')
    folder = ensure_private_directory()
    started = datetime.now(timezone.utc).isoformat()
    pages = capture_pages(lambda body: request_page(body, args.subscription, folder), args.subscription)
    records = [row for page in pages for row in page['data']]
    needles = [args.cluster_id.lower(), args.namespace.lower(), args.cluster_id.split('/')[-1].lower()]
    candidates = [row for row in records if any(n in json.dumps(row).lower() for n in needles)]
    payload = {
        'source': 'AzureResourceGraph', 'captureStartedUtc': started,
        'capturedUtc': datetime.now(timezone.utc).isoformat(), 'phase': args.phase,
        'subscriptionId': args.subscription, 'clusterId': args.cluster_id,
        'namespace': args.namespace, 'query': QUERY, 'completePagination': True,
        'pageCount': len(pages), 'assessmentCount': len(records),
        'candidateCount': len(candidates), 'candidateSelection': 'broad text; manual review required',
        'pages': pages, 'candidates': candidates,
        'candidateSchemaPaths': sorted({p for row in candidates for p in schema_paths(row)}),
    }
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    path = folder / f'{stamp}-{args.phase}-arg-assessments.json'
    encoded = (json.dumps(payload, indent=2) + '\n').encode('utf-8')
    with path.open('xb') as stream:
        stream.write(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    with path.with_suffix('.sha256').open('x', encoding='utf-8') as stream:
        stream.write(digest + '\n')
    print(json.dumps({'file': path.name, 'phase': args.phase, 'pages': len(pages),
                      'assessments': len(records), 'candidatesRequireReview': len(candidates),
                      'sha256': digest}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
