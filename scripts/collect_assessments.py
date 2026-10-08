"""Read-only, paginated Defender assessment capture. Raw output stays private.

No controller field names are assumed: the October schema must be observed.
Credentials are handled by Azure CLI and are never written by this collector.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


def cluster_uid(cluster):
    # ARM uses resourceUID; Azure CLI serializes the SDK property as resourceUid.
    values = {cluster[key] for key in ('resourceUID', 'resourceUid') if cluster.get(key)}
    if len(values) > 1 or any(not isinstance(value, str) for value in values):
        raise ValueError('Ambiguous cluster resource UID')
    return next(iter(values), None)


def cli_prefix():
    executable = shutil.which('az')
    if not executable:
        raise RuntimeError('Azure CLI is required')
    if os.name == 'nt' and executable.lower().endswith('.cmd'):
        python = Path(executable).resolve().parent.parent / 'python.exe'
        if not python.is_file():
            raise RuntimeError('Cannot resolve Azure CLI Python; refusing a shell fallback')
        return [str(python), '-IBm', 'azure.cli']
    return [executable]


def az_json(arguments):
    # Retry only known read operations. An uncertain write must never be repeated blindly.
    read_prefixes = [('account', 'show'), ('aks', 'show'), ('group', 'show'),
                     ('group', 'exists'), ('resource', 'list'), ('role', 'definition', 'list'),
                     ('deployment', 'group', 'show'), ('deployment', 'group', 'list')]
    retry_safe = any(tuple(arguments[:len(prefix)]) == prefix for prefix in read_prefixes)

    def single_option(*names):
        # Repeated/ambiguous options must not classify an effective write as a read.
        values = []
        for index, argument in enumerate(arguments):
            if argument in names:
                values.append(arguments[index + 1] if index + 1 < len(arguments) else None)
            else:
                for name in names:
                    if argument.startswith(name + '='):
                        values.append(argument[len(name) + 1:])
        return values[0] if len(values) == 1 else None

    if arguments and arguments[0] == 'rest':
        method = (single_option('--method', '-m') or '').lower()
        retry_safe = method == 'get'
        url = single_option('--url', '-u')
        if method == 'post' and url:
            target = urlsplit(url)
            retry_safe = (target.scheme == 'https' and target.netloc.lower() == 'management.azure.com'
                          and target.path.lower() == '/providers/microsoft.resourcegraph/resources'
                          and not target.fragment)
    attempts = 5 if retry_safe else 1
    command = cli_prefix() + arguments + ['--output', 'json', '--only-show-errors']
    # At most 5 x 60 seconds plus 1+2+4+8 seconds of backoff for a read.
    # Timeouts on writes have an uncertain outcome and are never retried.
    for attempt in range(attempts):
        timed_out = False
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    check=False, timeout=60)
        except subprocess.TimeoutExpired:
            timed_out = True
            transient = True
        else:
            if not result.returncode:
                return json.loads(result.stdout) if result.stdout.strip() else None
            error = result.stderr.lower()
            transient = any(marker in error for marker in
                            ['connectionreseterror', 'connection reset', 'connection aborted',
                             'readtimeout', 'connecttimeout', 'too many requests', 'toomanyrequests',
                             'serviceunavailable', 'service unavailable', 'gatewaytimeout',
                             'gateway timeout', 'badgateway', 'bad gateway'])
        if retry_safe and transient and attempt + 1 < attempts:
            time.sleep(min(2 ** attempt, 8))
            continue
        # Avoid echoing provider error bodies, account data, or credentials.
        if timed_out:
            raise RuntimeError('Azure CLI operation timed out; outcome is unconfirmed') from None
        raise RuntimeError(f'Azure CLI operation failed (exit {result.returncode}; transient={transient})')


def validate_url(url, subscription):
    parsed = urlsplit(url)
    prefix = f'/subscriptions/{subscription}/providers/microsoft.security/assessments'
    path = unquote(parsed.path).lower()
    if (parsed.scheme != 'https' or parsed.netloc.lower() != 'management.azure.com'
            or parsed.username or parsed.password or parsed.fragment
            or path != prefix.lower()):
        raise ValueError('Rejected assessment pagination URL outside the exact ARM collection')
    return url


def capture_pages(fetch, first_url, subscription, max_pages=1000):
    pages, seen, url = [], set(), first_url
    while url:
        validate_url(url, subscription)
        if url in seen or len(pages) >= max_pages:
            raise RuntimeError('Pagination loop or page limit; capture is incomplete')
        seen.add(url)
        page = fetch(url)
        if not isinstance(page, dict) or not isinstance(page.get('value'), list):
            raise ValueError('Unexpected assessment response shape')
        pages.append(page)
        url = page.get('nextLink')
        if url is not None and not isinstance(url, str):
            raise ValueError('Invalid nextLink')
    return pages


def ensure_private_directory():
    folder = ROOT / 'private'
    if folder.is_symlink() or (folder.exists() and folder.is_junction()):
        raise ValueError('Private folder must not be a link or junction')
    folder.mkdir(exist_ok=True, mode=0o700)
    if os.name == 'nt':
        who = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'],
                             capture_output=True, text=True, check=True).stdout
        sid = re.search(r'S-1-\d+(?:-\d+)+', who)
        if not sid:
            raise RuntimeError('Cannot determine Windows owner SID')
        subprocess.run(['icacls', str(folder), '/inheritance:r', '/grant:r',
                        '*' + sid.group(0) + ':(OI)(CI)F'],
                       capture_output=True, check=True)
    else:
        folder.chmod(0o700)
    return folder


def schema_paths(value, prefix=''):
    """Describe observed shape only, not values or assumed controller semantics."""
    result = set()
    if isinstance(value, dict):
        for key, item in value.items():
            path = f'{prefix}.{key}' if prefix else key
            result.add(path)
            result.update(schema_paths(item, path))
    elif isinstance(value, list):
        for item in value:
            result.update(schema_paths(item, prefix + '[]'))
    return result


def resource_details(record):
    details = (record.get('properties') or {}).get('resourceDetails') if isinstance(record, dict) else None
    return details if isinstance(details, dict) else {}


def resource_type_counts(records):
    """Count assessed-resource types per capture so a missing entity class is visible, not silent."""
    counts = {}
    for record in records:
        details = resource_details(record)
        kind = (details.get('ResourceType') or details.get('resourceType')
                or details.get('Source') or details.get('source') or 'unknown')
        kind = str(kind).lower()
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def cluster_reference_count(records, cluster_id):
    """Assessments whose assessed resource is the cluster or lives under it, for any recommendation.

    Zero means Defender has not assessed the cluster resource at all yet; that makes an
    absent KSPM record uninformative rather than a KSPM-specific negative.
    """
    needle = cluster_id.lower()
    total = 0
    for record in records:
        details = resource_details(record)
        target = str(details.get('Id') or details.get('id') or '').lower()
        if target == needle or target.startswith(needle + '/'):
            total += 1
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--cluster-id', required=True)
    parser.add_argument('--namespace', default='nls-kspm-controller-lab')
    parser.add_argument('--phase', choices=['preflight', 'baseline', 'scaled', 'rolled', 'remediated'], required=True)
    args = parser.parse_args()
    if not GUID.fullmatch(args.subscription):
        parser.error('subscription must be a GUID')
    expected = f'/subscriptions/{args.subscription}/resourcegroups/'
    if not args.cluster_id.lower().startswith(expected.lower()) or '/providers/microsoft.containerservice/managedclusters/' not in args.cluster_id.lower():
        parser.error('cluster-id must identify an AKS cluster in the selected subscription')
    account = az_json(['account', 'show', '--subscription', args.subscription])
    if account.get('id', '').lower() != args.subscription.lower():
        raise RuntimeError('Azure subscription mismatch')
    first_url = (f'https://management.azure.com/subscriptions/{args.subscription}'
                 '/providers/Microsoft.Security/assessments?api-version=2021-06-01')
    pages = capture_pages(lambda url: az_json(['rest', '--method', 'get', '--subscription', args.subscription,
                                               '--url', url]), first_url, args.subscription)
    records = [record for page in pages for record in page['value']]
    needles = [args.cluster_id.lower(), args.namespace.lower(), args.cluster_id.split('/')[-1].lower()]
    # Broad textual candidates require manual confirmation. They are not findings-count evidence.
    candidates = [r for r in records if any(n in json.dumps(r).lower() for n in needles)]
    payload = {'capturedUtc': datetime.now(timezone.utc).isoformat(), 'phase': args.phase,
               'subscriptionId': args.subscription, 'clusterId': args.cluster_id,
               'namespace': args.namespace, 'completePagination': True,
               'pageCount': len(pages), 'assessmentCount': len(records),
               'candidateCount': len(candidates), 'candidateSelection': 'broad text; manual review required',
               'resourceTypeCounts': resource_type_counts(records),
               'clusterReferencedAssessments': cluster_reference_count(records, args.cluster_id),
               'pages': pages, 'candidates': candidates,
               'candidateSchemaPaths': sorted({p for r in candidates for p in schema_paths(r)})}
    folder = ensure_private_directory()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    path = folder / f'{stamp}-{args.phase}-assessments.json'
    encoded = (json.dumps(payload, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    with path.with_suffix('.sha256').open('x', encoding='utf-8') as stream:
        stream.write(digest + '\n')
    print(json.dumps({'file': path.name, 'phase': args.phase, 'pages': len(pages),
                      'assessments': len(records), 'candidatesRequireReview': len(candidates),
                      'clusterReferencedAssessments': payload['clusterReferencedAssessments'],
                      'sha256': digest}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
