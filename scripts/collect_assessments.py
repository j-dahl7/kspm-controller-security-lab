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
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
DEFAULT_ASSESSMENT_KEYS = ('b4262879-2a96-468f-bacd-6ed4d567bbdd',
                           '27d6f0e9-b4d5-468b-ae7e-03d5473fd864')
ROOT_FILESYSTEM_TITLES = ('Immutable (read-only) root filesystem should be enforced for containers',
                          'Containers should use a read-only root filesystem')
CLUSTER_REFERENCE_DEFINITION = (
    'Explicit resourceDetails.Id/id equals the selected cluster ARM path or is beneath it. '
    'Zero does not establish that the cluster was not processed or that no finding exists; '
    'virtual identifiers, other reference fields, node resources and other surfaces can differ. '
    'A reused ARM path does not identify the current cluster instance or establish record freshness.')


class AzureCliError(RuntimeError):
    """Redacted failure metadata; provider message bodies are never retained."""
    def __init__(self, exit_code=None, http_status=None, error_code=None,
                 transient=False, timed_out=False, attempts=1, failure_category='unknown'):
        self.exit_code, self.http_status, self.error_code = exit_code, http_status, error_code
        self.transient, self.timed_out = transient, timed_out
        self.attempts, self.failure_category = attempts, failure_category
        message = ('Azure CLI operation timed out; outcome is unconfirmed' if timed_out else
                   f'Azure CLI operation failed (exit {exit_code}; transient={transient})')
        super().__init__(message)

    def redacted(self):
        return {'exitCode': self.exit_code, 'httpStatus': self.http_status,
                'providerErrorCode': self.error_code, 'transient': self.transient,
                'timedOut': self.timed_out, 'attempts': self.attempts,
                'failureCategory': self.failure_category}


def cli_error_details(stderr):
    """Recognize provider status/code envelopes, never a stray '404' in a message."""
    code = None
    envelope = re.search(r'^ERROR:\s*\(([A-Za-z][A-Za-z0-9_.-]{0,79})\)', stderr, re.MULTILINE)
    if envelope:
        code = envelope.group(1)
    for match in re.finditer(r'\{\s*"error"\s*:', stderr):
        try:
            body, _ = json.JSONDecoder().raw_decode(stderr[match.start():])
        except (ValueError, TypeError):
            continue
        error = body.get('error')
        candidate = error.get('code') if isinstance(error, dict) else None
        if isinstance(candidate, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,79}', candidate):
            if code and code != candidate:
                return None, None  # Conflicting envelopes cannot establish absence.
            code = candidate
            break
    code_status = {'resourcenotfound': 404, 'resourcegroupnotfound': 404, 'notfound': 404,
                   'authorizationfailed': 403, 'forbidden': 403,
                   'invalidauthenticationtoken': 401, 'unauthorized': 401,
                   'toomanyrequests': 429, 'internalservererror': 500, 'serviceunavailable': 503,
                   'gatewaytimeout': 504, 'badgateway': 502}
    status = code_status.get((code or '').lower())
    # Azure CLI az rest renders failed HTTP statuses using these leading phrases.
    header = re.search(r'^ERROR:\s*(Not Found|Forbidden|Unauthorized|Bad Request|Too Many Requests|'
                       r'Internal Server Error|Service Unavailable|Gateway Timeout|Bad Gateway)(?=\s|\(|:|$)',
                       stderr, re.MULTILINE | re.IGNORECASE)
    if header:
        header_status = {'not found': 404, 'forbidden': 403, 'unauthorized': 401,
                         'bad request': 400, 'too many requests': 429,
                         'internal server error': 500, 'service unavailable': 503, 'gateway timeout': 504,
                         'bad gateway': 502}[header.group(1).lower()]
        if status is not None and status != header_status:
            return None, code
        status = header_status
    return status, code


def cli_failure_category(stderr, http_status, error_code):
    """Return a fixed category, never provider text; explicit rejections take priority."""
    error = stderr.casefold()
    if http_status in (401, 403) or any(marker in error for marker in
            ('authorizationfailed', 'authenticationfailed', 'invalidauthenticationtoken',
             'expiredauthenticationtoken', 'aadsts', 'please run az login')):
        return 'authentication-or-authorization', False
    if error_code is not None and error_code.casefold() not in {
            'toomanyrequests', 'internalservererror', 'serviceunavailable', 'gatewaytimeout', 'badgateway'}:
        return 'provider-rejection', False
    if http_status in (429, 500, 502, 503, 504):
        return 'transient-http', True
    if http_status is not None or error_code is not None:
        return 'provider-rejection', False
    if re.search(r'(^|\n)(usage:|error:\s*(unrecognized arguments|the following arguments are required))',
                 error):
        return 'cli-argument-rejection', False
    if any(marker in error for marker in ('certificate_verify_failed', 'certificateverifyfailed',
                                          'sslcertverificationerror')):
        return 'tls-verification', False
    if any(marker in error for marker in ('connectionreseterror', 'connection reset',
                                          'connection aborted', 'remote disconnected',
                                          'remotedisconnected', 'ssleoferror')):
        return 'transport-connection-reset', True
    if any(marker in error for marker in ('readtimeout', 'connecttimeout')):
        return 'transport-timeout', True
    # Some CLI failures use a bare exception/code instead of an HTTP envelope.
    if re.fullmatch(r'\s*(TooManyRequests|ServiceUnavailable|GatewayTimeout|BadGateway)\s*',
                    stderr, re.IGNORECASE):
        return 'transient-http', True
    return 'unclassified-cli-failure', False


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


def az_json(arguments, diagnostics=None):
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
                if diagnostics is not None:
                    diagnostics.append({'responseState': 'succeeded', 'attempts': attempt + 1,
                                        'retrySafeRead': retry_safe})
                return json.loads(result.stdout) if result.stdout.strip() else None
            http_status, error_code = cli_error_details(result.stderr)
            category, transient = cli_failure_category(result.stderr, http_status, error_code)
        failure = (AzureCliError(transient=True, timed_out=True, attempts=attempt + 1,
                                 failure_category='command-timeout') if timed_out else
                   AzureCliError(result.returncode, http_status, error_code, transient,
                                 attempts=attempt + 1, failure_category=category))
        if diagnostics is not None:
            diagnostics.append(dict(failure.redacted(), responseState='error', retrySafeRead=retry_safe))
        if retry_safe and transient and attempt + 1 < attempts:
            time.sleep(min(2 ** attempt, 8))
            continue
        # Avoid echoing provider error bodies, account data, or credentials.
        raise failure from None


def validate_url(url, subscription):
    parsed = urlsplit(url)
    prefix = f'/subscriptions/{subscription}/providers/microsoft.security/assessments'
    path = unquote(parsed.path).lower()
    if (parsed.scheme != 'https' or parsed.netloc.lower() != 'management.azure.com'
            or parsed.username or parsed.password or parsed.fragment
            or path != prefix.lower()):
        raise ValueError('Rejected assessment pagination URL outside the exact ARM collection')
    return url


def capture_pages(fetch, first_url, subscription, max_pages=1000, pages=None):
    # Optional caller-owned list retains successful pages if a later read fails.
    # Callers must mark that result incomplete; this function still raises.
    pages = [] if pages is None else pages
    if pages:
        raise ValueError('Pagination must start with an empty page collection')
    seen, url = set(), first_url
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
        kind = next((value for key, value in details.items()
                     if key.lower() == 'resourcetype' and isinstance(value, str) and value.strip()), 'unknown')
        kind = str(kind).lower()
        counts[kind] = counts.get(kind, 0) + 1
    return dict(sorted(counts.items()))


def cluster_reference_count(records, cluster_id):
    """Count only explicit resourceDetails.Id/id references to this cluster ARM path.

    This is an observation aid, not a finding-eligibility gate or processing-state
    signal. Zero does not establish absence; a reused path does not prove freshness.
    """
    needle = cluster_id.lower()
    total = 0
    for record in records:
        details = resource_details(record)
        target = str(details.get('Id') or details.get('id') or '').lower()
        if target == needle or target.startswith(needle + '/'):
            total += 1
    return total


def validate_capture_scope(subscription, cluster_id, namespace, workload=None, assessment_keys=()):
    if not isinstance(subscription, str) or not GUID.fullmatch(subscription):
        raise ValueError('subscription must be a GUID')
    cluster_pattern = (rf'/subscriptions/{re.escape(subscription)}/resourceGroups/[A-Za-z0-9_.()-]+'
                       r'/providers/Microsoft\.ContainerService/managedClusters/[A-Za-z0-9_-]+')
    if not isinstance(cluster_id, str) or not re.fullmatch(cluster_pattern, cluster_id, re.IGNORECASE):
        raise ValueError('cluster-id must be an exact AKS resource ID in the selected subscription')
    if not isinstance(namespace, str) or not re.fullmatch(r'[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?', namespace):
        raise ValueError('namespace must be a nonempty Kubernetes namespace name')
    if workload is not None and (not isinstance(workload, str) or len(workload) > 253
                                or not re.fullmatch(r'[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?', workload)):
        raise ValueError('workload must be a nonempty Kubernetes resource name')
    if any(not isinstance(key, str) or not GUID.fullmatch(key) for key in assessment_keys):
        raise ValueError('assessment-key must be a GUID')


def candidate_coverage(records, cluster_id, namespace, workload=None, assessment_keys=()):
    """Broad, independent leads. Preserve every original record; never assert attribution."""
    keys = {key.lower() for key in (*DEFAULT_ASSESSMENT_KEYS, *assessment_keys)}
    titles = {title.casefold() for title in ROOT_FILESYSTEM_TITLES}
    candidates, matches = [], []

    def string_fields(value, path=''):
        if isinstance(value, str):
            yield path, value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield from string_fields(item, f'{path}.{key}' if path else key)
        elif isinstance(value, list):
            for offset, item in enumerate(value):
                yield from string_fields(item, f'{path}[{offset}]')

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        properties = record.get('properties') or {}
        metadata = properties.get('metadata') or {}
        identifiers = [record.get('name'), metadata.get('assessmentKey')]
        identifiers += re.findall(r'/assessments/([^/]+)(?:/|$)', str(record.get('id', '')), re.IGNORECASE)
        criteria = []
        matched_keys = sorted({value.lower() for value in identifiers if isinstance(value, str)} & keys)
        if matched_keys:
            criteria.append('assessment-key')
        key_fields = [{'assessmentKey': key, 'path': path,
                       'match': 'exact' if value.casefold() == key else 'embedded'}
                      for path, value in string_fields(record) for key in sorted(keys)
                      if key in value.casefold()]
        if key_fields and not matched_keys:
            criteria.append('assessment-key-text')
        if str(properties.get('displayName', '')).strip().casefold() in titles:
            criteria.append('root-filesystem-title')
        kinds = [str(value).casefold() for key, value in resource_details(record).items()
                 if key.lower() == 'resourcetype']
        if any(kind.startswith('k8s') or 'kubernetes' in kind or re.search(r'(^|[/._-])k8s([/._-]|$)', kind)
               or kind.startswith('microsoft.containerservice/managedclusters') for kind in kinds):
            criteria.append('kubernetes-resource-type')
        text = json.dumps(record, ensure_ascii=False).casefold()
        for label, value in [('cluster-id-text', cluster_id), ('cluster-name-text', cluster_id.rsplit('/', 1)[1]),
                             ('namespace-text', namespace), ('workload-text', workload)]:
            if value and value.casefold() in text:
                criteria.append(label)
        if criteria:
            candidates.append(record)
            matches.append({'recordIndex': index, 'assessmentId': record.get('id'),
                            'matchedCriteria': criteria, 'matchedAssessmentKeys': matched_keys,
                            'matchedAssessmentKeyFields': key_fields})
    return candidates, matches


def write_private_capture(payload, suffix, folder=None):
    if not re.fullmatch(r'[a-z0-9-]+', suffix):
        raise ValueError('Invalid capture suffix')
    folder = ensure_private_directory() if folder is None else folder
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    path = folder / f'{stamp}-{suffix}.json'
    payload, redactions = redact_credentials(payload)
    payload['credentialRedactions'] = redactions
    encoded = (json.dumps(payload, indent=2) + '\n').encode('utf-8')
    digest = hashlib.sha256(encoded).hexdigest()
    with path.open('xb') as stream:
        stream.write(encoded)
    with path.with_suffix('.sha256').open('x', encoding='utf-8') as stream:
        stream.write(digest + '\n')
    return path, digest


def redact_credentials(value):
    """Remove credential values without removing records or ordinary resource IDs.

    This is a targeted safeguard, not a general PII classifier. Paths/reasons are
    retained so a saved capture never silently claims to be an untouched response.
    """
    sensitive = {'accesstoken', 'refreshtoken', 'idtoken', 'clientsecret', 'password',
                 'secret', 'authorization', 'proxyauthorization', 'apikey', 'accountkey',
                 'sastoken', 'connectionstring', 'privatekey', 'certificatepassword',
                 'credential', 'credentials', 'token', 'signature', 'sig',
                 'xamzsignature', 'xgoogsignature'}
    query_sensitive = sensitive | {'code', 'xamzcredential', 'xgoogcredential'}
    redactions = []

    def normalized(key):
        return re.sub(r'[^a-z0-9]', '', key.casefold())

    def mark(path, reason):
        item = {'path': path, 'reason': reason}
        if item not in redactions:
            redactions.append(item)

    def walk(item, path):
        if isinstance(item, dict):
            result = {}
            header_name = item.get('name', item.get('key', ''))
            named_secret = isinstance(header_name, str) and normalized(header_name) in sensitive
            for key, child in item.items():
                child_path = f'{path}.{key}' if path else key
                if normalized(key) in sensitive or (named_secret and key.casefold() == 'value'):
                    result[key] = '[REDACTED]'
                    mark(child_path, 'credential-field')
                else:
                    result[key] = walk(child, child_path)
            return result
        if isinstance(item, list):
            return [walk(child, f'{path}[{index}]') for index, child in enumerate(item)]
        if not isinstance(item, str):
            return item

        def scrub_url(match):
            url = match.group(0)
            try:
                parsed = urlsplit(url)
                query = parse_qsl(parsed.query, keep_blank_values=True)
                changed = any(normalized(key) in query_sensitive for key, _ in query)
                credentials = parsed.username is not None or parsed.password is not None
                if not changed and not credentials:
                    return url
                netloc = parsed.netloc
                if credentials:
                    netloc = parsed.hostname or ''
                    if parsed.port:
                        netloc += ':' + str(parsed.port)
                safe_query = [(key, '[REDACTED]' if normalized(key) in query_sensitive else val)
                              for key, val in query]
                mark(path, 'credential-bearing-url')
                return urlunsplit((parsed.scheme, netloc, parsed.path,
                                   urlencode(safe_query), parsed.fragment))
            except ValueError:
                mark(path, 'unparseable-url')
                return '[REDACTED URL]'

        item = re.sub(r'https?://[^\s<>"\']+', scrub_url, item)
        if re.search(r'\bBearer\s+[A-Za-z0-9._~+/-]+=*', item, re.IGNORECASE):
            item = re.sub(r'\bBearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer [REDACTED]', item, flags=re.IGNORECASE)
            mark(path, 'bearer-credential')
        return item

    return walk(value, ''), redactions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--cluster-id', required=True)
    parser.add_argument('--namespace', default='nls-kspm-controller-lab')
    parser.add_argument('--workload')
    parser.add_argument('--assessment-key', action='append', default=[])
    parser.add_argument('--phase', choices=['preflight', 'baseline', 'scaled', 'rolled', 'remediated'], required=True)
    args = parser.parse_args()
    try:
        validate_capture_scope(args.subscription, args.cluster_id, args.namespace,
                               args.workload, args.assessment_key)
    except ValueError as error:
        parser.error(str(error))
    read_diagnostics = []
    account = az_json(['account', 'show', '--subscription', args.subscription],
                      diagnostics=read_diagnostics)
    if not isinstance(account, dict) or account.get('id', '').lower() != args.subscription.lower():
        raise RuntimeError('Azure subscription mismatch')
    first_url = (f'https://management.azure.com/subscriptions/{args.subscription}'
                 '/providers/Microsoft.Security/assessments?api-version=2021-06-01')
    pages = []
    try:
        capture_pages(lambda url: az_json(['rest', '--method', 'get', '--subscription', args.subscription,
                                           '--url', url], diagnostics=read_diagnostics),
                      first_url, args.subscription, pages=pages)
    except (AzureCliError, ValueError, RuntimeError) as error:
        failure = (error.redacted() if isinstance(error, AzureCliError) else
                   {'failureCategory': 'pagination-or-response-validation'})
        payload = {'capturedUtc': datetime.now(timezone.utc).isoformat(), 'phase': args.phase,
                   'subscriptionId': args.subscription, 'clusterId': args.cluster_id,
                   'completePagination': False, 'pageCount': len(pages),
                   'partialAssessmentCount': sum(len(page['value']) for page in pages),
                   'pages': pages, 'readDiagnostics': read_diagnostics, 'error': failure,
                   'interpretation': 'Incomplete export; never interpret as an empty or complete assessment result.'}
        path, digest = write_private_capture(payload, f'{args.phase}-assessments-incomplete')
        print(json.dumps({'file': path.name, 'phase': args.phase, 'completePagination': False,
                          'pages': len(pages), 'error': failure, 'sha256': digest}))
        return 1
    records = [record for page in pages for record in page['value']]
    candidates, matches = candidate_coverage(records, args.cluster_id, args.namespace,
                                             args.workload, args.assessment_key)
    payload = {'capturedUtc': datetime.now(timezone.utc).isoformat(), 'phase': args.phase,
               'subscriptionId': args.subscription, 'clusterId': args.cluster_id,
               'namespace': args.namespace, 'workload': args.workload, 'completePagination': True,
               'candidateAssessmentKeys': sorted(set(DEFAULT_ASSESSMENT_KEYS) | {key.lower() for key in args.assessment_key}),
               'pageCount': len(pages), 'assessmentCount': len(records),
               'candidateCount': len(candidates), 'candidateSelection': 'independent key/title/type/text leads; attribution and freshness require review',
               'candidateMatches': matches, 'clusterReferenceDefinition': CLUSTER_REFERENCE_DEFINITION,
               'resourceTypeCounts': resource_type_counts(records),
               'clusterReferencedAssessments': cluster_reference_count(records, args.cluster_id),
               'pages': pages, 'candidates': candidates,
               'readDiagnostics': read_diagnostics,
               'candidateSchemaPaths': sorted({p for r in candidates for p in schema_paths(r)})}
    path, digest = write_private_capture(payload, f'{args.phase}-assessments')
    print(json.dumps({'file': path.name, 'phase': args.phase, 'pages': len(pages),
                      'assessments': len(records), 'candidatesRequireReview': len(candidates),
                      'clusterReferencedAssessments': payload['clusterReferencedAssessments'],
                      'completePagination': True, 'sha256': digest}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Assessment capture failed; no complete evidence claimed. Provider details omitted.', file=sys.stderr)
        sys.exit(1)
