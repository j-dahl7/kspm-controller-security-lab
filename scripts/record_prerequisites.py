"""Read-only snapshots of account scope, AKS configuration, plans and Trusted Access.

These control-plane reads do not inspect sensor pods or establish discovery,
assessment processing, effective policy coverage, or feature readiness.
"""
import argparse
from datetime import datetime, timezone
import json
import re
import sys
from urllib.parse import urlsplit

from collect_assessments import (AzureCliError, az_json, cluster_uid,
                                 validate_capture_scope, write_private_capture)


def observed_component(operation):
    started = datetime.now(timezone.utc).isoformat()
    try:
        value = operation()
    except AzureCliError as error:
        result = {'responseState': ('not-found-at-requested-address' if error.http_status == 404
                                   and not error.transient and not error.timed_out else 'error'),
                  'error': error.redacted()}
    except Exception:
        result = {'responseState': 'error', 'error': {'category': 'read-or-validation-failure'}}
    else:
        result = {'responseState': 'observed', 'value': value}
    return dict(result, startedUtc=started, completedUtc=datetime.now(timezone.utc).isoformat())


def collect_prerequisites(subscription, cluster_id, experiment, reader=None):
    validate_capture_scope(subscription, cluster_id, 'nls-kspm-controller-lab')
    if not re.fullmatch(r'kspm-[a-z0-9-]{6,64}', experiment):
        raise ValueError('Expected experiment identifier')
    reader = az_json if reader is None else reader
    account = reader(['account', 'show', '--subscription', subscription])
    if not isinstance(account, dict) or str(account.get('id', '')).lower() != subscription.lower():
        raise ValueError('Azure subscription mismatch')
    result = {'account': {key: account[key] for key in ('id', 'tenantId', 'environmentName', 'state') if key in account}}
    segments = cluster_id.split('/')

    def cluster_configuration():
        cluster = reader(['aks', 'show', '--subscription', subscription,
                          '--resource-group', segments[4], '--name', segments[-1]])
        if not isinstance(cluster, dict) or str(cluster.get('id', '')).lower() != cluster_id.lower():
            raise ValueError('Unexpected AKS resource')
        tags = cluster.get('tags') or {}
        if tags.get('experiment') != experiment or tags.get('purpose') != 'kspm-controller-scope':
            raise ValueError('Cluster ownership tags do not match')
        addons = cluster.get('addonProfiles')
        if addons is not None and not isinstance(addons, dict):
            raise ValueError('Malformed add-on profile')
        security = cluster.get('securityProfile')
        if security is not None and not isinstance(security, dict):
            raise ValueError('Malformed security profile')
        defender = security.get('defender') if security else None
        return {'id': cluster['id'], 'resourceUid': cluster_uid(cluster),
                'location': cluster.get('location'), 'provisioningState': cluster.get('provisioningState'),
                'kubernetesVersion': cluster.get('kubernetesVersion'),
                'defenderProfileConfiguration': defender,
                'addonProfiles': (None if addons is None else
                                  {name: {'enabled': item.get('enabled')} for name, item in addons.items()}),
                'observationSource': 'az aks show; sensor pods and effective data-plane access not inspected'}

    result['aksConfiguration'] = observed_component(cluster_configuration)

    def pricing(name):
        resource_id = f'/subscriptions/{subscription}/providers/Microsoft.Security/pricings/{name}'
        value = reader(['rest', '--method', 'get', '--subscription', subscription,
                        '--url', f'https://management.azure.com{resource_id}?api-version=2024-01-01'])
        if not isinstance(value, dict) or str(value.get('id', '')).lower() != resource_id.lower():
            raise ValueError('Unexpected plan resource')
        properties = value.get('properties')
        if not isinstance(properties, dict):
            raise ValueError('Malformed plan configuration')
        return {'id': value['id'], 'properties': {key: properties[key] for key in
                 ('pricingTier', 'subPlan', 'extensions', 'inherited', 'inheritedFrom', 'enforce')
                 if key in properties}}

    for name in ('CloudPosture', 'Containers'):
        result[name] = observed_component(lambda name=name: pricing(name))

    def bindings():
        expected_path = cluster_id + '/trustedAccessRoleBindings'
        url = f'https://management.azure.com{expected_path}?api-version=2025-05-01'
        pages, values, seen = [], [], set()
        while url:
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.netloc.lower() != 'management.azure.com'
                    or parsed.path.lower() != expected_path.lower() or parsed.fragment
                    or url in seen or len(pages) >= 20):
                raise ValueError('Unexpected or incomplete Trusted Access pagination')
            seen.add(url)
            page = reader(['rest', '--method', 'get', '--subscription', subscription, '--url', url])
            if not isinstance(page, dict) or not isinstance(page.get('value'), list):
                raise ValueError('Malformed Trusted Access response')
            for value in page['value']:
                if (not isinstance(value, dict) or
                        not str(value.get('id', '')).lower().startswith(expected_path.lower() + '/')):
                    raise ValueError('Trusted Access binding outside selected cluster')
                values.append(value)
            pages.append(page)
            url = page.get('nextLink')
            if url is not None and not isinstance(url, str):
                raise ValueError('Malformed Trusted Access continuation')
        return {'bindings': values, 'pageCount': len(pages), 'completePagination': True}

    result['trustedAccess'] = observed_component(bindings)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--cluster-id', required=True)
    parser.add_argument('--experiment-id', required=True)
    parser.add_argument('--phase', choices=['preflight', 'baseline', 'scaled', 'rolled', 'remediated'], default='baseline')
    args = parser.parse_args()
    result = collect_prerequisites(args.subscription, args.cluster_id, args.experiment_id)
    complete = all(result[name]['responseState'] == 'observed' for name in
                   ('aksConfiguration', 'CloudPosture', 'Containers', 'trustedAccess'))
    payload = {'source': 'ReadOnlyPrerequisiteConfiguration', 'capturedUtc': datetime.now(timezone.utc).isoformat(),
               'phase': args.phase, 'subscriptionId': args.subscription, 'clusterId': args.cluster_id,
               'experimentId': args.experiment_id, 'components': result, 'allReadsObserved': complete,
               'readinessEvaluated': False,
               'limitations': ['Control-plane configuration only; no sensor-pod inspection.',
                              'A Trusted Access binding establishes a configured relationship, not completed discovery.',
                              'Plan settings do not establish effective recommendation coverage or assessment execution.',
                              'Missing or failed reads remain unknown, not disabled or healthy.']}
    path, digest = write_private_capture(payload, f'{args.phase}-prerequisites')
    print(json.dumps({'file': path.name, 'sha256': digest, 'allReadsObserved': complete,
                      'readinessEvaluated': False}))
    return 0 if complete else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Prerequisite snapshot failed; private diagnostics omitted and readiness not established.', file=sys.stderr)
        sys.exit(1)
