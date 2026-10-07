"""Read-only, ownership-checked Kubernetes evidence capture. No secrets are saved.

Exit 0: complete, ready Kubernetes snapshot; 2: snapshot saved but rollout or
fixture evidence is incomplete; 1: identity, command, or collection failure.
This does not prove a Defender assessment or a change caused by the experiment.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

from collect_assessments import GUID, az_json, ensure_private_directory, cluster_uid

NAMESPACE = 'nls-kspm-controller-lab'
DEPLOYMENT = 'kspm-scope-proof'
GROUP = 'nls-kspm-scope-20261007'
CLUSTER = 'nls-kspm-scope'
SELECTOR = 'app.kubernetes.io/name=' + DEPLOYMENT
PHASES = ('baseline', 'scaled', 'rolled', 'remediated')


def validate_cluster(subscription, cluster_id, experiment, cluster):
    if not GUID.fullmatch(subscription):
        raise ValueError('Invalid subscription GUID')
    expected = (f'/subscriptions/{subscription}/resourceGroups/{GROUP}'
                f'/providers/Microsoft.ContainerService/managedClusters/{CLUSTER}')
    if cluster_id.lower() != expected.lower() or cluster.get('id', '').lower() != expected.lower():
        raise ValueError('Unexpected Azure cluster identity')
    if not re.fullmatch(r'kspm-[a-z0-9-]{6,64}', experiment):
        raise ValueError('Invalid expected experiment tag')
    tags = cluster.get('tags', {})
    if tags.get('experiment') != experiment or tags.get('purpose') != 'kspm-controller-scope':
        raise ValueError('Azure experiment ownership mismatch')
    hosts = {cluster[key].lower().rstrip('.') for key in ('fqdn', 'privateFqdn')
             if isinstance(cluster.get(key), str) and cluster[key]}
    if not hosts:
        raise ValueError('Azure cluster has no verifiable API hostname')
    return hosts


def validate_server(server, expected_hosts, insecure=False):
    parsed = urlsplit(server)
    if (insecure or parsed.scheme != 'https' or not parsed.hostname
            or parsed.hostname.lower().rstrip('.') not in expected_hosts
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
        raise ValueError('Kubeconfig API server does not match the verified Azure cluster')


def run_kubectl(prefix, arguments):
    try:
        result = subprocess.run(prefix + arguments, capture_output=True, text=True,
                                check=False, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Kubernetes command could not complete; evidence is missing') from None
    if result.returncode:
        # Provider output can include authentication details; never echo it.
        raise RuntimeError('Kubernetes command failed; evidence is missing')
    return result.stdout


def get_json(prefix, resource, name=None, selector=None):
    if resource not in ('deployment', 'replicasets', 'pods', 'networkpolicies', 'resourcequotas'):
        raise ValueError('Resource type is outside the capture allowlist')
    args = ['get', resource]
    if name:
        if resource != 'deployment' or name != DEPLOYMENT:
            raise ValueError('Unexpected named resource')
        args.append(name)
    args += ['--namespace', NAMESPACE, '--output', 'json', '--request-timeout=60s']
    if selector:
        if selector != SELECTOR or resource not in ('replicasets', 'pods'):
            raise ValueError('Unexpected label selection')
        args += ['--selector', selector]
    return json.loads(run_kubectl(prefix, args))


def metadata(resource, kind):
    value = resource.get('metadata', {})
    if resource.get('kind') != kind or value.get('namespace') != NAMESPACE:
        raise ValueError('Resource kind or namespace is outside the fixture')
    if not value.get('name') or not value.get('uid'):
        raise ValueError('Resource identity is incomplete')
    allowed = ('name', 'namespace', 'uid', 'generation', 'resourceVersion', 'creationTimestamp',
               'deletionTimestamp')
    selected = {key: value[key] for key in allowed if key in value}
    selected['ownerReferences'] = [
        {key: owner[key] for key in ('apiVersion', 'kind', 'name', 'uid', 'controller') if key in owner}
        for owner in value.get('ownerReferences', [])
    ]
    return selected


def list_items(value, kind):
    if value.get('kind') not in (kind + 'List', 'List') or not isinstance(value.get('items'), list):
        raise ValueError('Unexpected Kubernetes list response')
    if value.get('metadata', {}).get('continue'):
        raise ValueError('Kubernetes pagination is incomplete')
    for item in value['items']:
        metadata(item, kind)
    return value['items']


def controller_owner(resource, kind, owners):
    refs = [owner for owner in resource['metadata'].get('ownerReferences', [])
            if owner.get('controller') is True]
    if (len(refs) != 1 or refs[0].get('kind') != kind
            or owners.get(refs[0].get('uid')) != refs[0].get('name')):
        raise ValueError('Resource does not belong to the fixture owner chain')


def conditions(status):
    return [{key: item[key] for key in ('type', 'status', 'reason', 'lastTransitionTime') if key in item}
            for item in status.get('conditions', [])]


def pod_spec(spec):
    # No annotations, commands, arguments, env values, volumes, kubeconfig, or secrets.
    result = {key: spec[key] for key in ('automountServiceAccountToken', 'securityContext',
                                        'hostNetwork', 'hostPID', 'hostIPC') if key in spec}
    for collection in ('containers', 'initContainers', 'ephemeralContainers'):
        if collection in spec:
            result[collection] = [
                {key: container[key] for key in ('name', 'image', 'imagePullPolicy',
                                                'securityContext', 'resources') if key in container}
                for container in spec[collection]
            ]
    return result


def controller_record(resource, kind):
    status, spec = resource.get('status', {}), resource.get('spec', {})
    return {'kind': kind, 'metadata': metadata(resource, kind),
            'desiredReplicas': spec.get('replicas'),
            'template': pod_spec(spec.get('template', {}).get('spec', {})),
            'status': {key: status[key] for key in ('observedGeneration', 'replicas', 'updatedReplicas',
                       'readyReplicas', 'availableReplicas', 'unavailableReplicas') if key in status},
            'conditions': conditions(status)}


def snapshot(deployment, replicasets, pods, networkpolicies, quotas, phase):
    if phase not in PHASES:
        raise ValueError('Unexpected capture phase')
    dep = controller_record(deployment, 'Deployment')
    if dep['metadata']['name'] != DEPLOYMENT:
        raise ValueError('Unexpected Deployment')
    rs_items = list_items(replicasets, 'ReplicaSet')
    pod_items = list_items(pods, 'Pod')
    for item in rs_items:
        controller_owner(item, 'Deployment', {dep['metadata']['uid']: DEPLOYMENT})
    rs_owners = {item['metadata']['uid']: item['metadata']['name'] for item in rs_items}
    selected_pods = []
    for item in pod_items:
        controller_owner(item, 'ReplicaSet', rs_owners)
        status = item.get('status', {})
        selected_pods.append({'kind': 'Pod', 'metadata': metadata(item, 'Pod'),
                              'spec': pod_spec(item.get('spec', {})), 'phase': status.get('phase'),
                              'conditions': conditions(status),
                              'containers': [{key: container[key] for key in
                                  ('name', 'ready', 'restartCount', 'image', 'imageID') if key in container}
                                  for container in status.get('containerStatuses', [])]})
    networks = [{'kind': 'NetworkPolicy', 'metadata': metadata(item, 'NetworkPolicy'),
                 'spec': item.get('spec', {})} for item in list_items(networkpolicies, 'NetworkPolicy')]
    resource_quotas = [{'kind': 'ResourceQuota', 'metadata': metadata(item, 'ResourceQuota'),
                       'spec': item.get('spec', {}), 'status': item.get('status', {})}
                      for item in list_items(quotas, 'ResourceQuota')]
    missing = []
    desired = dep['desiredReplicas']
    if not isinstance(desired, int) or isinstance(desired, bool) or desired < 1:
        missing.append('deployment-replica-target-missing')
    status = dep['status']
    generation = dep['metadata'].get('generation')
    if not isinstance(generation, int) or status.get('observedGeneration', 0) < generation:
        missing.append('deployment-generation-not-observed')
    if any(status.get(key, 0) != desired for key in ('replicas', 'updatedReplicas', 'readyReplicas', 'availableReplicas')):
        missing.append('deployment-rollout-pending')
    if len(selected_pods) != desired or not selected_pods or any(
        item['metadata'].get('deletionTimestamp') or item['phase'] != 'Running'
        or not any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in item['conditions'])
        or not item['containers'] or any(c.get('ready') is not True for c in item['containers'])
        for item in selected_pods
    ):
        missing.append('owned-pods-not-all-ready')
    if not any(item['metadata']['name'] == 'default-deny-all' for item in networks):
        missing.append('network-policy-not-observed')
    if not any(item['metadata']['name'] == 'lab-resource-budget' for item in resource_quotas):
        missing.append('resource-quota-not-observed')
    return {'phase': phase, 'namespace': NAMESPACE, 'deployment': dep,
            'replicaSets': [controller_record(item, 'ReplicaSet') for item in rs_items],
            'pods': selected_pods, 'networkPolicies': networks, 'resourceQuotas': resource_quotas,
            'captureComplete': not missing, 'missingEvidence': missing,
            'scope': 'Observed Kubernetes state only; not Defender assessment evidence'}


def save_capture(payload, folder):
    now = datetime.now(timezone.utc)
    payload = dict(payload, capturedUtc=now.isoformat())
    path = folder / f"{now.strftime('%Y%m%dT%H%M%S%fZ')}-{payload['phase']}-kubernetes.json"
    encoded = (json.dumps(payload, indent=2) + '\n').encode('utf-8')
    digest = hashlib.sha256(encoded).hexdigest()
    with path.open('xb') as stream:
        stream.write(encoded)
    with path.with_suffix('.sha256').open('x', encoding='utf-8') as stream:
        stream.write(digest + '\n')
    return path, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription', required=True)
    parser.add_argument('--cluster-id', required=True)
    parser.add_argument('--experiment-id', required=True)
    parser.add_argument('--kubeconfig', required=True, type=Path)
    parser.add_argument('--phase', required=True, choices=PHASES)
    args = parser.parse_args()
    if not GUID.fullmatch(args.subscription):
        parser.error('subscription must be a GUID')
    if not args.kubeconfig.is_file() or args.kubeconfig.is_symlink():
        raise ValueError('Expected an explicit regular kubeconfig file')
    account = az_json(['account', 'show', '--subscription', args.subscription])
    if account.get('id', '').lower() != args.subscription.lower():
        raise ValueError('Wrong Azure subscription context')
    cluster = az_json(['aks', 'show', '--subscription', args.subscription,
                       '--resource-group', GROUP, '--name', CLUSTER])
    hosts = validate_cluster(args.subscription, args.cluster_id, args.experiment_id, cluster)
    executable = shutil.which('kubectl')
    if not executable or Path(executable).suffix.lower() in ('.cmd', '.bat'):
        raise RuntimeError('A native kubectl executable is required')
    prefix = [executable, '--kubeconfig', str(args.kubeconfig.resolve())]
    server_output = run_kubectl(prefix, ['config', 'view', '--minify', '--output',
        'jsonpath={.clusters[0].cluster.server}{"\\n"}{.clusters[0].cluster.insecure-skip-tls-verify}'])
    server_lines = server_output.strip().splitlines()
    if not server_lines or len(server_lines) > 2:
        raise ValueError('Cannot identify exactly one selected Kubernetes API server')
    validate_server(server_lines[0], hosts,
                    insecure=len(server_lines) == 2 and server_lines[1].lower() != 'false')
    deployment = get_json(prefix, 'deployment', name=DEPLOYMENT)
    result = snapshot(deployment,
        get_json(prefix, 'replicasets', selector=SELECTOR),
        get_json(prefix, 'pods', selector=SELECTOR),
        get_json(prefix, 'networkpolicies'), get_json(prefix, 'resourcequotas'), args.phase)
    latest = get_json(prefix, 'deployment', name=DEPLOYMENT)
    first_meta, last_meta = metadata(deployment, 'Deployment'), metadata(latest, 'Deployment')
    if (last_meta['uid'], last_meta.get('generation')) != (first_meta['uid'], first_meta.get('generation')):
        result['captureComplete'] = False
        result['missingEvidence'].append('deployment-changed-during-capture')
    result.update(subscriptionId=args.subscription, clusterId=cluster['id'],
                  experimentId=args.experiment_id,
                  clusterResourceUid=cluster_uid(cluster), apiHostnameVerified=True)
    path, digest = save_capture(result, ensure_private_directory())
    print(json.dumps({'file': path.name, 'sha256': digest, 'phase': args.phase,
                      'namespace': NAMESPACE, 'deployment': DEPLOYMENT,
                      'replicaSets': len(result['replicaSets']), 'pods': len(result['pods']),
                      'captureComplete': result['captureComplete'],
                      'missingEvidence': result['missingEvidence']}))
    return 0 if result['captureComplete'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        # Avoid leaking CLI messages, kubeconfig details, tokens, or resource IDs.
        print('Kubernetes capture failed identity or collection checks; no complete evidence claimed.', file=sys.stderr)
        sys.exit(1)
