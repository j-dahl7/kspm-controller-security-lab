"""Compare two integrity-checked Kubernetes captures without cloud calls.

The public report contains counts and configuration comparisons, never provider
identifiers, pod/ReplicaSet UIDs, image locations, API hosts, or input paths.
Phase labels are operator-supplied labels, not evidence of successful actions.
SHA-256 verifies file consistency; it does not authenticate a capture's producer.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from capture_kubernetes import DEPLOYMENTS, NAMESPACE, PHASES


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text_value(value):
    return isinstance(value, str) and bool(value.strip())


def utc_time(value):
    require(text_value(value), 'Capture timestamp is missing.')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Capture timestamp is invalid.') from None
    require(result.tzinfo is not None and result.utcoffset() == timedelta(0),
            'Capture timestamp must explicitly use UTC.')
    return result.astimezone(timezone.utc)


def load_capture(path):
    path = Path(path)
    digest_path = path.with_suffix('.sha256')
    require(path.is_file() and not path.is_symlink()
            and digest_path.is_file() and not digest_path.is_symlink(),
            'Capture and adjacent digest must be regular files.')
    require(path.stat().st_size <= 20 * 1024 * 1024
            and digest_path.stat().st_size <= 128, 'Capture or digest exceeds the size limit.')
    raw = path.read_bytes()
    expected = digest_path.read_text(encoding='utf-8').strip()
    require(re.fullmatch(r'[0-9a-f]{64}', expected) is not None, 'Invalid capture digest.')
    actual = hashlib.sha256(raw).hexdigest()
    require(actual == expected, 'Capture digest does not match.')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError('Capture is not valid JSON.') from None
    require(isinstance(value, dict), 'Capture must be an object.')
    validate_capture(value)
    return value, actual


def integer(value, minimum=0):
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def object_metadata(value, kind):
    require(isinstance(value, dict) and value.get('kind') == kind,
            'Unexpected Kubernetes object kind.')
    meta = value.get('metadata')
    require(isinstance(meta, dict) and meta.get('namespace') == NAMESPACE
            and text_value(meta.get('uid')) and text_value(meta.get('name')),
            'Object identity or namespace is invalid.')
    require(not meta.get('deletionTimestamp'), 'Deleting objects cannot form a complete comparison.')
    return meta


def owners_match(meta, kind, allowed):
    refs = meta.get('ownerReferences', [])
    require(isinstance(refs, list) and all(isinstance(ref, dict) for ref in refs),
            'Invalid owner references.')
    controlling = [ref for ref in refs if ref.get('controller') is True]
    require(len(controlling) == 1 and controlling[0].get('kind') == kind
            and allowed.get(controlling[0].get('uid')) == controlling[0].get('name'),
            'Object owner chain does not match the captured Deployment.')


def containers(spec):
    require(isinstance(spec, dict), 'Container specification is missing.')
    values = spec.get('containers')
    require(isinstance(values, list) and bool(values), 'Application containers are missing.')
    result = {}
    for item in values:
        require(isinstance(item, dict) and text_value(item.get('name'))
                and text_value(item.get('image')), 'Container identity or image is missing.')
        require(item['name'] not in result, 'Duplicate container name.')
        security = item.get('securityContext', {})
        require(isinstance(security, dict), 'Invalid container security context.')
        root = security.get('readOnlyRootFilesystem')
        require(root is None or isinstance(root, bool), 'Invalid root filesystem setting.')
        result[item['name']] = {'image': item['image'], 'root': root,
                                'rootPresent': 'readOnlyRootFilesystem' in security}
    return result


def validate_capture(value):
    require(value.get('captureComplete') is True and value.get('missingEvidence') == [],
            'Incomplete capture cannot be compared.')
    require(value.get('phase') in PHASES and value.get('namespace') == NAMESPACE,
            'Unexpected capture phase or namespace.')
    require(value.get('apiHostnameVerified') is True, 'API host verification is missing.')
    for field in ('subscriptionId', 'clusterId', 'experimentId'):
        require(text_value(value.get(field)), 'Capture scope identity is missing.')
    utc_time(value.get('capturedUtc'))
    deployment = value.get('deployment')
    meta = object_metadata(deployment, 'Deployment')
    require(meta['name'] in DEPLOYMENTS, 'Unexpected Deployment name.')
    desired, status = deployment.get('desiredReplicas'), deployment.get('status', {})
    require(integer(desired, 1) and isinstance(status, dict), 'Invalid Deployment replica state.')
    require(integer(meta.get('generation'), 1)
            and integer(status.get('observedGeneration'))
            and status['observedGeneration'] >= meta['generation'],
            'Deployment generation has not been observed.')
    require(all(integer(status.get(key)) and status[key] == desired for key in
                ('replicas', 'updatedReplicas', 'readyReplicas', 'availableReplicas')),
            'Deployment rollout is not complete.')
    containers(deployment.get('template'))
    replica_sets = value.get('replicaSets')
    require(isinstance(replica_sets, list) and replica_sets, 'ReplicaSet evidence is missing.')
    allowed_rs = {}
    active_desired = 0
    for replica_set in replica_sets:
        rs_meta = object_metadata(replica_set, 'ReplicaSet')
        require(rs_meta['uid'] not in allowed_rs, 'Duplicate ReplicaSet UID.')
        owners_match(rs_meta, 'Deployment', {meta['uid']: meta['name']})
        allowed_rs[rs_meta['uid']] = rs_meta['name']
        require(integer(replica_set.get('desiredReplicas')), 'Invalid ReplicaSet replica count.')
        active_desired += replica_set['desiredReplicas']
    require(active_desired == desired, 'ReplicaSet targets do not match the Deployment.')
    pods = value.get('pods')
    require(isinstance(pods, list) and len(pods) == desired, 'Pod count is incomplete.')
    seen = set()
    for pod in pods:
        pod_meta = object_metadata(pod, 'Pod')
        require(pod_meta['uid'] not in seen, 'Duplicate Pod UID.')
        seen.add(pod_meta['uid'])
        owners_match(pod_meta, 'ReplicaSet', allowed_rs)
        require(pod.get('phase') == 'Running' and any(
            row.get('type') == 'Ready' and row.get('status') == 'True'
            for row in pod.get('conditions', []) if isinstance(row, dict)), 'Pod is not ready.')
        spec = containers(pod.get('spec'))
        statuses = pod.get('containers')
        require(isinstance(statuses, list) and len(statuses) == len(spec)
                and all(isinstance(row, dict) and row.get('ready') is True for row in statuses)
                and {row.get('name') for row in statuses} == set(spec),
                'Container readiness evidence is incomplete.')


def pod_details(value, name):
    template = containers(value['deployment']['template']).get(name)
    observed, image_ids = [], set()
    complete_ids = True
    for pod in value['pods']:
        entry = containers(pod['spec']).get(name)
        observed.append(entry)
        matching = [item for item in pod['containers'] if item.get('name') == name]
        if len(matching) != 1 or not text_value(matching[0].get('imageID')):
            complete_ids = False
        else:
            image_ids.add(matching[0]['imageID'])
    return {
        'podCountWithContainer': sum(item is not None for item in observed),
        'allPodsMatchTemplateImage': template is not None and all(
            item is not None and item['image'] == template['image'] for item in observed),
        'allPodsMatchTemplateRootFilesystem': template is not None and all(
            item is not None and (item['root'], item['rootPresent']) ==
            (template['root'], template['rootPresent']) for item in observed),
    }, image_ids if complete_ids else None


def compare(before_path, after_path):
    before, before_hash = load_capture(before_path)
    after, after_hash = load_capture(after_path)
    for field in ('subscriptionId', 'clusterId'):
        require(before[field].lower() == after[field].lower(), 'Capture cloud scope does not match.')
    require(before['experimentId'] == after['experimentId'], 'Capture experiment does not match.')
    require(all(before['deployment']['metadata'][key] == after['deployment']['metadata'][key]
                for key in ('uid', 'name', 'namespace')),
            'Deployment identity changed; these are different controller objects.')
    for value in (before, after):
        require(text_value(value.get('clusterResourceUid')),
                'Cluster resource UID is missing; name reuse across cluster instances is not identity.')
    require(before['clusterResourceUid'] == after['clusterResourceUid'],
            'Cluster resource UID changed; these captures come from different cluster instances.')
    require(utc_time(before['capturedUtc']) < utc_time(after['capturedUtc']),
            'Before capture must precede after capture.')
    pod_ids = [{pod['metadata']['uid'] for pod in value['pods']} for value in (before, after)]
    active_rs = [{row['metadata']['uid'] for row in value['replicaSets']
                  if row['desiredReplicas'] > 0} for value in (before, after)]
    templates = [containers(value['deployment']['template']) for value in (before, after)]
    comparisons = []
    for index, name in enumerate(sorted(set(templates[0]) | set(templates[1])), 1):
        left, right = templates[0].get(name), templates[1].get(name)
        sides = []
        image_sets = []
        for value, container in ((before, left), (after, right)):
            detail, images = pod_details(value, name)
            sides.append(dict(detail, presentInTemplate=container is not None,
                readOnlyRootFilesystem=container['root'] if container else None,
                rootFilesystemFieldPresent=container['rootPresent'] if container else False))
            image_sets.append(images)
        comparisons.append({'containerAlias': f'container-{index}',
            'before': sides[0], 'after': sides[1],
            'templateImageUnchanged': bool(left and right and left['image'] == right['image']),
            'observedImageIdSetUnchanged': (image_sets[0] == image_sets[1]
                if all(item is not None for item in image_sets) else None)})
    def summary(value, digest):
        return {'sourceSHA256': digest, 'capturedUtc': utc_time(value['capturedUtc']).isoformat(),
                'phaseLabel': value['phase'],
                'desiredReplicas': value['deployment']['desiredReplicas'],
                'readyReplicas': value['deployment']['status']['readyReplicas'],
                'podCount': len(value['pods'])}
    return {'schemaVersion': '1.0', 'before': summary(before, before_hash),
            'after': summary(after, after_hash), 'sameDeploymentObject': True,
            'clusterResourceUidCompared': text_value(before.get('clusterResourceUid')),
            'podUidCounts': {'common': len(pod_ids[0] & pod_ids[1]),
                            'new': len(pod_ids[1] - pod_ids[0]),
                            'removed': len(pod_ids[0] - pod_ids[1])},
            'activeReplicaSets': {'beforeCount': len(active_rs[0]), 'afterCount': len(active_rs[1]),
                                 'uidSetChanged': active_rs[0] != active_rs[1]},
            'applicationContainers': comparisons,
            'scope': 'Two observed Kubernetes snapshots; no Defender assessment, clearance, '
                     'finding stability, or causal claim is established.',
            'limitations': ['Phase labels are supplied by the operator, not asserted outcomes.',
                           'Container aliases follow the sorted union of application-container names; '
                           'init and ephemeral containers are not compared.',
                           'Image-ID comparisons are unavailable when either snapshot lacks an ID.',
                           'Matching sidecar hashes establish file consistency, not source authenticity.',
                           'Two snapshots do not establish continuous state between captures.',
                           'Both captures carried the same Azure cluster resource UID; reused '
                           'resource names alone are never accepted as cluster identity.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True, type=Path)
    parser.add_argument('--after', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    report = compare(args.before, args.after)
    require(not args.out.exists() and not args.out.is_symlink(), 'Output already exists.')
    with args.out.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print('Comparison saved; Kubernetes observations only.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Comparison refused: capture integrity, scope, completeness, time, or output checks failed.',
              file=sys.stderr)
        sys.exit(1)
