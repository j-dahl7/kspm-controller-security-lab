"""Plan-only by default. Delete only the exact experiment recorded at deployment."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from collect_assessments import GUID, az_json, cluster_uid

GROUP = 'nls-kspm-scope-20261007'
CLUSTER = 'nls-kspm-scope'


def validate_receipt(raw, trusted_digest):
    if not re.fullmatch(r'[0-9a-f]{64}', trusted_digest):
        raise ValueError('Expected a trusted SHA-256 receipt digest')
    if hashlib.sha256(raw).hexdigest() != trusted_digest:
        raise ValueError('Deployment receipt changed')
    receipt = json.loads(raw)
    sub = receipt.get('subscriptionId', '')
    if not GUID.fullmatch(sub):
        raise ValueError('Invalid subscription')
    group_id = f'/subscriptions/{sub}/resourceGroups/{GROUP}'
    cluster_id = group_id + f'/providers/Microsoft.ContainerService/managedClusters/{CLUSTER}'
    if receipt.get('resourceGroupId', '').lower() != group_id.lower():
        raise ValueError('Unexpected resource group')
    if receipt.get('clusterId', '').lower() != cluster_id.lower():
        raise ValueError('Unexpected cluster')
    experiment = receipt.get('experimentId', '')
    if not re.fullmatch(r'kspm-[a-z0-9-]{6,64}', experiment):
        raise ValueError('Invalid experiment tag')
    node_id = receipt.get('nodeResourceGroupId', '')
    if not re.fullmatch(re.escape(f'/subscriptions/{sub}/resourceGroups/') + r'[A-Za-z0-9_.()-]+', node_id, re.I):
        raise ValueError('Unexpected managed node group')
    if node_id.lower() == group_id.lower():
        raise ValueError('Managed node group must be distinct')
    expected_cleanup = group_id + '/providers/Microsoft.Logic/workflows/kspm-expiry-cleanup'
    if receipt.get('cleanupWorkflowId') and receipt['cleanupWorkflowId'].lower() != expected_cleanup.lower():
        raise ValueError('Unexpected cleanup workflow')
    return receipt


def validate_live(receipt, group, cluster, resources):
    experiment = receipt['experimentId']
    for actual, expected in [(group, receipt['resourceGroupId']), (cluster, receipt['clusterId'])]:
        if actual.get('id', '').lower() != expected.lower():
            raise ValueError('Live resource identity mismatch')
        if actual.get('tags', {}).get('experiment') != experiment:
            raise ValueError('Experiment ownership tag mismatch')
        if actual.get('tags', {}).get('purpose') != 'kspm-controller-scope':
            raise ValueError('Experiment purpose tag mismatch')
    node_name = receipt['nodeResourceGroupId'].rsplit('/', 1)[1]
    if cluster.get('nodeResourceGroup', '').lower() != node_name.lower():
        raise ValueError('Managed node group relationship changed')
    if receipt.get('clusterResourceUid'):
        if cluster_uid(cluster) != receipt['clusterResourceUid']:
            raise ValueError('Cluster UID changed')
    allowed_ids = {receipt['clusterId'].lower()}
    if receipt.get('cleanupWorkflowId'):
        allowed_ids.add(receipt['cleanupWorkflowId'].lower())
    unexpected = [item for item in resources if item.get('id', '').lower() not in allowed_ids]
    if unexpected:
        raise ValueError('Dedicated group contains unexpected resources; manual review required')
    for item in resources:
        if item.get('id', '').lower() == receipt.get('cleanupWorkflowId', '').lower():
            if item.get('tags', {}).get('experiment') != experiment or item.get('tags', {}).get('purpose') != 'kspm-controller-scope':
                raise ValueError('Cleanup workflow ownership changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.receipt.is_symlink() or args.receipt.stat().st_size > 16384:
        raise ValueError('Unexpected receipt file')
    receipt = validate_receipt(args.receipt.read_bytes(), args.receipt_sha256)
    sub = receipt['subscriptionId']
    node_group = receipt['nodeResourceGroupId'].rsplit('/', 1)[1]
    account = az_json(['account', 'show', '--subscription', sub])
    if account['id'].lower() != sub.lower():
        raise ValueError('Wrong subscription context')
    exists = az_json(['group', 'exists', '--subscription', sub, '--name', GROUP])
    if not exists:
        node_exists = az_json(['group', 'exists', '--subscription', sub, '--name', node_group])
        if node_exists:
            raise RuntimeError('Main group absent but managed group remains; review required')
        print(json.dumps({'status': 'already-absent', 'resourcesChanged': False}))
        return
    group = az_json(['group', 'show', '--subscription', sub, '--name', GROUP])
    cluster = az_json(['aks', 'show', '--subscription', sub, '--resource-group', GROUP, '--name', CLUSTER])
    resources = az_json(['resource', 'list', '--subscription', sub, '--resource-group', GROUP])
    validate_live(receipt, group, cluster, resources)
    if not args.execute:
        print(json.dumps({'status': 'validated-plan-only', 'resourceGroup': GROUP,
                          'cluster': CLUSTER, 'changesPricing': False}))
        return
    # Delete the containing experiment group; AKS owns removal of its managed node group.
    # No direct managed-node-group deletion or subscription-wide cleanup is permitted.
    az_json(['group', 'delete', '--subscription', sub, '--name', GROUP, '--yes', '--no-wait'])
    print(json.dumps({'status': 'deletion-requested-not-verified', 'resourceGroup': GROUP}))


if __name__ == '__main__':
    main()
