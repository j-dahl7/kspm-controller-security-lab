import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cleanup_lab import validate_receipt, validate_live

SUB = '00000000-0000-0000-0000-000000000001'
RG = f'/subscriptions/{SUB}/resourceGroups/nls-kspm-scope-20261007'
AKS = RG + '/providers/Microsoft.ContainerService/managedClusters/nls-kspm-scope'
NODE = f'/subscriptions/{SUB}/resourceGroups/MC_lab_nodes_eastus'
RECEIPT = {'subscriptionId': SUB, 'resourceGroupId': RG, 'clusterId': AKS,
           'nodeResourceGroupId': NODE, 'experimentId': 'kspm-test001', 'clusterResourceUid': 'uid-1'}


class CleanupBoundaries(unittest.TestCase):
    def valid_receipt(self, data):
        raw = json.dumps(data).encode()
        return validate_receipt(raw, hashlib.sha256(raw).hexdigest())

    def objects(self):
        tags = {'experiment': 'kspm-test001', 'purpose': 'kspm-controller-scope'}
        return ({'id': RG, 'tags': dict(tags)},
                {'id': AKS, 'tags': dict(tags), 'nodeResourceGroup': 'MC_lab_nodes_eastus', 'resourceUID': 'uid-1'},
                [{'id': AKS}])

    def test_accepts_exact_owned_resources(self):
        self.valid_receipt(RECEIPT)
        validate_live(RECEIPT, *self.objects())

    def test_rejects_edited_receipt(self):
        raw = json.dumps(RECEIPT).encode()
        with self.assertRaises(ValueError):
            validate_receipt(raw + b' ', hashlib.sha256(raw).hexdigest())

    def test_rejects_other_named_group_even_with_matching_hash(self):
        receipt = dict(RECEIPT, resourceGroupId=RG.replace('nls-kspm-scope-20261007', 'production'))
        with self.assertRaises(ValueError):
            self.valid_receipt(receipt)

    def test_rejects_ownership_changes(self):
        for field in ['experiment', 'purpose']:
            group, cluster, resources = self.objects()
            group['tags'][field] = 'different'
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_live(RECEIPT, group, cluster, resources)

    def test_rejects_new_resource_or_replaced_cluster(self):
        group, cluster, resources = self.objects()
        resources.append({'id': RG + '/providers/Microsoft.Storage/storageAccounts/unrelated'})
        with self.assertRaises(ValueError):
            validate_live(RECEIPT, group, cluster, resources)
        group, cluster, resources = self.objects()
        cluster['resourceUID'] = 'different'
        with self.assertRaises(ValueError):
            validate_live(RECEIPT, group, cluster, resources)

    def test_rejects_managed_group_mismatch(self):
        group, cluster, resources = self.objects()
        cluster['nodeResourceGroup'] = 'unrelated'
        with self.assertRaises(ValueError):
            validate_live(RECEIPT, group, cluster, resources)

    def test_accepts_only_recorded_owned_cleanup_workflow(self):
        workflow_id = RG + '/providers/Microsoft.Logic/workflows/kspm-expiry-cleanup'
        receipt = dict(RECEIPT, cleanupWorkflowId=workflow_id)
        self.valid_receipt(receipt)
        group, cluster, resources = self.objects()
        workflow = {'id': workflow_id, 'tags': {'experiment': 'kspm-test001', 'purpose': 'kspm-controller-scope'}}
        resources.append(workflow)
        validate_live(receipt, group, cluster, resources)
        workflow['tags']['experiment'] = 'another-task'
        with self.assertRaises(ValueError):
            validate_live(receipt, group, cluster, resources)


if __name__ == '__main__':
    unittest.main()
