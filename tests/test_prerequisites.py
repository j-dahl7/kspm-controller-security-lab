import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
try:
    import collect_assessments as common
    import record_prerequisites as prereqs
finally:
    sys.path.pop(0)

SUB = '00000000-0000-0000-0000-000000000001'
CLUSTER = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c1'
EXPERIMENT = 'kspm-123456'


def reader(arguments):
    if arguments[:2] == ['account', 'show']:
        return {'id': SUB, 'tenantId': SUB, 'user': {'name': 'never-save@example.invalid'}}
    if arguments[:2] == ['aks', 'show']:
        return {'id': CLUSTER, 'resourceUid': 'test-cluster-uid',
                'tags': {'experiment': EXPERIMENT, 'purpose': 'kspm-controller-scope'},
                'securityProfile': {'defender': {'securityMonitoring': {'enabled': True}}}, 'addonProfiles': {}}
    if arguments[:3] != ['rest', '--method', 'get']:
        raise AssertionError('Only reads are allowed')
    url = arguments[arguments.index('--url') + 1]
    path = url.split('management.azure.com')[1].split('?')[0]
    if '/pricings/' in path:
        return {'id': path, 'properties': {'pricingTier': 'Standard',
                'extensions': [{'name': 'AgentlessDiscoveryForKubernetes', 'isEnabled': 'True'}]}}
    return {'value': [{'id': path + '/test-binding', 'properties': {'roles': ['reader']}}]}


class PrerequisiteSnapshots(unittest.TestCase):
    def test_keeps_profiles_extensions_and_bindings_but_not_account_identity(self):
        result = prereqs.collect_prerequisites(SUB, CLUSTER, EXPERIMENT, reader)
        self.assertNotIn('never-save', json.dumps(result))
        self.assertTrue(result['aksConfiguration']['value']['defenderProfileConfiguration']['securityMonitoring']['enabled'])
        self.assertEqual(result['CloudPosture']['value']['properties']['extensions'][0]['isEnabled'], 'True')
        self.assertEqual(len(result['trustedAccess']['value']['bindings']), 1)
        self.assertIn('not inspected', result['aksConfiguration']['value']['observationSource'])

    def test_unknown_addon_configuration_is_not_inferred_disabled(self):
        def without_addons(args):
            value = reader(args)
            if args[:2] == ['aks', 'show']:
                value.pop('addonProfiles')
            return value
        result = prereqs.collect_prerequisites(SUB, CLUSTER, EXPERIMENT, without_addons)
        self.assertIsNone(result['aksConfiguration']['value']['addonProfiles'])

    def test_wrong_subscription_fails_before_cluster_reads(self):
        calls = []
        def wrong(args):
            calls.append(args)
            return {'id': '00000000-0000-0000-0000-000000000002'}
        with self.assertRaises(ValueError):
            prereqs.collect_prerequisites(SUB, CLUSTER, EXPERIMENT, wrong)
        self.assertEqual(len(calls), 1)

    def test_access_denial_cannot_become_absent_or_disabled(self):
        def denied(args):
            if args[0] == 'rest' and 'trustedAccessRoleBindings' in args[args.index('--url') + 1]:
                raise common.AzureCliError(1, 403, 'AuthorizationFailed')
            return reader(args)
        result = prereqs.collect_prerequisites(SUB, CLUSTER, EXPERIMENT, denied)
        self.assertEqual(result['trustedAccess']['responseState'], 'error')
        self.assertEqual(result['trustedAccess']['error']['httpStatus'], 403)

    def test_escaping_pagination_is_rejected_without_requesting_it(self):
        calls = []
        def escaping(args):
            calls.append(args)
            result = reader(args)
            if args[0] == 'rest' and 'trustedAccessRoleBindings' in args[args.index('--url') + 1]:
                result['nextLink'] = 'https://example.invalid/private'
            return result
        result = prereqs.collect_prerequisites(SUB, CLUSTER, EXPERIMENT, escaping)
        self.assertEqual(result['trustedAccess']['responseState'], 'error')
        self.assertFalse(any('https://example.invalid/private' in args for args in calls))

    def test_main_saves_hashed_configuration_snapshot_without_readiness_claim(self):
        argv = ['record_prerequisites.py', '--subscription', SUB, '--cluster-id', CLUSTER,
                '--experiment-id', EXPERIMENT]
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, 'argv', argv), \
             patch.object(prereqs, 'az_json', side_effect=reader), \
             patch.object(common, 'ensure_private_directory', return_value=Path(temp)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(prereqs.main(), 0)
            summary = json.loads(output.getvalue())
            path = Path(temp) / summary['file']
            payload = json.loads(path.read_text())
            self.assertFalse(payload['readinessEvaluated'])
            self.assertEqual(payload['components']['aksConfiguration']['value']['resourceUid'], 'test-cluster-uid')
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), summary['sha256'])
            self.assertNotIn(SUB, output.getvalue())


if __name__ == '__main__':
    unittest.main()
