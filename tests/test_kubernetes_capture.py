import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('kubernetes_capture', SCRIPTS / 'capture_kubernetes.py')
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
SUB = '00000000-0000-0000-0000-000000000001'
CLUSTER_ID = f'/subscriptions/{SUB}/resourceGroups/{capture.GROUP}/providers/Microsoft.ContainerService/managedClusters/{capture.CLUSTER}'


def fixture(kind, name, uid, owner=None):
    metadata = {'name': name, 'uid': uid, 'namespace': capture.NAMESPACE, 'generation': 1}
    if owner:
        metadata['ownerReferences'] = [dict(owner, controller=True)]
    return {'kind': kind, 'metadata': metadata, 'spec': {}, 'status': {}}


def fixtures():
    dep = fixture('Deployment', capture.DEPLOYMENT, 'dep-uid')
    podspec = {'automountServiceAccountToken': False, 'containers': [
        {'name': 'pause', 'image': 'registry.k8s.io/pause:test',
         'securityContext': {'readOnlyRootFilesystem': False},
         'env': [{'name': 'TOKEN', 'value': 'never-save-this'}]}]}
    dep['spec'] = {'replicas': 1, 'template': {'spec': podspec}}
    dep['status'] = {'observedGeneration': 1, 'replicas': 1, 'updatedReplicas': 1,
                     'readyReplicas': 1, 'availableReplicas': 1}
    rs = fixture('ReplicaSet', 'proof-rs', 'rs-uid',
                 {'kind': 'Deployment', 'name': capture.DEPLOYMENT, 'uid': 'dep-uid'})
    rs['spec'] = {'replicas': 1, 'template': {'spec': podspec}}
    pod = fixture('Pod', 'proof-pod', 'pod-uid',
                  {'kind': 'ReplicaSet', 'name': 'proof-rs', 'uid': 'rs-uid'})
    pod['spec'] = podspec
    pod['metadata']['annotations'] = {'secret': 'never-save-this'}
    pod['status'] = {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                     'containerStatuses': [{'name': 'pause', 'ready': True, 'imageID': 'digest'}]}
    net = fixture('NetworkPolicy', 'default-deny-all', 'net-uid')
    quota = fixture('ResourceQuota', 'lab-resource-budget', 'quota-uid')
    def items(kind, resource):
        return {'kind': kind + 'List', 'items': [resource]}
    return dep, items('ReplicaSet', rs), items('Pod', pod), items('NetworkPolicy', net), items('ResourceQuota', quota)


class KubernetesCaptureBoundaries(unittest.TestCase):
    def test_v2_capture_requires_explicit_selection_and_matching_owner(self):
        values = fixtures()
        name = 'kspm-scope-proof-v2'
        values[0]['metadata']['name'] = name
        values[1]['items'][0]['metadata']['ownerReferences'][0]['name'] = name
        result = capture.snapshot(*values, 'baseline', deployment_name=name)
        self.assertTrue(result['captureComplete'])
        self.assertEqual(result['deployment']['metadata']['name'], name)
        with self.assertRaises(ValueError):
            capture.snapshot(*values, 'baseline')
        values[1]['items'][0]['metadata']['ownerReferences'][0]['name'] = capture.DEPLOYMENT
        with self.assertRaises(ValueError):
            capture.snapshot(*values, 'baseline', deployment_name=name)

    def test_selected_deployment_binds_named_reads_and_label_selectors(self):
        name = 'kspm-scope-proof-v2'
        selector = capture.deployment_selector(name)
        with patch.object(capture, 'run_kubectl', return_value='{}') as command:
            capture.get_json(['kubectl'], 'deployment', name=name, deployment_name=name)
            self.assertEqual(command.call_args.args[1][:3], ['get', 'deployment', name])
            capture.get_json(['kubectl'], 'pods', selector=selector, deployment_name=name)
            self.assertEqual(command.call_args.args[1][-2:], ['--selector', selector])
        rejected = [dict(resource='deployment', name=capture.DEPLOYMENT, deployment_name=name),
                    dict(resource='deployment', name='other', deployment_name='other'),
                    dict(resource='pods', selector=capture.SELECTOR, deployment_name=name),
                    dict(resource='pods', deployment_name=name),
                    dict(resource='replicasets', selector=selector, deployment_name=capture.DEPLOYMENT)]
        for arguments in rejected:
            with self.subTest(arguments=arguments), patch.object(capture, 'run_kubectl') as command:
                with self.assertRaises(ValueError):
                    capture.get_json(['kubectl'], **arguments)
                command.assert_not_called()

    def test_v2_manifest_changes_only_workload_identity_labels(self):
        root = SCRIPTS.parent / 'manifests'
        expected = json.loads((root / 'baseline-deployment.json').read_text())
        name = 'kspm-scope-proof-v2'
        expected['metadata']['name'] = name
        expected['metadata']['labels']['app.kubernetes.io/name'] = name
        expected['spec']['selector']['matchLabels']['app.kubernetes.io/name'] = name
        expected['spec']['template']['metadata']['labels']['app.kubernetes.io/name'] = name
        self.assertEqual(json.loads((root / 'baseline-deployment-v2.json').read_text()), expected)

    def test_main_v2_selection_reaches_both_reads_and_capture(self):
        name = 'kspm-scope-proof-v2'
        values = fixtures()
        values[0]['metadata']['name'] = name
        values[1]['items'][0]['metadata']['ownerReferences'][0]['name'] = name
        cluster = {'id': CLUSTER_ID, 'fqdn': 'expected.azmk8s.io',
                   'tags': {'experiment': 'kspm-123456', 'purpose': 'kspm-controller-scope'}}
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'config'
            config.write_text('unused mocked configuration')
            args = ['capture_kubernetes.py', '--subscription', SUB, '--cluster-id', CLUSTER_ID,
                    '--experiment-id', 'kspm-123456', '--kubeconfig', str(config),
                    '--phase', 'baseline', '--deployment', name]
            with patch.object(sys, 'argv', args), \
                 patch.object(capture, 'az_json', side_effect=[{'id': SUB}, cluster]), \
                 patch.object(capture.shutil, 'which', return_value='kubectl.exe'), \
                 patch.object(capture, 'run_kubectl', return_value='https://expected.azmk8s.io\nfalse'), \
                 patch.object(capture, 'get_json', side_effect=[*values, values[0]]) as read, \
                 patch.object(capture, 'ensure_private_directory', return_value=Path(temp)), \
                 patch.object(capture, 'save_capture', return_value=(Path(temp) / 'capture.json', 'hash')) as save:
                self.assertEqual(capture.main(), 0)
                self.assertEqual(save.call_args.args[0]['deployment']['metadata']['name'], name)
                self.assertEqual(read.call_args_list[0].kwargs, {'name': name, 'deployment_name': name})
                self.assertEqual(read.call_args_list[-1].kwargs, {'name': name, 'deployment_name': name})
                for call in read.call_args_list[1:3]:
                    self.assertEqual(call.kwargs, {'selector': capture.deployment_selector(name),
                                                  'deployment_name': name})

    def test_cluster_security_state_reads_flags_without_assuming_them(self):
        self.assertEqual(capture.cluster_security_state({}),
                         {'azurePolicyAddonEnabled': None, 'defenderSensorProfileEnabled': None})
        cluster = {'addonProfiles': {'azurepolicy': {'enabled': True}},
                   'securityProfile': {'defender': {'securityMonitoring': {'enabled': False}}}}
        self.assertEqual(capture.cluster_security_state(cluster),
                         {'azurePolicyAddonEnabled': True, 'defenderSensorProfileEnabled': False})
        self.assertIsNone(capture.cluster_security_state(
            {'addonProfiles': {'AzurePolicy': {'enabled': 'yes'}}, 'securityProfile': None}
        )['azurePolicyAddonEnabled'])

    def test_api_hostname_mismatch_and_insecure_transport_are_rejected(self):
        hosts = {'expected.azmk8s.io'}
        capture.validate_server('https://expected.azmk8s.io:443/', hosts)
        for server in ('https://other.azmk8s.io', 'https://expected.azmk8s.io.evil.test',
                       'http://expected.azmk8s.io', 'https://user:password@expected.azmk8s.io',
                       'https://expected.azmk8s.io/path', 'https://expected.azmk8s.io:6443'):
            with self.subTest(server=server), self.assertRaises(ValueError):
                capture.validate_server(server, hosts)
        with self.assertRaises(ValueError):
            capture.validate_server('https://expected.azmk8s.io', hosts, insecure=True)

    def test_cluster_and_experiment_must_match_exactly(self):
        cluster = {'id': CLUSTER_ID, 'fqdn': 'expected.azmk8s.io',
                   'tags': {'experiment': 'kspm-123456', 'purpose': 'kspm-controller-scope'}}
        self.assertEqual(capture.validate_cluster(SUB, CLUSTER_ID, 'kspm-123456', cluster),
                         {'expected.azmk8s.io'})
        for changed in (dict(cluster, id=CLUSTER_ID + '/other'),
                        dict(cluster, tags={'experiment': 'kspm-other1', 'purpose': 'kspm-controller-scope'})):
            with self.assertRaises(ValueError):
                capture.validate_cluster(SUB, CLUSTER_ID, 'kspm-123456', changed)

    def test_mismatched_server_stops_before_any_cluster_read(self):
        cluster = {'id': CLUSTER_ID, 'fqdn': 'expected.azmk8s.io',
                   'tags': {'experiment': 'kspm-123456', 'purpose': 'kspm-controller-scope'}}
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'config'
            config.write_text('test placeholder, never parsed by mocked kubectl')
            args = ['capture_kubernetes.py', '--subscription', SUB, '--cluster-id', CLUSTER_ID,
                    '--experiment-id', 'kspm-123456', '--kubeconfig', str(config), '--phase', 'baseline']
            with patch.object(sys, 'argv', args), \
                 patch.object(capture, 'az_json', side_effect=[{'id': SUB}, cluster]), \
                 patch.object(capture.shutil, 'which', return_value='kubectl.exe'), \
                 patch.object(capture, 'run_kubectl', return_value='https://other.azmk8s.io\nfalse') as command, \
                 patch.object(capture, 'get_json') as read:
                with self.assertRaises(ValueError):
                    capture.main()
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[1][:2], ['config', 'view'])
                read.assert_not_called()

    def test_other_namespace_is_refused_even_when_owner_matches(self):
        values = fixtures()
        values[2]['items'][0]['metadata']['namespace'] = 'production'
        with self.assertRaises(ValueError):
            capture.snapshot(*values, 'baseline')

    def test_owner_links_survive_capture_without_secrets(self):
        result = capture.snapshot(*fixtures(), 'baseline')
        self.assertTrue(result['captureComplete'])
        self.assertEqual(result['replicaSets'][0]['metadata']['ownerReferences'][0]['uid'],
                         result['deployment']['metadata']['uid'])
        self.assertEqual(result['pods'][0]['metadata']['ownerReferences'][0]['uid'],
                         result['replicaSets'][0]['metadata']['uid'])
        self.assertNotIn('never-save-this', json.dumps(result))
        self.assertFalse(result['pods'][0]['spec']['containers'][0]['securityContext']['readOnlyRootFilesystem'])

    def test_matching_names_with_wrong_owner_uid_are_rejected(self):
        for index in (1, 2):
            values = fixtures()
            values[index]['items'][0]['metadata']['ownerReferences'][0]['uid'] = 'different-uid'
            with self.subTest(index=index), self.assertRaises(ValueError):
                capture.snapshot(*values, 'baseline')

    def test_pending_rollout_is_missing_evidence(self):
        values = fixtures()
        values[0]['status']['observedGeneration'] = 0
        values[2]['items'][0]['status']['conditions'][0]['status'] = 'False'
        result = capture.snapshot(*values, 'scaled')
        self.assertFalse(result['captureComplete'])
        self.assertIn('deployment-generation-not-observed', result['missingEvidence'])
        self.assertIn('owned-pods-not-all-ready', result['missingEvidence'])

    def test_failed_command_never_returns_empty_success(self):
        failure = subprocess.CompletedProcess(['kubectl'], 1, '', 'secret must not leak')
        with patch.object(capture.subprocess, 'run', return_value=failure):
            with self.assertRaisesRegex(RuntimeError, 'evidence is missing') as caught:
                capture.run_kubectl(['kubectl'], ['get', 'pods'])
        self.assertNotIn('secret', str(caught.exception))

    def test_resource_allowlist_blocks_secrets(self):
        with patch.object(capture, 'run_kubectl') as command:
            with self.assertRaises(ValueError):
                capture.get_json(['kubectl'], 'secrets')
        command.assert_not_called()

    def test_partial_list_is_not_complete_evidence(self):
        values = fixtures()
        values[1]['metadata'] = {'continue': 'next-page'}
        with self.assertRaises(ValueError):
            capture.snapshot(*values, 'baseline')

    def test_saved_digest_covers_exact_immutable_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest = capture.save_capture(capture.snapshot(*fixtures(), 'baseline'), Path(temp))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.with_suffix('.sha256').read_text().strip(), digest)
            self.assertIn('capturedUtc', json.loads(path.read_text()))


if __name__ == '__main__':
    unittest.main()
