import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import compare_captures as compare
from test_kubernetes_capture import capture, fixtures, SUB, CLUSTER_ID


def example(phase='baseline', minute=0, count=1, readonly=False, suffix='a'):
    values = list(copy.deepcopy(fixtures()))
    values[0]['spec']['replicas'] = count
    for field in ('replicas', 'updatedReplicas', 'readyReplicas', 'availableReplicas'):
        values[0]['status'][field] = count
    values[0]['spec']['template']['spec']['containers'][0]['securityContext']['readOnlyRootFilesystem'] = readonly
    rs = values[1]['items'][0]
    rs['metadata']['uid'] = 'rs-' + suffix
    rs['spec']['replicas'] = count
    pod = values[2]['items'][0]
    pod['metadata']['ownerReferences'][0]['uid'] = rs['metadata']['uid']
    values[2]['items'] = []
    for index in range(count):
        item = copy.deepcopy(pod)
        item['metadata']['uid'] = f'pod-{suffix}-{index}'
        item['metadata']['name'] = f'pod-{index}'
        values[2]['items'].append(item)
    result = capture.snapshot(*values, phase)
    result.update(subscriptionId=SUB, clusterId=CLUSTER_ID,
                  experimentId='kspm-synthetic-only', clusterResourceUid='cluster-uid-private',
                  apiHostnameVerified=True, capturedUtc=f'2026-10-07T12:{minute:02d}:00Z',
                  apiHostname='example.test')
    return result


class CaptureComparison(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def save(self, name, value):
        path = self.root / (name + '.json')
        encoded = (json.dumps(value) + '\n').encode('utf-8')
        path.write_bytes(encoded)
        path.with_suffix('.sha256').write_text(hashlib.sha256(encoded).hexdigest() + '\n')
        return path

    def run_pair(self, before, after):
        return compare.compare(self.save('before', before), self.save('after', after))

    def test_v2_comparison_accepts_known_name_but_refuses_cross_deployment(self):
        def rename(value, name):
            value['deployment']['metadata']['name'] = name
            for replica_set in value['replicaSets']:
                replica_set['metadata']['ownerReferences'][0]['name'] = name
            return value
        name = 'kspm-scope-proof-v2'
        before = rename(example(), name)
        after = rename(example('scaled', 1, count=3), name)
        self.assertTrue(self.run_pair(before, after)['sameDeploymentObject'])
        # Even a reused UID cannot justify comparing two distinct allowed names.
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            self.run_pair(example(), after)
        with self.assertRaisesRegex(ValueError, 'Unexpected Deployment name'):
            self.run_pair(before, rename(example(minute=1), 'arbitrary-workload'))

    def test_valid_scaling_reports_counts_without_asserting_phase_outcome(self):
        result = self.run_pair(example(), example('scaled', 1, count=3))
        self.assertEqual(result['podUidCounts'], {'common': 1, 'new': 2, 'removed': 0})
        self.assertEqual(result['before']['desiredReplicas'], 1)
        self.assertEqual(result['after']['readyReplicas'], 3)
        self.assertFalse(result['activeReplicaSets']['uidSetChanged'])
        self.assertTrue(result['applicationContainers'][0]['templateImageUnchanged'])
        self.assertTrue(result['applicationContainers'][0]['observedImageIdSetUnchanged'])
        self.assertIn('not asserted outcomes', result['limitations'][0])

    def test_readonly_template_change_reports_replacement_and_image_invariant(self):
        result = self.run_pair(example(count=3), example('remediated', 2, 3, True, 'b'))
        self.assertEqual(result['podUidCounts'], {'common': 0, 'new': 3, 'removed': 3})
        self.assertTrue(result['activeReplicaSets']['uidSetChanged'])
        container = result['applicationContainers'][0]
        self.assertFalse(container['before']['readOnlyRootFilesystem'])
        self.assertTrue(container['after']['readOnlyRootFilesystem'])
        self.assertTrue(container['after']['allPodsMatchTemplateRootFilesystem'])
        serialized = json.dumps(result)
        for private in (SUB, CLUSTER_ID, 'cluster-uid-private', 'dep-uid', 'rs-b',
                        'pod-b-0', 'example.test', 'registry.k8s.io/pause:test'):
            self.assertNotIn(private, serialized)

    def test_altered_bytes_rejected(self):
        before, after = self.save('before', example()), self.save('after', example(minute=1))
        after.write_bytes(after.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'digest'):
            compare.compare(before, after)

    def test_scope_completeness_and_clock_refusals(self):
        changes = [lambda x: x.update(captureComplete=False),
                   lambda x: x.update(missingEvidence=['pending']),
                   lambda x: x.update(clusterId=x['clusterId'] + '-other'),
                   lambda x: x.update(subscriptionId='different-subscription'),
                   lambda x: x.update(experimentId='kspm-other-experiment'),
                   lambda x: x['deployment']['metadata'].update(uid='another-deployment'),
                   lambda x: x.update(clusterResourceUid='another-cluster'),
                   lambda x: x.update(capturedUtc='2026-10-07T11:59:00Z'),
                   lambda x: x.update(capturedUtc='2026-10-07T12:00:00Z'),
                   lambda x: x.update(capturedUtc='2026-10-07T12:01:00'),
                   lambda x: x.update(capturedUtc='2026-10-07T12:01:00-05:00'),
                   lambda x: x.update(phase='production'),
                   lambda x: x.update(namespace='production')]
        for index, change in enumerate(changes):
            after = example(minute=1)
            change(after)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.run_pair(example(), after)

    def test_false_complete_flag_cannot_hide_not_ready_or_broken_owner(self):
        changes = [lambda x: x['pods'][0]['conditions'][0].update(status='False'),
                   lambda x: x['pods'][0]['metadata']['ownerReferences'][0].update(uid='foreign'),
                   lambda x: x['deployment']['status'].update(readyReplicas=0)]
        for change in changes:
            after = example(minute=1)
            change(after)
            with self.assertRaises(ValueError):
                self.run_pair(example(), after)

    def test_missing_image_id_is_unknown_not_unchanged(self):
        after = example(minute=1)
        after['pods'][0]['containers'][0].pop('imageID')
        result = self.run_pair(example(), after)
        self.assertIsNone(result['applicationContainers'][0]['observedImageIdSetUnchanged'])

    def test_cli_public_report_refuses_overwrite(self):
        before, after = self.save('before', example()), self.save('after', example(minute=1))
        output = self.root / 'public.json'
        args = ['--before', str(before), '--after', str(after), '--out', str(output)]
        self.assertEqual(compare.main(args), 0)
        original = output.read_bytes()
        with self.assertRaises(ValueError):
            compare.main(args)
        self.assertEqual(output.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
