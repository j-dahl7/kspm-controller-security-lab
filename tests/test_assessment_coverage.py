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
    import collect_assessments as arm
    import collect_arg as arg
finally:
    sys.path.pop(0)

SUB = '00000000-0000-0000-0000-000000000001'
CLUSTER = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c1'
NAMESPACE = 'nls-kspm-controller-lab'
KEY = arm.DEFAULT_ASSESSMENT_KEYS[0]
EXTRA_KEY = '00000000-0000-0000-0000-000000000002'


def row(name, properties):
    return {'id': 'virtual/' + name, 'name': name, 'type': 'microsoft.security/assessments',
            'subscriptionId': SUB, 'properties': properties}


class AssessmentCoverage(unittest.TestCase):
    def test_rejects_empty_selectors_and_malformed_cluster_paths(self):
        bad = [(CLUSTER + '/', NAMESPACE, None), (CLUSTER + '?x=y', NAMESPACE, None),
               (CLUSTER.replace(SUB, EXTRA_KEY), NAMESPACE, None), (CLUSTER, '', None),
               (CLUSTER, ' ', None), (CLUSTER, NAMESPACE, '')]
        for cluster, namespace, workload in bad:
            with self.subTest(cluster=cluster, namespace=namespace, workload=workload), self.assertRaises(ValueError):
                arm.validate_capture_scope(SUB, cluster, namespace, workload)

    def test_independent_candidates_do_not_require_explicit_cluster_reference(self):
        records = [row(KEY.upper(), {}),
                   row('title', {'displayName': arm.ROOT_FILESYSTEM_TITLES[1].upper()}),
                   row('kind', {'resourceDetails': {'RESOURCETYPE': 'K8S-Deployment', 'Source': 'Azure'}}),
                   row('workload', {'additionalData': {'name': 'kspm-scope-proof-v2'}}),
                   row('azure-only', {'resourceDetails': {'Source': 'Azure'}}),
                   row('registry', {'resourceDetails': {'ResourceType': 'microsoft.containerregistry/registries'}})]
        candidates, matches = arm.candidate_coverage(records, CLUSTER, NAMESPACE, 'kspm-scope-proof-v2')
        self.assertEqual([r['name'] for r in candidates], [r['name'] for r in records[:4]])
        self.assertEqual(arm.cluster_reference_count(records, CLUSTER), 0)
        self.assertEqual(matches[0]['matchedCriteria'], ['assessment-key'])
        self.assertEqual({item['path'] for item in matches[0]['matchedAssessmentKeyFields']}, {'id', 'name'})
        self.assertIn('kubernetes-resource-type', matches[2]['matchedCriteria'])

    def test_key_can_be_observed_outside_finding_name_and_location_is_recorded(self):
        records = [row('opaque-finding-id', {'additionalData': {'reference': 'rule:' + EXTRA_KEY}})]
        candidates, matches = arm.candidate_coverage(records, CLUSTER, NAMESPACE, assessment_keys=[EXTRA_KEY])
        self.assertEqual(candidates, records)
        self.assertEqual(matches[0]['matchedCriteria'], ['assessment-key-text'])
        self.assertEqual(matches[0]['matchedAssessmentKeyFields'], [
            {'assessmentKey': EXTRA_KEY, 'path': 'properties.additionalData.reference', 'match': 'embedded'}])

    def test_exact_titles_do_not_select_unrelated_or_partial_titles(self):
        records = [row('partial', {'displayName': 'Root filesystem'}),
                   row('different', {'displayName': arm.ROOT_FILESYSTEM_TITLES[0] + ' (other product)'})]
        self.assertEqual(arm.candidate_coverage(records, CLUSTER, NAMESPACE)[0], [])

    def test_k8s_prefix_types_are_case_insensitive_broad_leads_without_a_separator(self):
        records = [row('deployment', {'resourceDetails': {'ResourceType': 'K8sDeployment'}}),
                   row('container', {'resourceDetails': {'resourceType': 'k8SContainer'}}),
                   row('unrelated', {'resourceDetails': {'ResourceType': 'AzureIamUser', 'Source': 'Azure'}})]
        candidates, matches = arm.candidate_coverage(records, CLUSTER, NAMESPACE)
        self.assertEqual(candidates, records[:2])
        self.assertEqual([match['matchedCriteria'] for match in matches],
                         [['kubernetes-resource-type'], ['kubernetes-resource-type']])
        self.assertEqual(arm.cluster_reference_count(candidates, CLUSTER), 0)

    def test_resource_source_is_not_reported_as_a_resource_type(self):
        self.assertEqual(arm.resource_type_counts([row('x', {'resourceDetails': {'Source': 'Azure'}})]),
                         {'unknown': 1})

    def test_arm_main_saves_all_records_and_candidate_criteria_with_hash(self):
        records = [row(KEY, {}), row('unrelated', {'resourceDetails': {'Source': 'Azure'}})]
        responses = [{'id': SUB}, {'value': records}]
        argv = ['collect_assessments.py', '--subscription', SUB, '--cluster-id', CLUSTER,
                '--phase', 'baseline', '--workload', 'proof', '--assessment-key', EXTRA_KEY]
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, 'argv', argv), \
             patch.object(arm, 'az_json', side_effect=responses), \
             patch.object(arm, 'ensure_private_directory', return_value=Path(temp)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            arm.main()
            summary = json.loads(output.getvalue())
            path = Path(temp) / summary['file']
            payload = json.loads(path.read_text())
            self.assertEqual(payload['pages'][0]['value'], records)
            self.assertEqual(payload['assessmentCount'], 2)
            self.assertEqual(payload['candidateCount'], 1)
            self.assertEqual(payload['candidateMatches'][0]['matchedCriteria'], ['assessment-key'])
            self.assertEqual(payload['clusterReferencedAssessments'], 0)
            self.assertIn('Zero does not establish', payload['clusterReferenceDefinition'])
            self.assertEqual(payload['resourceTypeCounts'], {'unknown': 2})
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), summary['sha256'])
            self.assertEqual(path.with_suffix('.sha256').read_text().strip(), summary['sha256'])
            self.assertNotIn(SUB, output.getvalue())

    def test_arg_main_saves_all_records_and_same_independent_selection(self):
        records = [row('opaque', {'resourceDetails': {'ResourceType': 'k8s-deployment'}}), row('unrelated', {})]
        response = {'data': records, 'count': 2, 'resultTruncated': False}
        argv = ['collect_arg.py', '--subscription', SUB, '--cluster-id', CLUSTER, '--phase', 'baseline']
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, 'argv', argv), \
             patch.object(arg, 'az_json', return_value={'id': SUB}), \
             patch.object(arg, 'request_page', return_value=response), \
             patch.object(arg, 'ensure_private_directory', return_value=Path(temp)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            arg.main()
            summary = json.loads(output.getvalue())
            path = Path(temp) / summary['file']
            payload = json.loads(path.read_text())
            self.assertEqual(payload['pages'][0]['data'], records)
            self.assertEqual(payload['resourceTypeCounts'], {'k8s-deployment': 1, 'unknown': 1})
            self.assertEqual(payload['clusterReferencedAssessments'], 0)
            self.assertEqual(payload['candidateMatches'][0]['matchedCriteria'], ['kubernetes-resource-type'])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), summary['sha256'])

    def test_bad_scope_fails_before_azure_request(self):
        for module in (arm, arg):
            argv = ['collector.py', '--subscription', SUB, '--cluster-id', CLUSTER + '/', '--phase', 'baseline']
            with self.subTest(module=module.__name__), patch.object(sys, 'argv', argv), \
                 patch.object(module, 'az_json') as call, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    module.main()
                call.assert_not_called()

    def test_writer_removes_credentials_and_signed_links_but_preserves_assessment_ids(self):
        payload = {'records': [{'id': CLUSTER + '/providers/Microsoft.Security/assessments/' + KEY,
                   'properties': {'accessToken': 'access-value', 'clientSecret': 'secret-value',
                                  'headers': {'Authorization': 'Bearer auth-value'},
                                  'inputLink': 'https://example.invalid/run?api-version=1&sig=signed-value',
                                  'normalLink': 'https://example.invalid/resource?id=' + KEY,
                                  'credentialPairs': [{'name': 'Authorization', 'value': 'pair-value'}]}}]}
        with tempfile.TemporaryDirectory() as temp:
            path, digest = arm.write_private_capture(payload, 'redaction-test', Path(temp))
            encoded = path.read_text()
            for value in ('access-value', 'secret-value', 'auth-value', 'signed-value', 'pair-value'):
                self.assertNotIn(value, encoded)
            saved = json.loads(encoded)
            self.assertEqual(len(saved['records']), 1)
            self.assertEqual(saved['records'][0]['id'], payload['records'][0]['id'])
            self.assertEqual(saved['records'][0]['properties']['normalLink'],
                             payload['records'][0]['properties']['normalLink'])
            self.assertEqual(len(saved['credentialRedactions']), 5)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(payload['records'][0]['properties']['accessToken'], 'access-value')


if __name__ == '__main__':
    unittest.main()
