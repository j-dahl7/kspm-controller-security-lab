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
    import probe_assessments as probe
finally:
    sys.path.pop(0)

SUB = '00000000-0000-0000-0000-000000000001'
CLUSTER = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c1'
KEY = common.DEFAULT_ASSESSMENT_KEYS[0]
URL = f'https://management.azure.com{CLUSTER}/providers/Microsoft.Security/assessments/{KEY}?api-version=2021-06-01'


class TargetedProbeBoundaries(unittest.TestCase):
    def test_only_404_is_address_not_found_not_permission_or_transient_error(self):
        for error, state in [(common.AzureCliError(1, 404, 'ResourceNotFound'), 'not-found-at-requested-url'),
                             (common.AzureCliError(1, 403, 'AuthorizationFailed'), 'error'),
                             (common.AzureCliError(1, 503, 'ServiceUnavailable', True), 'error'),
                             (common.AzureCliError(transient=True, timed_out=True), 'error'),
                             (RuntimeError('private-token 404 Not Found'), 'error')]:
            with self.subTest(error=type(error).__name__, state=state):
                def read(_):
                    raise error
                result = probe.probe_get(URL, SUB, CLUSTER, read)
                self.assertEqual(result['responseState'], state)
                self.assertNotIn('private-token', json.dumps(result))

    def test_cli_status_parser_requires_an_error_envelope(self):
        self.assertEqual(common.cli_error_details('ERROR: (ResourceNotFound) missing'), (404, 'ResourceNotFound'))
        self.assertEqual(common.cli_error_details('ERROR: Not Found({})'), (404, None))
        self.assertEqual(common.cli_error_details('ERROR: Forbidden({"error":{"code":"AuthorizationFailed","message":"404 private-token"}})'),
                         (403, 'AuthorizationFailed'))
        self.assertEqual(common.cli_error_details('request retry failed, mentioned 404 in body'), (None, None))
        self.assertEqual(common.cli_error_details('ERROR: Not Found({"error":{"code":"AuthorizationFailed"}})'),
                         (None, 'AuthorizationFailed'))

    def test_scope_validation_rejects_other_cluster_host_or_operation_before_read(self):
        for url in [URL.replace('/managedClusters/c1/', '/managedClusters/other/'),
                    URL.replace('management.azure.com', 'example.test'), URL + '&other=true',
                    URL.replace('/assessments/', '/assessments/delete/'), URL + '#fragment']:
            with self.subTest(url=url), patch.object(probe, 'az_json') as read:
                with self.assertRaises(ValueError):
                    probe.probe_get(url, SUB, CLUSTER)
                read.assert_not_called()

    def test_found_response_must_match_requested_id_and_type(self):
        resource = {'id': URL.split('management.azure.com')[1].split('?')[0],
                    'type': 'Microsoft.Security/assessments', 'properties': {'status': {'code': 'Unhealthy'}}}
        self.assertEqual(probe.probe_get(URL, SUB, CLUSTER, lambda _: resource)['responseState'], 'found')
        for changed in [dict(resource, id=resource['id'] + '-other'), {'error': {'code': 'ResourceNotFound'}}, None]:
            self.assertEqual(probe.probe_get(URL, SUB, CLUSTER, lambda _: changed)['responseState'], 'error')

    def test_default_probes_are_get_only_and_metadata_partner_data_is_excluded(self):
        calls = []
        def read(args):
            calls.append(args)
            url = args[args.index('--url') + 1]
            path = url.split('management.azure.com')[1].split('?')[0]
            kind = 'assessmentMetadata' if '/assessmentMetadata/' in path else 'assessments'
            return {'id': path, 'type': 'Microsoft.Security/' + kind,
                    'properties': {'partnerData': {'secret': 'never-save'}, 'displayName': 'Example'}}
        records = probe.collect_probes(SUB, CLUSTER, reader=read)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(args[args.index('--method') + 1] == 'get' for args in calls))
        self.assertNotIn('never-save', json.dumps(records))

    def test_main_preserves_partial_errors_and_hashes_without_claiming_absence(self):
        rows = [{'assessmentKey': KEY, 'assessment': {'responseState': 'error',
                 'error': {'httpStatus': 403}}, 'metadata': {'responseState': 'found'}}]
        argv = ['probe_assessments.py', '--subscription', SUB, '--cluster-id', CLUSTER]
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, 'argv', argv), \
             patch.object(probe, 'az_json', return_value={'id': SUB}), \
             patch.object(probe, 'collect_probes', return_value=rows), \
             patch.object(common, 'ensure_private_directory', return_value=Path(temp)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(probe.main(), 1)
            summary = json.loads(output.getvalue())
            self.assertEqual(summary['assessmentAddressesNotFound'], 0)
            self.assertFalse(summary['allProbesAnswered'])
            path = Path(temp) / summary['file']
            payload = json.loads(path.read_text())
            self.assertEqual(payload['probes'], rows)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), summary['sha256'])
            self.assertNotIn(SUB, output.getvalue())


if __name__ == '__main__':
    unittest.main()
