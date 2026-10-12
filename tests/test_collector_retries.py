"""Read retries preserve evidence while failing closed on authorization and scope."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import collect_assessments as collector
sys.path.pop(0)

SUB = '00000000-0000-0000-0000-000000000001'
CLUSTER = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c1'
URL = f'https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Security/assessments'
ARGS = ['rest', '--method', 'get', '--url', URL]
ARGV = ['collector.py', '--subscription', SUB, '--cluster-id', CLUSTER, '--phase', 'remediated']


def success(value):
    return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr='')


def failure(stderr):
    return SimpleNamespace(returncode=1, stdout='', stderr=stderr)


class CollectorReadRecovery(unittest.TestCase):
    def test_tls_eof_recovers_and_reports_only_safe_attempt_metadata(self):
        diagnostics = []
        responses = [failure('SSLEOFError: unexpected EOF during handshake; confidential-diagnostic'),
                     success({'value': [{'name': 'observed'}]})]
        with patch.object(collector, 'cli_prefix', return_value=['az']), \
             patch.object(collector.subprocess, 'run', side_effect=responses) as run, \
             patch.object(collector.time, 'sleep'):
            self.assertEqual(collector.az_json(ARGS, diagnostics), {'value': [{'name': 'observed'}]})
        self.assertEqual(run.call_count, 2)
        self.assertEqual(diagnostics[0]['failureCategory'], 'transport-connection-reset')
        self.assertEqual(diagnostics[-1], {'responseState': 'succeeded', 'attempts': 2, 'retrySafeRead': True})
        self.assertNotIn('confidential-diagnostic', json.dumps(diagnostics))

    def test_http_500_recovers_for_read(self):
        responses = [failure('ERROR: Internal Server Error({"error":{"code":"InternalServerError"}})'),
                     success({'value': []})]
        diagnostics = []
        with patch.object(collector, 'cli_prefix', return_value=['az']), \
             patch.object(collector.subprocess, 'run', side_effect=responses) as run, \
             patch.object(collector.time, 'sleep'):
            self.assertEqual(collector.az_json(ARGS, diagnostics), {'value': []})
        self.assertEqual(run.call_count, 2)
        self.assertEqual(diagnostics[0]['httpStatus'], 500)
        self.assertEqual(diagnostics[0]['failureCategory'], 'transient-http')

    def test_http_500_never_retries_write(self):
        with patch.object(collector, 'cli_prefix', return_value=['az']), \
             patch.object(collector.subprocess, 'run', return_value=failure('ERROR: (InternalServerError) unavailable')) as run, \
             patch.object(collector.time, 'sleep') as sleep:
            with self.assertRaises(collector.AzureCliError) as caught:
                collector.az_json(['rest', '--method', 'put', '--url', URL])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(caught.exception.redacted()['attempts'], 1)
        sleep.assert_not_called()

    def test_authoritative_rejections_do_not_retry_transient_words_in_body(self):
        messages = [
            'ERROR: (AuthorizationFailed) ConnectionResetError confidential-diagnostic',
            'ERROR: Unauthorized({"error":{"code":"Unauthorized","message":"ReadTimeout"}})',
            'ERROR: (InvalidScope) connection reset confidential-diagnostic',
            'ERROR: Internal Server Error({"error":{"code":"InvalidScope","message":"ReadTimeout"}})',
            'ERROR: Bad Request({"error":{"code":"InvalidQuery","message":"ServiceUnavailable"}})',
            'AADSTS700082 authentication failed ConnectionResetError',
            'SSLCertVerificationError CERTIFICATE_VERIFY_FAILED ConnectionResetError',
            'ERROR: unrecognized arguments: unexpected-option',
            'ERROR: unrecognized arguments: ConnectionResetError',
        ]
        for message in messages:
            with self.subTest(message=message), \
                 patch.object(collector, 'cli_prefix', return_value=['az']), \
                 patch.object(collector.subprocess, 'run', return_value=failure(message)) as run, \
                 patch.object(collector.time, 'sleep') as sleep:
                with self.assertRaises(collector.AzureCliError) as caught:
                    collector.az_json(ARGS)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(caught.exception.attempts, 1)
                self.assertFalse(caught.exception.transient)
                self.assertNotIn('confidential-diagnostic', json.dumps(caught.exception.redacted()))
                sleep.assert_not_called()

    def run_main(self, responses):
        with tempfile.TemporaryDirectory() as temp, patch.object(sys, 'argv', ARGV), \
             patch.object(collector, 'cli_prefix', return_value=['az']), \
             patch.object(collector.subprocess, 'run', side_effect=responses) as run, \
             patch.object(collector.time, 'sleep'), \
             patch.object(collector, 'ensure_private_directory', return_value=Path(temp)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            exit_code = collector.main()
            receipt = json.loads(output.getvalue())
            path = Path(temp) / receipt['file']
            raw = path.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), receipt['sha256'])
            self.assertEqual(path.with_suffix('.sha256').read_text().strip(), receipt['sha256'])
            self.assertNotIn('confidential-diagnostic', raw.decode())
            self.assertNotIn('confidential-diagnostic', output.getvalue())
            return exit_code, receipt, json.loads(raw), run.call_count

    def test_later_page_exhaustion_saves_incomplete_never_empty_export(self):
        responses = [success({'id': SUB}), success({'value': [{'name': 'first'}], 'nextLink': URL + '?page=2'})]
        responses += [failure('ConnectionResetError confidential-diagnostic')] * 5
        code, receipt, payload, calls = self.run_main(responses)
        self.assertEqual(code, 1)
        self.assertEqual(calls, 7)
        self.assertFalse(receipt['completePagination'])
        self.assertFalse(payload['completePagination'])
        self.assertTrue(receipt['file'].endswith('-assessments-incomplete.json'))
        self.assertEqual(payload['partialAssessmentCount'], 1)
        self.assertEqual(payload['pages'][0]['value'], [{'name': 'first'}])
        self.assertEqual(payload['error']['attempts'], 5)
        self.assertEqual(payload['error']['failureCategory'], 'transport-connection-reset')
        self.assertNotIn('assessmentCount', payload)

    def test_pagination_retry_keeps_every_page_including_empty_terminal_page(self):
        responses = [success({'id': SUB}), success({'value': [{'name': 'first'}], 'nextLink': URL + '?page=2'}),
                     failure('ConnectionResetError'),
                     success({'value': [{'name': 'second'}], 'nextLink': URL + '?page=3'}),
                     success({'value': []})]
        code, receipt, payload, calls = self.run_main(responses)
        self.assertEqual((code, calls), (0, 5))
        self.assertTrue(receipt['completePagination'])
        self.assertEqual(payload['assessmentCount'], 2)
        self.assertEqual(payload['pageCount'], 3)
        self.assertEqual([r['name'] for p in payload['pages'] for r in p['value']], ['first', 'second'])
        self.assertTrue(any(d['responseState'] == 'succeeded' and d['attempts'] == 2
                            for d in payload['readDiagnostics']))

    def test_scope_change_is_rejected_before_next_request_and_saved_incomplete(self):
        responses = [success({'id': SUB}), success({'value': [], 'nextLink': 'https://example.invalid/steal'})]
        code, receipt, payload, calls = self.run_main(responses)
        self.assertEqual((code, calls), (1, 2))
        self.assertFalse(receipt['completePagination'])
        self.assertEqual(payload['error']['failureCategory'], 'pagination-or-response-validation')

    def test_successful_empty_export_is_distinct_from_failure(self):
        code, receipt, payload, calls = self.run_main([success({'id': SUB}), success({'value': []})])
        self.assertEqual((code, calls), (0, 2))
        self.assertTrue(receipt['completePagination'])
        self.assertEqual(payload['assessmentCount'], 0)
        self.assertNotIn('error', payload)


if __name__ == '__main__':
    unittest.main()
