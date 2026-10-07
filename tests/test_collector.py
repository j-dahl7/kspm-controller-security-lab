import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('collector', Path(__file__).resolve().parents[1] / 'scripts' / 'collect_assessments.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
SUB = '00000000-0000-0000-0000-000000000001'
BASE = f'https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Security/assessments'


class CollectorBoundaries(unittest.TestCase):
    def test_accepts_verified_arm_and_cli_uid_spellings(self):
        self.assertEqual(collector.cluster_uid({'resourceUid': 'example-uid'}), 'example-uid')
        self.assertEqual(collector.cluster_uid({'resourceUID': 'example-uid'}), 'example-uid')
        self.assertIsNone(collector.cluster_uid({}))
        with self.assertRaises(ValueError):
            collector.cluster_uid({'resourceUID': 'one', 'resourceUid': 'two'})

    def test_pagination_keeps_every_record(self):
        pages = {BASE: {'value': [{'id': 'first'}], 'nextLink': BASE + '?page=2'},
                 BASE + '?page=2': {'value': [{'id': 'second'}]}}
        result = collector.capture_pages(pages.__getitem__, BASE, SUB)
        self.assertEqual([r['id'] for p in result for r in p['value']], ['first', 'second'])

    def test_rejects_untrusted_next_link_before_fetch(self):
        called = []
        def fetch(url):
            called.append(url)
            return {'value': [], 'nextLink': 'https://example.com/steal'}
        with self.assertRaises(ValueError):
            collector.capture_pages(fetch, BASE, SUB)
        self.assertEqual(called, [BASE])

    def test_rejects_other_subscription_and_credentials(self):
        for url in [BASE.replace(SUB, '00000000-0000-0000-0000-000000000002'),
                    BASE.replace('https://', 'http://'),
                    BASE.replace('management.azure.com', 'management.azure.com.evil.test'),
                    BASE.replace('management.azure.com', 'user@management.azure.com'), BASE + '/../../secrets']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                collector.validate_url(url, SUB)

    def test_loop_does_not_report_complete_capture(self):
        with self.assertRaises(RuntimeError):
            collector.capture_pages(lambda _: {'value': [], 'nextLink': BASE}, BASE, SUB)

    def test_malformed_page_fails(self):
        with self.assertRaises(ValueError):
            collector.capture_pages(lambda _: {'error': 'denied'}, BASE, SUB)

    def test_schema_preserves_nested_array_paths_not_values(self):
        paths = collector.schema_paths({'properties': {'targets': [{'uid': 'private-value'}]}})
        self.assertIn('properties.targets[].uid', paths)
        self.assertNotIn('private-value', paths)

    def test_read_retries_transient_reset(self):
        for arguments in [['rest', '--method', 'get', '--url', BASE], ['resource', 'list', '--resource-group', 'example']]:
            responses = [SimpleNamespace(returncode=1, stdout='', stderr='ConnectionResetError'),
                         SimpleNamespace(returncode=0, stdout='{"value":[]}', stderr='')]
            with self.subTest(arguments=arguments), patch.object(collector, 'cli_prefix', return_value=['az']), patch.object(collector.subprocess, 'run', side_effect=responses) as run, patch.object(collector.time, 'sleep'):
                self.assertEqual(collector.az_json(arguments), {'value': []})
                self.assertEqual(run.call_count, 2)

    def test_write_is_not_retried_after_uncertain_failure(self):
        failed = SimpleNamespace(returncode=1, stdout='', stderr='ConnectionResetError')
        with patch.object(collector, 'cli_prefix', return_value=['az']), patch.object(collector.subprocess, 'run', return_value=failed) as run:
            with self.assertRaises(RuntimeError):
                collector.az_json(['rest', '--method', 'delete', '--url', BASE])
            self.assertEqual(run.call_count, 1)

    def test_empty_success_response_is_allowed_for_delete_request(self):
        empty = SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(collector, 'cli_prefix', return_value=['az']), patch.object(collector.subprocess, 'run', return_value=empty):
            self.assertIsNone(collector.az_json(['group', 'delete', '--name', 'example']))


if __name__ == '__main__':
    unittest.main()
