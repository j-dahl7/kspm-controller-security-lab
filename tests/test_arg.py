import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
try:
    import collect_arg as collector
finally:
    sys.path.pop(0)

SUB = '00000000-0000-0000-0000-000000000001'


def row(name='one', subscription=SUB):
    return {'id': name, 'name': name, 'type': 'microsoft.security/assessments',
            'subscriptionId': subscription, 'properties': {}}


def page(rows=None, truncated=False, token=None):
    rows = [] if rows is None else rows
    result = {'data': rows, 'count': len(rows), 'resultTruncated': truncated}
    if token is not None:
        result['$skipToken'] = token
    return result


class ArgCollectorBoundaries(unittest.TestCase):
    def test_two_pages_keep_scope_query_and_all_rows(self):
        calls = []
        def fetch(body):
            calls.append(body)
            return page([row('one')], 'true', 'next') if len(calls) == 1 else page([row('two')], 'false')
        pages = collector.capture_pages(fetch, SUB)
        self.assertEqual([r['id'] for p in pages for r in p['data']], ['one', 'two'])
        for body in calls:
            self.assertEqual(body['subscriptions'], [SUB])
            self.assertEqual(body['query'], collector.QUERY)
            self.assertEqual(body['options']['resultFormat'], 'objectArray')
        self.assertNotIn('$skipToken', calls[0]['options'])
        self.assertEqual(calls[1]['options']['$skipToken'], 'next')

    def test_truncation_without_token_fails(self):
        for flag in (True, 'true', 'TRUE'):
            with self.subTest(flag=flag), self.assertRaises(RuntimeError):
                collector.capture_pages(lambda _: page([row()], flag), SUB)

    def test_bad_response_shapes_and_count_fail(self):
        for value in (None, {}, {'data': {}}, {'data': [], 'resultTruncated': 'maybe'},
                      {'data': [], 'resultTruncated': False, 'count': 2},
                      page(['not-an-object']), page([{}])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.capture_pages(lambda _: value, SUB)

    def test_other_subscription_row_rejected(self):
        with self.assertRaises(ValueError):
            collector.capture_pages(lambda _: page([row(subscription=SUB[:-1] + '2')]), SUB)

    def test_wrong_resource_type_rejected(self):
        item = row()
        item['type'] = 'microsoft.compute/virtualmachines'
        with self.assertRaises(ValueError):
            collector.capture_pages(lambda _: page([item]), SUB)

    def test_loop_rejected_before_reusing_token(self):
        calls = []
        def fetch(body):
            calls.append(body)
            return page([row()], True, 'same')
        with self.assertRaises(RuntimeError):
            collector.capture_pages(fetch, SUB)
        self.assertEqual(len(calls), 2)

    def test_invalid_token_and_missing_truncation_rejected(self):
        for value in (page([], True, 123), page([], False, ''), {'data': []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.capture_pages(lambda _: value, SUB)

    def test_page_limit_does_not_return_partial_success(self):
        with self.assertRaises(RuntimeError):
            collector.capture_pages(lambda _: page([row()], True, 'next'), SUB, max_pages=1)

    def test_complete_empty_result_is_valid(self):
        self.assertEqual(collector.capture_pages(lambda _: page(), SUB), [page()])

    def test_private_request_file_is_removed_on_success_and_failure(self):
        body = {'subscriptions': [SUB], 'query': collector.QUERY, 'options': {'resultFormat': 'objectArray'}}
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as folder:
                paths = []
                def invoke(arguments):
                    self.assertEqual(arguments[arguments.index('--method') + 1], 'post')
                    self.assertEqual(arguments[arguments.index('--url') + 1], collector.ARG_URL)
                    argument = arguments[arguments.index('--body') + 1]
                    self.assertTrue(argument.startswith('@'))
                    path = Path(argument[1:])
                    self.assertEqual(path.parent, Path(folder))
                    self.assertEqual(json.loads(path.read_text(encoding='utf-8')), body)
                    paths.append(path)
                    if fail:
                        raise RuntimeError('test request failed')
                    return page()
                with patch.object(collector, 'az_json', side_effect=invoke):
                    if fail:
                        with self.assertRaises(RuntimeError):
                            collector.request_page(body, SUB, Path(folder))
                    else:
                        self.assertEqual(collector.request_page(body, SUB, Path(folder)), page())
                self.assertEqual(len(paths), 1)
                self.assertFalse(paths[0].exists())


if __name__ == '__main__':
    unittest.main()
