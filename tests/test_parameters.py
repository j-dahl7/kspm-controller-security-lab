import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from prepare_run import validate_operator_cidr


class ParameterBoundaries(unittest.TestCase):
    def test_accepts_one_public_operator(self):
        self.assertEqual(validate_operator_cidr('8.8.8.8/32'), '8.8.8.8/32')

    def test_rejects_open_private_broad_or_invalid_ranges(self):
        for value in ['0.0.0.0/0', '8.8.8.0/24', '192.168.1.1/32', '127.0.0.1/32',
                      '::/0', '::1/128', '8.8.8.8/24', '', 'not-an-ip']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_operator_cidr(value)


if __name__ == '__main__':
    unittest.main()
