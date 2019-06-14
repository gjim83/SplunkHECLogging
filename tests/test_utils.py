import unittest
import json
import re

from datetime import datetime

from sheclog import utils


class UtilsTestCase(unittest.TestCase):

    def test_CustomEncoder_date_ok(self):
        timestamp = datetime(2018, 12, 1, 12, 34, 56, 78910)
        encoded_json = json.dumps({'ts': timestamp}, cls=utils.CustomEncoder)
        self.assertEqual(encoded_json, '{"ts": "2018-12-01T12:34:56.078910"}')

    def test_time_int(self):
        self.assertNotIsInstance(utils.time_int(), float)
        self.assertIsInstance(utils.time_int(), int)

    def test_get_execution_id(self):
        exec_id_re = re.compile(r'^[a-zA-Z0-9_\-]{10}$')
        exec_id = utils.get_execution_id()

        # Test that format is expected
        self.assertEqual(exec_id_re.search(exec_id).group(), exec_id)

        # Call 20 times and expect all returns to be different
        vals = set([utils.get_execution_id() for _ in range(20)])
        self.assertEqual(len(vals), 20, msg='There seem to be repeated values in {}'.format(vals))

    def test_check_record_parameters_ok(self):
        requested_params = set(['module', 'name', 'process', 'processName', 'relateiveCreated',
                                'thread', 'threadName'])
        self.assertIsNone(utils.check_record_parameters(requested_params))

    def test_check_record_parameters_error(self):
        requested_params = set(['module', 'name', 'process', 'processName', 'relateiveCreated',
                                'thread', 'threadName', 'foo', 'bar'])

        with self.assertRaises(ValueError) as e:
            utils.check_record_parameters(requested_params)

        # Use a regex and not direct string comparison because the attributes are added from
        # a set
        expected_error = (r'The following fields are not standard logging attributes: '
                          '(foo, bar|bar, foo)')
        err_regex = re.compile(expected_error)
        exc = e.exception
        self.assertTrue(err_regex.search(str(exc)))
