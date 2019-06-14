import time
import json
import re
import socket

import sheclog.splunk_hec_logging

from datetime import datetime
from unittest.mock import call, ANY

from .testing_setup import SHECLogTestCase


class TestSHECLogger(SHECLogTestCase):

    def test_log_one_message_default_settings(self):
        """Test logger with all default settings except batch frequency, Splunk URL and host."""
        log = sheclog.logger('test', token='tokenfoo', host='https://host', url='a/b',
                             batch_frequency=1)

        # Test basic internals
        self.assertEqual(len(log.handlers), 1)
        hdlr = log.handlers[0]

        self.assertEqual(hdlr.log_buffer, [])
        self.assertEqual(hdlr.batch_frequency, 1)
        self.assertEqual(hdlr.extra_std_attr, [])
        self.assertIsNone(hdlr.last_buffer_check)
        self.assertEqual(hdlr.max_size, 4096)
        self.assertIs(hdlr.monitor_buffer_active, False)
        self.assertIs(hdlr.back_off, False)

        # log message to test
        expected_almost_timestamp = time.time()  # tested later
        log.info('message field value', extra={'extra_k': 'extra_v'})
        self.mock_request_post.assert_not_called()
        time.sleep(1.05)
        expected_call_args = call('http://host/a/b', headers={'Authorization': 'Splunk tokenfoo'},
                                  verify=False, data=ANY)
        self.mock_request_post.call_args.assert_called_with(expected_call_args)

        # extract log message sent
        log_msg = json.loads(self.mock_request_post.call_args[1]['data'])

        # Check fields of log message:

        # host
        this_host = socket.gethostname()
        self.assertEqual(log_msg['host'], this_host)

        # epoch timestamp
        fail_msg = 'Expected timestamp and real timestamp are not equal down to 3 decimal places'
        self.assertAlmostEqual(log_msg['time'], expected_almost_timestamp, places=3, msg=fail_msg)

        # execution ID
        exec_id_re = re.compile(r'^[a-zA-Z0-9_\-]{10}$')
        fail_msg = '{} does not comply with regex {}'.format(log_msg['event']['execution_id'],
                                                             exec_id_re.pattern)
        self.assertTrue(exec_id_re.search(log_msg['event']['execution_id']), msg=fail_msg)

        # timestamp format
        ts_re = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$')
        self.assertTrue(ts_re.search(log_msg['event']['timestamp']))

        # event timestamp value matches top level 'time' value
        ts_format = '%Y-%m-%dT%H:%M:%S.%f+00:00'
        ts_dt = datetime.timestamp(datetime.strptime(log_msg['event']['timestamp'], ts_format))
        self.assertEqual(ts_dt, log_msg['time'])

        # straight forward ones
        self.assertEqual(log_msg['event']['function'], 'test_log_one_message_default_settings')
        self.assertEqual(log_msg['event']['file'], 'test_sheclog.py')
        self.assertEqual(log_msg['event']['message'], 'message field value')
        self.assertEqual(log_msg['event']['extra_k'], 'extra_v')
        self.assertEqual(log_msg['event']['log_level'], 'INFO')
        self.assertIsInstance(log_msg['event']['line'], int)
