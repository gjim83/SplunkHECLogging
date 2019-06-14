import unittest

from unittest.mock import patch
# from requests import RequestException


def mock_post(*args, **kwargs):
    class MockResponse:

        def raise_for_status(self):
            pass

    return MockResponse()


class SHECLogTestCase(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        cls.mock_requests_post_patcher = patch(target='sheclog.splunk_hec_logging.requests.post',
                                               side_effect=mock_post)
        cls.mock_request_post = cls.mock_requests_post_patcher.start()

        cls.maxDiff = None

    @classmethod
    def teardown_class(cls):
        cls.mock_requests_post_patcher.stop()
