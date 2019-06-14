import json
import base64

from random import random
from hashlib import md5
from datetime import datetime
from time import time


class CustomEncoder(json.JSONEncoder):

    def default(self, o):
        try:
            encoded_obj = json.JSONEncoder.default(self, o)
        except TypeError:
            if isinstance(o, datetime):
                encoded_obj = o.isoformat()
            elif hasattr(o, '__repr__'):
                encoded_obj = repr(o)
            elif hasattr(o, '__str__'):
                encoded_obj = str(o)
            else:
                encoded_obj = '{} object could not be JSON encoded'.format(type(o))

        return encoded_obj


def time_int():
    """Returns ``time.time()`` without fractions of a second."""
    return int(time())


def get_execution_id():
    """
    Generates random 10-character hash to use as unique identifier for each script runtime
    execution. Matches regex ``^[a-zA-Z0-9_\\-]{10}$``.

    :returns execution_id: random hash
    :rtype: str
    """
    return base64.urlsafe_b64encode(
        md5(str(random()).encode('utf-8')).digest()
    )[:10].decode('utf-8')


def check_record_parameters(requested_params):
    """
    Checks if the user requested valid standard log record attributes to be added in logs. These
    parameters are additional to the standard ones already included in the custom log message
    structure found in the ``SplunkHTTPHandler.mapLogRecod`` method.

    It is based on the fact that the standard formatting of the fields matches the attribute
    names of the ``LogRecord`` class of the ``logging`` module.

    :param list requested_params: parameters that caller requested

    :raises ValueError: if a non-existent parameter was requested
    """
    params = set(['module', 'name', 'process', 'processName', 'relateiveCreated', 'thread',
                  'threadName'])

    requested_params = set(requested_params)
    if not requested_params.issubset(params):
        msg = ('The following fields are not standard logging '
               'attributes: {}'.format(', '.join(requested_params.difference(params))))
        raise ValueError(msg)
