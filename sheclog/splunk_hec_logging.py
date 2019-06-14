"""
Module for logging messages to Splunk using the HEC (HTTP Event Collector), based on the `logging`
Python module.

Example:

    >>> import sheclog
    >>> log = sheclog.logger('<app name>', level='INFO')
    >>> log.info('<log message here>', extra={'other_key': '<extra key/val pair to log>'})

"""
import logging
import logging.handlers
import socket
import json
import requests
import atexit
import sys

from copy import copy
from time import sleep
from threading import Thread, RLock, Event
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from .utils import time_int, CustomEncoder, get_execution_id, check_record_parameters

# ------------------------------------ Module-wide settings --------------------------------------#

hostname = socket.gethostname()

# Disable certificate warnings for 'requests' library
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Minumum time in seconds to wait before attempting to send logs again if there was an issue.
MIN_BACK_OFF = 60

# ------------------------------------------------------------------------------------------------#


class SplunkHTTPHandler(logging.handlers.HTTPHandler):

    def __init__(self, host, url='',
                 method='POST', secure=False, credentials=None, context=None,
                 batch_frequency=1800, max_size=4096, extra_std_attr=[]):
        """
        Custom HTTP log handler that inherits from ``logging.handlers.HTTPHandler``.

        Given that the HTTP call to send a log adds latency to the script execution, this handler
        buffers logs for at least 'batch_frequency' seconds (defaults to 30 mins/1800 seconds).
        When the user logs a message, if 'batch_frequency' seconds have passed, the buffered
        logs will be sent to Splunk. Otherwise it gets added to the queue.

        If the execution is closed or there is a fatal exception, this handler will try to send
        any buffered messages. A user may also enclose their parent script in a try/finally clause,
        and add a call to ``<'SplunkHTTPHandler' object>.send_log_batch()`` to the 'finally' section.
        """
        super().__init__(host, url, method, secure, credentials, context)
        self.log_buffer = []
        self.buffer_size = sys.getsizeof(self.log_buffer)
        self.batch_frequency = batch_frequency
        self.extra_std_attr = extra_std_attr
        self.last_buffer_check = None
        self.max_size = max_size
        self.monitor_buffer_active = False
        self.back_off = False
        self.flush_flag = Event()
        atexit.register(self._flush_buffer_on_exit)  # always try to flush pending logs on exit

    def mapLogRecord(self, record):
        """
        Arranges the event in the format that Splunk HEC expects it (see
        http://dev.splunk.com/view/event-collector/SP-CAAAE6P).
        """
        rec = {
            'host': hostname,
            'time': record.created,
            'event': {
                'timestamp': datetime.fromtimestamp(record.created).isoformat() + '+00:00',
                'log_level': record.levelname,
                'file': record.filename,
                'line': record.lineno,
                'function': record.funcName,
                'message': record.msg
            }
        }

        if execution_id:
            rec['event']['execution_id'] = execution_id

        if record.exc_info:
            rec['event']['exception_info'] = record.exc_info

        for attr in self.extra_std_attr:
            rec['event'][attr] = getattr(record, attr)

        for key in record.extra_keys:
            rec['event'][key] = getattr(record, key)

        return json.dumps(rec, cls=CustomEncoder)

    def emit(self, record):
        """
        Instead of directly emitting the message, it appends it to the buffer. It also starts the
        buffer monitor when the first log comes in.
        """
        if self.last_buffer_check is None:
            self.last_buffer_check = time_int()
            self.monitor_buffer_active = True
            monitor_thread = Thread(target=self._monitor_buffer, name='Buffer-Monitor')
            monitor_thread.daemon = True
            monitor_thread.start()

            flush_thread = Thread(target=self.send_log_batch, name='Log-Dispatcher')
            flush_thread.daemon = True
            flush_thread.start()

        self._append_to_buffer(self.mapLogRecord(record))

    def _append_to_buffer(self, mapped_record):
        """
        Appends a mapped record to the buffer, and checks if the size is already over the maximum
        set by the caller. If it is, it calls the method to send the buffer to the Splunk HEC.
        """
        self.log_buffer.append(mapped_record)
        self.buffer_size += sys.getsizeof(self.log_buffer[-1])

        if not self.back_off and self.buffer_size > self.max_size:
            self.flush_flag.set()

    def send_log_batch(self):
        """
        Uses the ``requests`` library to post the buffered logs to the Splunk HEC.

        If the post fails, it manually generates a ``LogRecord`` object describing the issue and
        appends it to the buffer in the hopes of sending it at the next attempt. It also fabricates
        a new value of ``self.last_buffer_check`` to force a pause before trying again.
        """
        _buffer_copy = []
        lock = RLock()

        while True:
            self.flush_flag.wait()

            with lock:
                _buffer_copy = copy(self.log_buffer)
                self.log_buffer = []
                self.buffer_size = sys.getsizeof(self.log_buffer)
            try:
                payload = ''.join(_buffer_copy)
                uri = '/'.join([self.host, self.url])
                hdr = {'Authorization': 'Splunk ' + self.credentials}
                r = requests.post(uri, data=payload, headers=hdr, verify=False)
                r.raise_for_status()
            except (requests.RequestException, OSError) as exc:
                import os.path
                this_file_path = os.path.abspath(__file__)
                err_msg = 'an error occurred during batch upload of log messages'
                rv = logging.LogRecord('http_handler', 40, this_file_path, 0, err_msg, (), exc,
                                       func=sys._getframe().f_code.co_name)
                rv.__dict__['extra_keys'] = []

                self.back_off = True
                self._append_to_buffer(self.mapLogRecord(rv))
                self.log_buffer.extend(_buffer_copy)

                # This fabricated last buffer check will force the back off time
                self.last_buffer_check = time_int() + back_off_time - self.batch_frequency
            else:
                self.last_buffer_check = time_int()
            finally:
                _buffer_copy = []
                self.flush_flag.clear()

    def _flush_buffer_on_exit(self):
        """
        Calls ``self.send_log_batch`` to flush buffered logs. If there are still logs after calling
        that method, then it prints out the buffer as a last resort to have an error traceback.
        """
        if len(self.log_buffer) == 0:
            self.flush_flag = None
            return

        self.monitor_buffer_active = False

        # Wait up to 2 seconds in case the program exits while the logger is busy flushing the
        # buffer, otherwise setting the flag would be ignored by send_log_batch for pending logs
        for _ in range(200):
            if not self.flush_flag.is_set():
                break
            sleep(0.01)

        self.flush_flag.set()

        # give up to 2 seconds for the buffer to be flushed, otherwise the next 'if' will
        # execute immediately after setting the flag and cause a race condition
        # with send_log_batch, printing the logs before it's done posting them to Splunk
        for _ in range(200):
            if not self.flush_flag.is_set():
                break
            sleep(0.01)

        if len(self.log_buffer) > 0:
            errs_to_print = '\n\n'.join([
                json.dumps(json.loads(record), indent=4)
                for record in self.log_buffer
            ])
            print('[ERROR] The following records could not be sent to the Splunk HEC: host="{}", '
                  'url="{}"\n'.format(self.host, self.url), file=sys.stderr)
            print(errs_to_print, file=sys.stderr)
            # reset buffer in case _monitor_buffer checks the buffer immediately after this
            self.log_buffer = []
            self.buffer_size = sys.getsizeof(self.log_buffer)
            self.flush_flag = None

    def _monitor_buffer(self):
        """
        Checks the buffer approximately every ``batch_frequency`` seconds and flushes it if it
        contains logs in the queue.
        """
        while self.monitor_buffer_active:
            sec_since_last_check = time_int() - self.last_buffer_check
            frequency_met = sec_since_last_check >= self.batch_frequency
            if len(self.log_buffer) > 0 and frequency_met:
                self.back_off = False
                self.flush_flag.set()
            else:
                self.last_buffer_check = time_int()

            sleep_time = max(self.batch_frequency, self.batch_frequency - sec_since_last_check, 1)
            sleep(sleep_time)


class SplunkHTTPLogger(logging.Logger):

    def makeRecord(self, name, level, fn, lno, msg, args, exc_info, func=None, extra=None,
                   sinfo=None):
        """
        This custom method adds the ``'extra_keys'`` attribute to the record,
        so that the ``SplunkHTTPHandler.mapLogRecord`` method of the handler knows that it
        must add extra custom keys to the JSON object being logged.
        """
        rv = logging.LogRecord(name, level, fn, lno, msg, args, exc_info, func, sinfo)
        extra_keys = []

        if extra is not None:
            for key, value in extra.items():
                if (key in ["message", "asctime", "extra_keys"]) or (key in rv.__dict__):
                    raise KeyError("Attempt to overwrite %r in LogRecord" % key)
                extra_keys.append(key)
                rv.__dict__[key] = value

        rv.__dict__['extra_keys'] = extra_keys

        return rv


def logger(app='nsm', token='', batch_frequency=300, max_size=4096, add_execution_id=True,
           extra_std_attr=[], level='INFO', host='',
           url='',):
    """Quick wrapper to get the logger in just one call."""
    global back_off_time
    back_off_time = max(int(batch_frequency/2), MIN_BACK_OFF)

    global execution_id
    execution_id = get_execution_id() if add_execution_id else ''

    if extra_std_attr:
        check_record_parameters(extra_std_attr)

    log = SplunkHTTPLogger(app, level=level)
    setattr(log, 'execution_hash', execution_id)
    setattr(log, 'execution_id', execution_id)
    http_handler = SplunkHTTPHandler(credentials=token, batch_frequency=batch_frequency,
                                  max_size=max_size, extra_std_attr=extra_std_attr, host=host,
                                  url=url)
    log.addHandler(http_handler)

    return log
