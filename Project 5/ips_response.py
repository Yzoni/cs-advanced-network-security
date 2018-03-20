"""
Standard IPS responses
"""

from ips_logger import get_logger
import inspect

log = get_logger()

class IPSResponse:
    def __init__(self, message, pkt_summary):


        frm = inspect.stack()[1]
        mod = inspect.getmodule(frm[0])

        self.module = mod.__name__
        self.message = message
        self.pkt_summary = pkt_summary

        self._save()

    def _save(self):
        raise NotImplementedError

    def __str__(self):
        return self.__class__.__name__ + ' ' + self.message


class PermittedResponse(IPSResponse):
    def _save(self):
        log.info('{} | PERMITTED | Response: {} | [{}]'.format(self.module, self.message, self.pkt_summary['pkt']))


class ErrorResponse(IPSResponse):
    def _save(self):
        log.info('{} | ERROR | Response: {} | [{}]'.format(self.module, self.message, self.pkt_summary['pkt']))


class NoticeResponse(IPSResponse):
    def _save(self):
        log.info('{} | NOTICE | Response: {} | [{}]'.format(self.module, self.message, self.pkt_summary['pkt']))
