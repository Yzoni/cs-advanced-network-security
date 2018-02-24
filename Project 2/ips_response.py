from ips_logger import log


class IPSResponse:
    def __init__(self, message, pkt_summary: dict) -> None:
        super().__init__()

        self.message = message
        self.pkt_summary = pkt_summary

        self._save()

    def _save(self):
        raise NotImplementedError

    def __str__(self) -> str:
        return self.__class__.__name__ + ' ' + self.message


class PermittedResponse(IPSResponse):
    def _save(self):
        log.info('PERMITTED Response: {} -> {}'.format(self.message, self.pkt_summary['pkt']))


class ErrorResponse(IPSResponse):
    def _save(self):
        log.info('ERROR Response: {} -> {}'.format(self.message, self.pkt_summary['pkt']))


class NoticeRespone(IPSResponse):
    def _save(self):
        log.info('NOTICE Response: {} -> {}'.format(self.message, self.pkt_summary['pkt']))
