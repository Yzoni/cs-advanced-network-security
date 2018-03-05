from modules.ieee80211.ieee80211_packet import RadioTapHeader, IEEE80211ManagementFrameType, \
    IEEE80211DataFrameType, IEEE80211FrameControl, IEEE80211DataFrame
from modules.ieee80211.ieee80211_database import IEEE80211Database

from ips_module import IPSModule
from ips_response import *


class IEEE80211Module(IPSModule):

    def __init__(self, iv_threshold=10) -> None:
        self.ieee80211_db = IEEE80211Database(iv_threshold)

        super().__init__()

    def receive_packet(self, pkt, pkt_c):
        radio_tap = RadioTapHeader.from_pkt(pkt)
        control_frame = IEEE80211FrameControl.from_pkt(pkt[radio_tap.length:])

        if isinstance(control_frame.subtype, IEEE80211DataFrameType) \
                and control_frame.subtype == IEEE80211DataFrameType.DATA \
                and not control_frame.retry_flag:

            data_frame = IEEE80211DataFrame.from_pkt(pkt[radio_tap.length:], control_frame)
            self.ieee80211_db.store_source_iv(data_frame.src, data_frame.wep_iv)

            if self.ieee80211_db.past_wep_replay_threshold(data_frame.src):
                return ErrorResponse('Probable WEP replay attack identified from {} [{}]'.format(data_frame.src, pkt_c),
                                     {
                                         'pkt': {
                                             'radio_tap': radio_tap.to_json(),
                                             'ieeee80211': data_frame.to_json()
                                         }
                                     })

        # Save transmitter address + last 50 packets IV
        # If more than 10 with the same IV then trigger ErrorResponse

        # if ieee80211.subtype == IEEE80211ManagementFrame.DEAUTHENTICATION \
        #         or ieee80211.subtype == IEEE80211ManagementFrame.DISASSOCIATION:
        #     return NoticeResponse('Parsed IEEE80211 DEAUTHENTICATION or DISASSOCIATION', {
        #         'pkt': {
        #             'radio_tap': radio_tap.to_json(),
        #             'ieeee80211': ieee80211.to_json()
        #         }
        #     })
