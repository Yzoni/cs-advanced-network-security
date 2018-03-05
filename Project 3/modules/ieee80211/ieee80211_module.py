from modules.ieee80211.ieee80211_packet import RadioTapHeader, IEEE80211Packet, IEEE80211ManagementFrame, \
    IEEE80211DataFrame
from modules.ieee80211.ieee80211_database import IEEE80211Database

from ips_module import IPSModule
from ips_response import *


class IEEE80211Module(IPSModule):

    def __init__(self, iv_threshold=10) -> None:
        self.ieee80211_db = IEEE80211Database(iv_threshold)

        super().__init__()

    def receive_packet(self, pkt):
        radio_tap = RadioTapHeader.from_pkt(pkt)
        ieee80211 = IEEE80211Packet.from_pkt(pkt[radio_tap.length:])

        if isinstance(ieee80211.subtype, IEEE80211DataFrame):

            self.ieee80211_db.store_source_iv(ieee80211.src, ieee80211.wep_iv)

            if self.ieee80211_db.past_wep_replay_threshold(ieee80211.src):
                return ErrorResponse('Probable WEP replay attack identified from {}'.format(ieee80211.src), {
                    'pkt': {
                        'radio_tap': radio_tap.to_json(),
                        'ieeee80211': ieee80211.to_json()
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
