from modules.ieee80211.ieee80211_packet import RadioTapHeader, IEEE80211ManagementFrameType, \
    IEEE80211DataFrameType, IEEE80211FrameControl, IEEE80211DataFrame, DSBits, IEEE80211ManagementFrameDisAuth
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

        if isinstance(control_frame.subtype, IEEE80211ManagementFrameType):
            if control_frame.subtype == (
                    IEEE80211ManagementFrameType.DEAUTHENTICATION or IEEE80211ManagementFrameType.DISASSOCIATION):
                management_frame = IEEE80211ManagementFrameDisAuth.from_pkt(pkt[radio_tap.length:], control_frame)

                return PermittedResponse(
                    'Deauthentication/Disassociation reason: {} [{}]'.format(management_frame.reason, pkt_c), {
                        'pkt': {
                            'radio_tap': radio_tap.__dict__,
                            'ieeee80211': management_frame.__dict__
                        }
                    })

        if isinstance(control_frame.subtype, IEEE80211DataFrameType):
            if control_frame.subtype == IEEE80211DataFrameType.DATA \
                    and not control_frame.retry_flag \
                    and control_frame.ds_flag == DSBits.TO_AP:

                data_frame = IEEE80211DataFrame.from_pkt(pkt[radio_tap.length:], control_frame)
                src = data_frame.address2

                self.ieee80211_db.store_source_iv(src, data_frame.wep_iv)

                if self.ieee80211_db.past_wep_replay_threshold(src):
                    self.ieee80211_db.clear_source_iv(src)
                    return ErrorResponse('Probable WEP replay attack identified from {} [{}]'.format(src, pkt_c),
                                         {
                                             'pkt': {
                                                 'radio_tap': radio_tap.__dict__,
                                                 'ieeee80211': data_frame.__dict__
                                             }
                                         })
