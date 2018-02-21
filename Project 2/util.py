import re


def is_valid_mac_address(mac) -> bool:
    return re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac)
