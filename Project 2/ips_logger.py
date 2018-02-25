"""
Global IPS logger
"""

import logging
import json_log_formatter
import sys


def init_logger(file_location='log.json'):
    formatter = json_log_formatter.JSONFormatter()

    json_handler = logging.FileHandler(filename=file_location)
    json_handler.setFormatter(formatter)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(message)s'))

    log = logging.getLogger('IPS')
    log.addHandler(json_handler)
    log.addHandler(stdout_handler)

    log.setLevel(logging.DEBUG)


def log():
    return logging.getLogger('IPS')
