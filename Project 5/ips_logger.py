"""
Global IPS logger
"""

import logging
import sys


def init_logger(file_location='log.json'):
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(filename=file_location)
    file_handler.setFormatter(formatter)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(message)s'))

    log = logging.getLogger('IPS')
    log.addHandler(file_handler)
    log.addHandler(stdout_handler)

    log.setLevel(logging.INFO)


def get_logger():
    return logging.getLogger('IPS')
