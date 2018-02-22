import logging
import json_log_formatter
import sys

formatter = json_log_formatter.JSONFormatter()

json_handler = logging.FileHandler(filename='log.json')
json_handler.setFormatter(formatter)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))

log = logging.getLogger('IPS')
log.addHandler(json_handler)
log.addHandler(stdout_handler)

log.setLevel(logging.DEBUG)

