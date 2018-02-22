import logging
from logging.config import dictConfig

LOGGING = dict(
    version=1,
    formatters={
        'f': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
        }
    },
    handlers={
        'stdout': {
            'class': 'logging.StreamHandler',
            'formatter': 'f',
            'stream': 'ext://sys.stdout'
        }
    },
    loggers={
        '':
            {
                'handlers': ['stdout'],
                'level': 'DEBUG',
                'propagate': True
            }
    }
)
dictConfig(LOGGING)
log = logging.getLogger('IPS')