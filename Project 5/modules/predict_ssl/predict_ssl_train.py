import subprocess
from multiprocessing import Process
import argparse
from pathlib2 import Path
import os


import pexpect

dir_path = Path(os.path.dirname(os.path.realpath(__file__)))

apps = [
    'www.nrc.nl',
    'docs.python.org',
    'stackoverflow.com',
    'news.ycombinator.com',
    'www.tudelft.nl'
]


def start_surfing(app):
    subprocess.call(str(dir_path / 'randomSurfer.sh ') + app, shell=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSL fingerprint trainer')
    parser.add_argument('interface', type=str,
                        help='Interface to capture on')
    args = parser.parse_args()

    for app in apps:

        p_capture = pexpect.spawn('tcpdump', ['tcp', 'port', str(443), '-i', str(args.interface), '-w', str(app + '.pcap')])

        subprocess.call(str(dir_path / 'randomSurfer.sh ') + app, shell=True)

        p_capture.sendcontrol('c')
        p_capture.close()
