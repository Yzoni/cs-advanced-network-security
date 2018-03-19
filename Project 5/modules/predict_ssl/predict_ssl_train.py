import subprocess
from multiprocessing import Process
import argparse

apps = [
    'amazon.com'
    'www.nrc.nl',
    'stackoverflow.com',
    'news.ycombinator.com',
    'www.tudelft.nl'
]


def start_surfing():
    subprocess.call('randomSurfer.sh app', shell=True)


def start_capture(interface, app):
    subprocess.call('tcpdump tcp -i {} -s -w {}.pcap'.format(args.interface, args.app))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSL fingerprint trainer')
    parser.add_argument('interface', type=str,
                        help='Interface to capture on')
    args = parser.parse_args()

    for app in apps:
        p = Process(target=start_surfing)
        p.start()
