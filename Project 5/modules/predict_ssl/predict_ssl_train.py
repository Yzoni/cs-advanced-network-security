import subprocess
import argparse
from pathlib2 import Path
import os
from selenium import webdriver
from random import choice
import time

import pexpect
from selenium.common.exceptions import WebDriverException

dir_path = Path(os.path.dirname(os.path.realpath(__file__)))

apps = [
    'tweakers.net',
    'en.wikipedia.org',
    'about.gitlab.com',
    'docs.python.org',
    'edition.cnn.com',
]


def start_surfing(app):
    subprocess.call(str(dir_path / 'randomSurfer.sh ') + app, shell=True)


def click_link(driver, links, visited):
    l = choice(links)
    link_url = l.get_attribute('href')

    try:
        print('Visiting: {}'.format(link_url))
        l.click()
        visited.append(link_url)
    except WebDriverException:
        print('Could not click link: {}'.format(link_url))
        visited.append(link_url)
        click_link(driver, links, visited)

    return visited


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SSL fingerprint trainer')
    parser.add_argument('interface', type=str,
                        help='Interface to capture on')
    parser.add_argument('--traces-per-app', dest='ntraces', type=int, default=1,
                        help='Traces per app')
    parser.add_argument('--time-per-trace', dest='time', type=int, default=15,
                        help='Time per trace')
    args = parser.parse_args()

    driver = webdriver.Firefox()
    for app in apps:
        for trace in range(args.ntraces):

            p_capture = pexpect.spawn('tcpdump',
                                      ['tcp', 'port', str(443), '-i', str(args.interface), '-w',
                                       str('{}-{}.pcap').format(app, trace)])

            visited = list()

            app_url = 'https://' + app
            print('Visiting: {}'.format(app_url))
            driver.get(app_url)
            visited.append(app_url)

            start_time = time.time()
            while True:
                links = driver.find_elements_by_tag_name('a')
                links = list(filter(
                    lambda x: (str(x.get_attribute('href')).startswith(app_url) or
                               str(x.get_attribute('href')).startswith('/')) and
                              str(x.get_attribute('href')) not in visited and
                              '#' not in str(x.get_attribute('href')), links)
                )

                if len(links) < 1:
                    print('Zero links')
                    break

                visited += click_link(driver, links, visited)

                if time.time() - start_time > args.time:
                    break

            p_capture.sendcontrol('c')
            p_capture.close()

    driver.close()
