#!/bin/bash

sudo apt -y install libpcap-dev python3-pip git

git clone https://github.com/tintinweb/scapy-ssl_tls
cd scapy-ssl_tls && git checkout py3compat && sudo pip3 install .

sudo pip3 install -r requirements.txt

python3 ips.py $1 $2