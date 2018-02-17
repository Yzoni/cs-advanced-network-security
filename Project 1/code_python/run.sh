#!/bin/bash

sudo apt install libpcap-dev python3-pip

sudo pip3 install pycap

python3 pcap_dns.py $1 $2