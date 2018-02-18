#!/bin/bash

sudo apt -y install libpcap-dev python3-pip

sudo pip3 install pypcap

python3 pcap_dns.py $1 $2