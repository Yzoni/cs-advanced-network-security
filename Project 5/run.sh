#!/bin/bash

sudo apt -y install libpcap-dev python-pip git graphviz

sudo pip3 install -r requirements.txt

python3 ips.py $1 $2