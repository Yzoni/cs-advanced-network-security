#!/bin/bash

sudo apt -y install libpcap-dev python3-pip

sudo pip3 install -r requirements.txt

python3 ips.py $1 $2