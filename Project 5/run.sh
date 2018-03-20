#!/bin/bash

sudo apt -y install libpcap-dev python-pip git graphviz firefox

sudo pip3 install -r requirements.txt

wget https://github.com/mozilla/geckodriver/releases/download/v0.20.0/geckodriver-v0.20.0-linux64.tar.gz
tar -xvzf geckodriver-v0.20.0-linux64.tar.gz
chmod +x geckodriver
sudo mv geckodriver /usr/local/bin/

python3 ips.py $1 $2