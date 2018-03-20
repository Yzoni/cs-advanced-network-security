#!/usr/bin/env bash

sudo apt install git python3-pip

sudo pip3 install -r requirements.txt

#git clone git://git.netfilter.org/iptables && cd iptables
cd iptables
git checkout v1.6.2
./autogen.sh
./configure --prefix=/tmp/iptables
make
make install

cd ..
sudo PATH=$PATH IPTABLES_LIBDIR=/tmp/iptables/lib XTABLES_LIBDIR=/tmp/iptables/lib/xtables python3 iptables.py