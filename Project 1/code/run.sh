#!/bin/bash

sudo apt install libpcap-dev libjson-c-dev cmake

cmake . && make
./code $1 $2