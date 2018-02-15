#!/bin/bash

sudo apt install libpcap-dev libjson-c-dev cmake

cmake .
./code $1 $2