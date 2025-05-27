#!/bin/bash

sudo apt update

sudo apt install -y python3-pip
pip3 install google-cloud-storage google-cloud-compute paramiko gdown
pip3 install tcconfig 



mkdir data
mkdir results
mkdir oram_data

# build diskann
mkdir src/diskann/build
cd src/diskann/build
cmake -DCMAKE_BUILD_TYPE=Release .. && make -Bj

# come back to root
cd ../../..
