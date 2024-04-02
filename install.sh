#!/bin/bash

# Update apt-get
sudo apt-get update

# Install tcpdump
sudo apt-get install -y tcpdump

# Set permissions to allow non-root users to capture packets
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Install Zeek (formerly known as Bro)
sudo apt-get install -y zeek

# Install Rita
git clone https://github.com/activecm/rita.git
cd rita
sudo python3 setup.py install
cd ..

# Inform user about completion
echo "Installation complete!"
