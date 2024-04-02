#!/bin/bash

# Install tcpdump
sudo apt-get update
sudo apt-get install -y tcpdump

# Set permissions to allow non-root users to capture packets
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Inform user about completion
echo "Installation complete!"
