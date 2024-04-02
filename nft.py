#!/usr/bin/env python3

import subprocess

def capture_packets(interface, output_file):
    command = ['tcpdump', '-i', interface, '-w', output_file]
    subprocess.run(command)

if __name__ == "__main__":
    interface = input("Enter the interface to capture packets (e.g., eth0): ")
    output_file = input("Enter the output file path to save captured packets (e.g., packets.pcap): ")
    capture_packets(interface, output_file)
