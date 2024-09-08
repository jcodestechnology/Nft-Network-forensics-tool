import argparse
import os
import shutil
import subprocess

from ntfs_data import insert_pcap_file, get_case_details_by_id, get_pcap_count_for_case

def execute_tcpdump(command, connection, case_id):
    parser = argparse.ArgumentParser(description="Packet capture utility using tcpdump")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture", required=True)
    parser.add_argument("-i", "--interface", help="Interface to capture packets from")
    parser.add_argument("target", nargs="+", help="Target specification (e.g., src host 192.168.1.1)")
    args = parser.parse_args(command.split()[1:])
    
    capture_packets(args.count, case_id, args.interface, " ".join(args.target), connection)

def capture_packets(packet_count, case_id, interface=None, target=None, connection=None):
    output_folder = "outputs"
    
    # Retrieve case details
    case_details = get_case_details_by_id(connection, case_id)
    if not case_details:
        print("Invalid case ID.")
        return

    case_name, organization_name, _ = case_details

    # Get the pcap file count for naming
    pcap_count = get_pcap_count_for_case(connection, case_name) + 1
    output_filename = f"{organization_name}-{case_name}-{pcap_count}.pcap"
    output_file = os.path.join(output_folder, output_filename)

    # Setting timeout for 10 seconds
    timeout = 10

    command = ["tcpdump", "-c", str(packet_count), "-G", str(timeout), "-w", output_file]

    if interface:
        command.extend(["-i", interface])

    if target:
        command.extend([target])

    try:
        # Execute the command, capturing the output
        subprocess.check_output(command, stderr=subprocess.STDOUT)

        print(f"{packet_count} packets captured successfully and saved to {output_file}")

        # Insert the pcap file path into the database with reference to the case
        insert_pcap_file(connection, case_name, output_file, 'collected')
    except subprocess.CalledProcessError as e:
        print("Error capturing packets:", e)

def import_pcap_file(file_location, connection, case_id):
    output_folder = "outputs"
    filename = os.path.basename(file_location)
    
    # Validate file extension
    if not filename.lower().endswith('.pcap'):
        print("Error: Invalid file format. Only pcap files are allowed.")
        return

    # Retrieve case details
    case_details = get_case_details_by_id(connection, case_id)
    if not case_details:
        print("Invalid case ID.")
        return

    case_name, organization_name, _, _ = case_details

    # Get the pcap file count for naming
    pcap_count = get_pcap_count_for_case(connection, case_name) + 1
    output_filename = f"{organization_name}-{case_name}-{pcap_count}.pcap"
    output_file = os.path.join(output_folder, output_filename)

    try:
        # Copy the file to the outputs folder
        shutil.copy2(file_location, output_file)
        print(f"File '{filename}' imported successfully!")

        # Insert the pcap file path into the database with reference to the case
        insert_pcap_file(connection, case_name, output_file, 'imported')
    except FileNotFoundError:
        print(f"File '{filename}' not found!")
    except Exception as e:
        print("Error importing file:", e)
