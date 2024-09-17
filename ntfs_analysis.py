import subprocess
import os
import hashlib
from tabulate import tabulate
from ntfs_capture import execute_tcpdump, import_pcap_file
from ntfs_data import insert_pcap_analysis, get_case_details_by_id
# from pcap_analysis_utils import count_total_packets, top_traffic_ips, count_packets, calculate_syn_ack_ratio, calculate_proportionality_ratio

def handle_command(command, connection, case_id):
    if command.startswith("ntfs "):
        if command.startswith("ntfs -i "):
            file_location = command.split()[2]
            import_pcap_file(file_location, connection, case_id)
        elif command.startswith("ntfs -c "):
            execute_tcpdump(command, connection, case_id)
        elif command.startswith("ntfs -a "):
            filename = command.split()[2]
            analyze_pcap_file(filename, connection, case_id)
        elif command.startswith("ntfs -d "):
            filename = command.split()[2]
            display_pcap_file(filename)
        else:
            print("Invalid command. Commands must start with 'ntfs'.")
    else:
        print("Invalid command. Commands must start with 'ntfs'.")

def calculate_file_hash(file_path):
    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for file {file_path}: {e}")
        return None
    

def count_total_packets(pcap_file):
    try:
        command = ['tcpdump', '-r', pcap_file, '-n']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        count_process = subprocess.Popen(['wc', '-l'], stdin=process.stdout, stdout=subprocess.PIPE)
        output, _ = count_process.communicate()
        return int(output.decode('utf-8').strip())
    except Exception as e:
        print("An error occurred:", e)
        return None

def count_packets(pcap_file, protocol):
    try:
        if protocol == 'http':
            command = ['tcpdump', '-r', pcap_file, '-n', 'tcp', 'port', '80']
        else:
            command = ['tcpdump', '-r', pcap_file, '-n', protocol]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        count_process = subprocess.Popen(['wc', '-l'], stdin=process.stdout, stdout=subprocess.PIPE)
        output, _ = count_process.communicate()
        return int(output.decode('utf-8').strip())
    except Exception as e:
        print("An error occurred:", e)
        return None

def top_traffic_ips(pcap_file):
    try:
        command = ['tcpdump', '-r', pcap_file, '-n']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        awk_process = subprocess.Popen(['awk', '{print $3}'], stdin=process.stdout, stdout=subprocess.PIPE)
        sort_process = subprocess.Popen(['sort'], stdin=awk_process.stdout, stdout=subprocess.PIPE)
        uniq_process = subprocess.Popen(['uniq', '-c'], stdin=sort_process.stdout, stdout=subprocess.PIPE)
        sort_count_process = subprocess.Popen(['sort', '-nr'], stdin=uniq_process.stdout, stdout=subprocess.PIPE)
        top_five_process = subprocess.Popen(['head', '-n', '5'], stdin=sort_count_process.stdout, stdout=subprocess.PIPE)
        output, _ = top_five_process.communicate()
        
        top_ips = []
        for line in output.decode('utf-8').strip().split('\n'):
            count, ip = line.strip().split()
            top_ips.append((ip, int(count)))
        
        return top_ips
    except Exception as e:
        print("An error occurred:", e)
        return None

def calculate_syn_ack_ratio(syn_count, syn_ack_count):
    try:
        ratio = syn_count / syn_ack_count if syn_ack_count != 0 else 0
        red_color = "\033[91m"
        reset_color = "\033[0m"

        feedback = ""

        if ratio > 4:
            feedback = f"{red_color}SYN-ACK ratio above threshold. Possible SYN flood attack.{reset_color}"
        elif syn_count > 1000 and syn_ack_count == 0:
            feedback = f"{red_color}Possible SYN flood attack.{reset_color}"
        else:
            feedback = "SYN-ACK ratio within threshold."
        
        # Print the feedback message
        print(feedback)

        # Format ratio to display full value if it's not zero
        ratio_str = f"{ratio:.4f}" if ratio != 0 else "0"

        return ratio_str, feedback
    except ZeroDivisionError:
        return "0", ""



def calculate_proportionality_ratio(tcp_count, udp_count, http_count, syn_count, syn_ack_count, ack_count):
    value = http_count + syn_count + syn_ack_count + ack_count
    red_color = "\033[91m"
    reset_color = "\033[0m"

    proportion = ""

    if value < (tcp_count / 2):
        proportion = f"{red_color}Possible TCP flood attack.{reset_color}"
    elif value < (udp_count / 2):
        proportion = f"{red_color}Possible UDP flood attack.{reset_color}"
    else:
        proportion = "Packets within proportional rate"
    
    print(proportion) 

    return proportion


def display_pcap_file(pcap_filename):
    pcap_file_path = os.path.join('outputs', pcap_filename)

    if not os.path.isfile(pcap_file_path):
        print("File does not exist")
        return

    try:
        command = ['tcpdump', '-r', pcap_file_path, '-n']
        subprocess.run(command)
    except Exception as e:
        print("An error occurred during display:", e)



def analyze_pcap_file(pcap_filename, connection, case_id):
    pcap_file_path = os.path.join('outputs', pcap_filename)

    if not os.path.isfile(pcap_file_path):
        print("File does not exist")
        return

    try:
        command = ['tcpdump', '-r', pcap_file_path, '-n']
        subprocess.run(command)
        
        case_details = get_case_details_by_id(connection, case_id)
        if not case_details:
            print("Case details not found")
            return
        case_name, org_name, _, _ = case_details
        
        analysis_details = {}
        analysis_details['total_packets'] = count_total_packets(pcap_file_path)
        analysis_details['top_ips'] = top_traffic_ips(pcap_file_path)
        analysis_details['tcp_count'] = count_packets(pcap_file_path, 'tcp')
        analysis_details['udp_count'] = count_packets(pcap_file_path, 'udp')
        analysis_details['http_count'] = count_packets(pcap_file_path, 'http')
        analysis_details['syn_count'] = count_packets(pcap_file_path, 'tcp[13] & 2 != 0')
        analysis_details['syn_ack_count'] = count_packets(pcap_file_path, 'tcp[13] & 18 == 18')
        analysis_details['ack_count'] = count_packets(pcap_file_path, 'tcp[13] & 16 != 0')
        analysis_details['syn_without_ack_count'] = count_packets(pcap_file_path, 'tcp[13] & 18 == 2')
        
        # Calculate ratios
        syn_ack_ratio, syn_ack_feedback = calculate_syn_ack_ratio(analysis_details['syn_count'], analysis_details['syn_ack_count'])
        proportion = calculate_proportionality_ratio(
            analysis_details['tcp_count'],
            analysis_details['udp_count'],
            analysis_details['http_count'],
            analysis_details['syn_count'],
            analysis_details['syn_ack_count'],
            analysis_details['ack_count']
        )
        
        analysis_details['syn_ack_ratio'] = syn_ack_ratio
        analysis_details['syn_ack_feedback'] = syn_ack_feedback
        analysis_details['proportionality_message'] = proportion
        
        # Calculate file hash
        file_hash = calculate_file_hash(pcap_file_path)
        if not file_hash:
            print(f"Failed to calculate hash for file: {pcap_filename}")
            return
        
        # Insert analysis details into the database
        insert_pcap_analysis(connection, case_name, org_name, pcap_filename, analysis_details, file_hash)

        print("Analysis complete. Details stored in the database.")

        # Display analysis details in tabular form with specified headings
        print("\nAnalysis Details:")
        headers = ['Parameter', 'Value']
        data = [
            ['Total Packets', analysis_details['total_packets']],
            ['TCP Count', analysis_details['tcp_count']],
            ['UDP Count', analysis_details['udp_count']],
            ['HTTP Count', analysis_details['http_count']],
            ['SYN Count', analysis_details['syn_count']],
            ['SYN-ACK Count', analysis_details['syn_ack_count']],
            ['ACK Count', analysis_details['ack_count']],
            ['SYN without ACK Count', analysis_details['syn_without_ack_count']],
            ['SYN-ACK Ratio', f"{analysis_details['syn_ack_ratio']} - {analysis_details['syn_ack_feedback']}"],
            ['Proportionality Message', analysis_details['proportionality_message']]
        ] 

        # Print main analysis details using tabulate
        print(tabulate(data, headers=headers, tablefmt='grid'))

        # Display top IPs in a separate table
        print("\nTop IPs:")
        headers_top_ips = ['IP', 'Count']
        data_top_ips = [[ip, count] for ip, count in analysis_details['top_ips']]
        print(tabulate(data_top_ips, headers=headers_top_ips, tablefmt='grid'))

    except Exception as e:
        print("An error occurred during analysis:", e)
