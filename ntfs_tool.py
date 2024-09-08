import argparse
import subprocess
import os
from ntfs_data import create_connection, create_tables, get_existing_cases, get_case_details_by_id, get_pcap_files_for_case
from ntfs_display import clear_screen, display_figlet_with_lolcat
from ntfs_registration import register_case, choose_existing_case
from ntfs_analysis import analyze_pcap_file, display_pcap_file, handle_command
from ntfs_report import generate_pdf_report

def display_cases_table(cases):
    table_header = "| {:<5} | {:<20} | {:<20} | {:<20} | {:<15} |".format("No", "Case Name", "Organization", "Investigator Name", "Date created")
    print(table_header)
    print("-" * len(table_header))
    for i, case in enumerate(cases):
        if len(case) != 5:
            print(f"Error: Case at index {i} does not have 5 elements. Case data: {case}")
            continue  # Skip this case
        case_row = "| {:<5} | {:<20} | {:<20} | {:<20} | {:<15} |".format(case[0], case[1], case[2], case[3], case[4])
        print(case_row)

def main():
    while True:
        clear_screen()
        display_figlet_with_lolcat("Network Forensic Tool", "standard")
        display_figlet_with_lolcat("Main Menu", "digital")

        db_file = "ntfs.db"
        connection = create_connection(db_file)
        if connection is not None:
            create_tables(connection)

        print("\n1. Register Case")
        print("2. Work on Existing Case")
        print("3. Retrieve Reports")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            case_id = register_case(connection)
            if case_id:
                case_registered = True
            else:
                continue  
            
        elif choice == '2':
            case_id = choose_existing_case(connection)
            if case_id:
                case_registered = True
            else:
                continue

        elif choice == '3':
            existing_cases = get_existing_cases(connection)
            if existing_cases:
                print("\nExisting Cases:")
                display_cases_table(existing_cases)
                case_id = input("\nEnter the ID of the case to generate report: ")
                case_details = get_case_details_by_id(connection, case_id)
                pcap_files = get_pcap_files_for_case(connection, case_details[0])
                generate_pdf_report(case_details, pcap_files)
            else:
                print("No existing cases found.")
            input("Press Enter to continue...")
        elif choice == '4':
            print("Exiting...")
            if connection:
                connection.close()
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

        if case_id:
            while True:
                command = input("\nEnter command: ")
                if command.startswith("ntfs "):
                    handle_command(command, connection, case_id)
                else:
                    print("Invalid command. Commands must start with 'ntfs'.")

if __name__ == "__main__":
    main()
