import datetime
import os
from ntfs_data import (
    insert_registration,
    get_existing_cases,
    get_registration_id_by_name,
    get_case_details_by_id,
    get_pcap_files_for_case,
)
from ntfs_display import clear_screen, display_figlet_with_lolcat
from ntfs_capture import execute_tcpdump, import_pcap_file
from ntfs_analysis import analyze_pcap_file, handle_command

def register_case(connection):
    clear_screen()
    display_figlet_with_lolcat("Network Forensic Tool", "standard")
    display_figlet_with_lolcat("Register Case", "digital")

    while True:
        case_name = input("Enter the case name: ")

        existing_case_id = get_registration_id_by_name(connection, case_name)
        if existing_case_id:
            print("Case name already exists. Press Enter to continue...")
            input()
            return None

        organization = input("Enter the organization: ")
        investigator_name = input("Enter the investigator name: ")

        current_date = datetime.date.today()

        case_id = insert_registration(connection, case_name, organization, investigator_name, current_date)

        if case_id:
            print("Case registered successfully!")
            input("Press Enter to continue...")
            return case_id
        else:
            print("Failed to register the case.")
            input("Press Enter to continue...")
            return None

def choose_existing_case(connection):
    while True:
        clear_screen()
        display_figlet_with_lolcat("Network Forensic Tool", "standard")
        display_figlet_with_lolcat("Choose Existing Case", "digital")

        print("1. View all cases")
        print("2. Search case by name")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            case_id = display_cases(connection)
            if case_id:
                display_case_details(connection, case_id)
        elif choice == '2':
            case_id = search_case_by_name(connection)
            if case_id:
                display_case_details(connection, case_id)
        elif choice == '3':
            return None
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

def display_case_details(connection, case_id):
    clear_screen()
    display_figlet_with_lolcat("Network Forensic Tool", "standard")
    display_figlet_with_lolcat("Case Details", "digital")

    case_details = get_case_details_by_id(connection, case_id)
    if case_details:
        case_name, organization, InvestigatorsName, registration_date = case_details

        print(f"Case ID: {case_id}")
        print(f"Case Name: {case_name}")
        print(f"Organization: {organization}")
        print(f"Investigators Name: {InvestigatorsName}")
        print(f"Registration Date: {registration_date}\n")

        display_pcap_files(connection, case_name)

        while True:
            command = input("\nEnter command (or type 'back' to return to the main menu): ")
            if command.strip().lower() == 'back':
                break
            else:
                handle_command(command, connection, case_id)
    else:
        print("Case details not found.")
        input("\nPress Enter to continue...")

def display_pcap_files(connection, case_name):
    pcap_files = get_pcap_files_for_case(connection, case_name)

    if pcap_files:
        print("PCAP Files:")
        print(f"{'No.':<5}{'File Name':<50}{'Date':<15}{'Status':<15}")
        print("-" * 90)

        for i, (file_path, date, status) in enumerate(pcap_files, start=1):
            file_name = os.path.basename(file_path)  # Extracts just the file name
            print(f"{i:<5}{file_name:<50}{date:<15}{status:<15}")
    else:
        print("No PCAP files found for this case.")

def display_cases(connection):
    clear_screen()
    display_figlet_with_lolcat("Network Forensic Tool", "standard")
    display_figlet_with_lolcat("Choose Existing Case", "digital")

    existing_cases = get_existing_cases(connection)
    case_count = len(existing_cases)

    if case_count:
        print("Existing Cases:")
        print(f"{'No.':<5}{'Case Name':<30}{'Organization':<30}{'Investigator(s)':<30}{'Date':<15}")
        print("-" * 110)

        for i, case in enumerate(existing_cases, start=1):
            case_id, case_name, organization_name, investigators_name, date = case
            print(f"{i:<5}{case_name:<30}{organization_name:<30}{investigators_name:<30}{date:<15}")

        return select_case(existing_cases, case_count)
    else:
        print("No existing cases found.")
        input("Press Enter to continue...")
        return None



def select_case(existing_cases, case_count):
    while True:
        choice = input("Enter the number of the case you want to work on: ")
        try:
            choice = int(choice)
            if 1 <= choice <= case_count:
                case_id = existing_cases[choice - 1][0]
                print(f"You've chosen to work on case: {existing_cases[choice - 1][1]}")
                return case_id
            else:
                print(f"Invalid choice. Please enter a number between 1 and {case_count}.")
                input("Press Enter to continue...")
        except ValueError:
            print("Invalid choice. Please enter a number.")
            input("Press Enter to continue...")

def search_case_by_name(connection):
    clear_screen()
    display_figlet_with_lolcat("Network Forensic Tool", "standard")
    display_figlet_with_lolcat("Search Case By Name", "digital")

    case_name = input("Enter the case name to search: ")
    case_id = get_registration_id_by_name(connection, case_name)

    if case_id:
        display_case_details(connection, case_id)
        return case_id
    else:
        print("Case not found.")
        input("Press Enter to continue...")
        return None

def main():
    # Your database connection initialization here
    connection = None  # Replace with actual database connection

    while True:
        clear_screen()
        display_figlet_with_lolcat("Network Forensic Tool", "standard")
        display_figlet_with_lolcat("Main Menu", "digital")

        print("1. Register a new case")
        print("2. Choose an existing case")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            register_case(connection)
        elif choice == '2':
            choose_existing_case(connection)
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
