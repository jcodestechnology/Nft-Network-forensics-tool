import sqlite3
from sqlite3 import Error
from datetime import datetime

def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None

def create_tables(connection):
    create_registration_table_sql = """CREATE TABLE IF NOT EXISTS registration (
                                        id INTEGER PRIMARY KEY,
                                        CaseName TEXT NOT NULL,
                                        OrganizationName TEXT NOT NULL,
                                        InvestigatorsName TEXT NOT NULL,
                                        Date DATE NOT NULL
                                    );"""
    create_pcap_file_table_sql = """CREATE TABLE IF NOT EXISTS pcap_file (
                                        id INTEGER PRIMARY KEY,
                                        CaseName TEXT NOT NULL,
                                        FilePath TEXT NOT NULL,
                                        Date DATE NOT NULL,
                                        Status TEXT NOT NULL DEFAULT 'collected',
                                        FOREIGN KEY (CaseName) REFERENCES registration(CaseName)
                                    );"""
    create_pcap_analysis_table_sql = """CREATE TABLE IF NOT EXISTS pcap_analysis (
                                            id INTEGER PRIMARY KEY,
                                            CaseName TEXT NOT NULL,
                                            org_name TEXT NOT NULL,
                                            pcap_file_name TEXT NOT NULL,
                                            total_packets INTEGER,
                                            top_ips TEXT,
                                            tcp_count INTEGER,
                                            udp_count INTEGER,
                                            http_count INTEGER,
                                            syn_count INTEGER,
                                            syn_ack_count INTEGER,
                                            ack_count INTEGER,
                                            syn_without_ack_count INTEGER,
                                            syn_ack_ratio REAL,
                                            syn_ack_message TEXT,
                                            proportionality_message TEXT,
                                            file_hash TEXT,
                                            analysis_date DATE NOT NULL,
                                            FOREIGN KEY (CaseName) REFERENCES registration(CaseName)
                                        );"""

    try:
        cursor = connection.cursor()
        cursor.execute(create_registration_table_sql)
        cursor.execute(create_pcap_file_table_sql)
        cursor.execute(create_pcap_analysis_table_sql)
        connection.commit()
        print("Tables created successfully.")
    except Error as e:
        print(e)

def insert_pcap_file(connection, case_name, file_path, status='collected'):
    sql_query = """INSERT INTO pcap_file (CaseName, FilePath, Date, Status) 
                   VALUES (?, ?, DATE('now'), ?)"""
    try:
        cursor = connection.cursor()
        cursor.execute(sql_query, (case_name, file_path, status))
        connection.commit()
        print("PCAP file inserted into the database successfully!")
    except Error as e:
        print("Error inserting PCAP file:", e)

# Function to insert analysis details into the pcap_analysis table
def insert_pcap_analysis(connection, case_name, org_name, pcap_filename, analysis_details, file_hash):
    insert_pcap_analysis_sql = """INSERT INTO pcap_analysis (CaseName, org_name, pcap_file_name, total_packets, top_ips,
                                    tcp_count, udp_count, http_count, syn_count, syn_ack_count, ack_count,
                                    syn_without_ack_count, syn_ack_ratio, syn_ack_message, proportionality_message,
                                    file_hash, analysis_date)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""
    try:
        cursor = connection.cursor()
        cursor.execute(insert_pcap_analysis_sql, (
            case_name,
            org_name,
            pcap_filename,
            analysis_details.get('total_packets'),
            str(analysis_details.get('top_ips')),  # Convert list to string for storage
            analysis_details.get('tcp_count'),
            analysis_details.get('udp_count'),
            analysis_details.get('http_count'),
            analysis_details.get('syn_count'),
            analysis_details.get('syn_ack_count'),
            analysis_details.get('ack_count'),
            analysis_details.get('syn_without_ack_count'),
            analysis_details.get('syn_ack_ratio'),
            analysis_details.get('syn_ack_feedback'),
            analysis_details.get('proportionality_message'),
            file_hash,
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Use datetime.now() to get current timestamp
        ))
        connection.commit()
    except sqlite3.Error as e:
        print(f"Error inserting into pcap_analysis table: {e}")


def get_existing_cases(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT id, CaseName, OrganizationName, Date FROM registration ORDER BY Date DESC")
    rows = cursor.fetchall()
    return rows

def get_registration_id_by_name(connection, case_name):
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM registration WHERE CaseName=?", (case_name,))
    row = cursor.fetchone()
    if row:
        return row[0]
    else:
        print("Case not found.")
        return None

def insert_registration(connection, case_name, organization, investigator_name, current_date):
    sql_query = """INSERT INTO registration (CaseName, OrganizationName, InvestigatorsName, Date) 
                   VALUES (?, ?, ?, ?)"""
    data = (case_name, organization, investigator_name, current_date)
    try:
        cursor = connection.cursor()
        cursor.execute(sql_query, data)
        connection.commit()
        print("Case registration successful!")
        return cursor.lastrowid
    except Error as e:
        print("Error inserting data:", e)
        return None

def get_case_details_by_id(connection, case_id):
    cursor = connection.cursor()
    cursor.execute("SELECT CaseName, OrganizationName, InvestigatorsName, Date FROM registration WHERE id=?", (case_id,))
    return cursor.fetchone()

def get_pcap_count_for_case(connection, case_name):
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) FROM pcap_file WHERE CaseName=?", (case_name,))
    return cursor.fetchone()[0]

def get_pcap_files_for_case(connection, case_name):
    cursor = connection.cursor()
    cursor.execute("SELECT FilePath, Date, Status FROM pcap_file WHERE CaseName=?", (case_name,))
    rows = cursor.fetchall()
    return rows

def get_pcap_analysis_for_case(connection, case_name):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM pcap_analysis WHERE CaseName=?", (case_name,))
    rows = cursor.fetchall()
    return rows

def get_existing_cases(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT id, CaseName, OrganizationName, InvestigatorsName, Date FROM registration ORDER BY Date DESC")
    rows = cursor.fetchall()
    return rows

# Ensure the connection and create tables
if __name__ == "__main__":
    connection = create_connection("ntfs.db")
    create_tables(connection)
