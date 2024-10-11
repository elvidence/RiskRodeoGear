#!/usr/bin/env python3
"""
Script Name: port_authority.py
Version: 0.3
Date: 10/08/2024
Author: A.R.
Purpose: This script queries running processes and their network connections continuously,
         including protocol details and parent process IDs, and logs the results for a specified duration. It is designed for
         real-time cybersecurity monitoring and identifying potentially malicious activity.

Details: The script leverages osquery to fetch details about processes communicating over the network,
         providing insights that are crucial for cybersecurity investigations. It runs with command-line arguments
         allowing the user to specify the monitoring duration in seconds ('s') or minutes ('m'). For example,
         to run the script for 10 minutes, use the command: 'sudo python port_authority.py -t 10m'. To run it for 30 seconds,
         use 'sudo python port_authority.py -t 30s'.

Setup: Ensure osquery is installed and accessible in the system's PATH. Run this script with Python 3.
"""

import subprocess
import json
import logging
import os
import argparse
import time

# Set up logging
script_dir = os.path.dirname(os.path.abspath(__file__))
log_filename = os.path.join(script_dir, 'port_authority.log')
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def query_osquery(sql):
    command = ['osqueryi', '--json', sql]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        error_message = f"Error running osquery: {stderr.decode()}"
        logging.error(error_message)
        raise Exception(error_message)
    return json.loads(stdout)

def list_processes_with_network_connections():
    sql_query = """
    SELECT p.pid, p.parent, p.name, p.cmdline, s.remote_address, s.remote_port, s.local_port, s.protocol
    FROM processes p
    JOIN process_open_sockets s ON p.pid = s.pid
    WHERE s.remote_address != '' AND s.remote_port != 0;
    """
    try:
        results = query_osquery(sql_query)
        for process in results:
            protocol = 'TCP' if process['protocol'] == '6' else 'UDP' if process['protocol'] == '17' else 'Unknown'
            log_message = f"PID: {process['pid']}, Parent PID: {process['parent']}, Name: {process['name']}, Cmd: {process['cmdline']}, Remote Address: {process['remote_address']}, Remote Port: {process['remote_port']}, Local Port: {process['local_port']}, Protocol: {protocol}"
            print(log_message)
            logging.info(log_message)
    except Exception as e:
        logging.error(f"Failed to run query: {str(e)}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Run the process network monitor for a specified duration.')
    parser.add_argument('-t', '--time', help='Duration for the script to run (e.g., 30s or 15m)', required=True)
    args = parser.parse_args()
    return args.time

def convert_time_to_seconds(time_str):
    if time_str.endswith('s'):
        return int(time_str[:-1])
    elif time_str.endswith('m'):
        return int(time_str[:-1]) * 60
    else:
        raise ValueError("Time must be in seconds ('s') or minutes ('m')")

if __name__ == "__main__":
    duration_str = parse_arguments()
    duration_seconds = convert_time_to_seconds(duration_str)
    start_time = time.time()
    while time.time() - start_time < duration_seconds:
        list_processes_with_network_connections()
        time.sleep(0.5)  # Delays for 0.5 seconds to limit CPU usage
    print("Completed monitoring.")
