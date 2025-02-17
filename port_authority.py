#!/usr/bin/env python3
"""
Script Name: port_authority.py
Version: 0.4
Date: 10/08/2024
Author: A.R.
Purpose: This script queries running processes and their network connections continuously,
         including protocol details and parent process IDs, and logs the results for a specified duration.
         It is designed for real-time cybersecurity monitoring and identifying potentially malicious activity.
         Duplicate entries are avoided by tracking previously seen connections in a Python set.
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
logging.basicConfig(filename=log_filename, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def query_osquery(sql):
    command = ['osqueryi', '--json', sql]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0 or stderr:
        error_message = f"Error running osquery: {stderr.decode().strip()}"
        logging.error(error_message)
        raise Exception(error_message)
    return json.loads(stdout)

def list_processes_with_network_connections(seen_connections):
    sql_query = """
    SELECT p.pid, p.parent, p.name, p.cmdline, s.remote_address, s.remote_port, s.local_port, s.protocol
    FROM processes p
    JOIN process_open_sockets s ON p.pid = s.pid
    WHERE s.remote_address != '' AND s.remote_port != 0;
    """
    try:
        results = query_osquery(sql_query)
        for process in results:
            try:
                protocol_value = int(process['protocol'])
            except (ValueError, TypeError):
                protocol_value = None
            if protocol_value == 6:
                protocol = 'TCP'
            elif protocol_value == 17:
                protocol = 'UDP'
            else:
                protocol = 'Unknown'
            # Create a unique key to represent the connection
            unique_key = (process['pid'], process['parent'], process['name'], process['cmdline'],
                          process['remote_address'], process['remote_port'], process['local_port'], protocol)
            if unique_key in seen_connections:
                continue
            seen_connections.add(unique_key)
            log_message = (f"PID: {process['pid']}, Parent PID: {process['parent']}, Name: {process['name']}, "
                           f"Cmd: {process['cmdline']}, Remote Address: {process['remote_address']}, "
                           f"Remote Port: {process['remote_port']}, Local Port: {process['local_port']}, Protocol: {protocol}")
            print(log_message, flush=True)
            logging.info(log_message)
    except Exception as e:
        logging.error(f"Failed to run query: {str(e)}")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Run the process network monitor for a specified duration.')
    parser.add_argument('-t', '--time', help="Duration for the script to run (e.g., '30s' or '15m')", required=True)
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
    seen_connections = set()  # Track previously reported connections
    try:
        while time.time() - start_time < duration_seconds:
            list_processes_with_network_connections(seen_connections)
            time.sleep(0.5)  # Delay to limit CPU usage
    except KeyboardInterrupt:
        print("Monitoring interrupted.", flush=True)
        logging.info("Monitoring interrupted by user.")
    print("Completed monitoring.", flush=True)
