#!/usr/bin/env python3
"""
Script Name: port_authority.py
Version: 0.3
Date: 10/08/2024
Author: A.R.
Purpose: This script queries running processes and their network connections, including protocol details,
         and logs the results. It is designed for cybersecurity monitoring and identifying potentially
         malicious activity on the system.

Details: The script leverages osquery to fetch details about processes communicating over the network,
         providing insights that are crucial for cybersecurity investigations.

Setup: Ensure osquery is installed and accessible in the system's PATH. Run this script with Python3.
"""

import subprocess
import json
import logging
import os

# Set up logging
script_dir = os.path.dirname(os.path.abspath(__file__))
log_filename = os.path.join(script_dir, 'zero_noise.log')
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
    SELECT p.pid, p.name, p.cmdline, s.remote_address, s.remote_port, s.local_port, s.protocol
    FROM processes p
    JOIN process_open_sockets s ON p.pid = s.pid
    WHERE s.remote_address != '' AND s.remote_port != 0;
    """
    try:
        results = query_osquery(sql_query)
        for process in results:
            protocol = 'TCP' if process['protocol'] == '6' else 'UDP' if process['protocol'] == '17' else 'Other'
            log_message = f"PID: {process['pid']}, Name: {process['name']}, Cmd: {process['cmdline']}, Remote Address: {process['remote_address']}, Remote Port: {process['remote_port']}, Local Port: {process['local_port']}, Protocol: {protocol}"
            print(log_message)
            logging.info(log_message)
    except Exception as e:
        logging.error(f"Failed to run query: {str(e)}")

if __name__ == "__main__":
    list_processes_with_network_connections()
