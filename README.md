# RiskRodeoGear
Threat Hunting and IT Sec tools

## port_authority.py
This script queries running processes and their network connections, including ports and protocol details, and logs the results. It is designed for cybersecurity monitoring and identifying potentially malicious activity on the system. It leverages osquery to fetch details about processes communicating over the network,
providing insights that are crucial for cybersecurity investigations.

#### Setup:
- Install osquery on your system. You can download osquery from the official osquery downloads page 
  (https://osquery.io/downloads/). Choose the appropriate binary for your operating system and follow 
  the installation instructions provided on the site.

- Ensure that the osquery binary is in your system's PATH to allow the script to execute osquery commands:
  1. Open a terminal.
  2. Type 'osqueryi --version' to check if the terminal recognises osquery.
  3. If the command isn't recognised, you may need to add the osquery installation path to your system's PATH:
     Open your terminal configuration file (e.g., .bash_profile for macOS or .bashrc for Linux) and append:
     export PATH=$PATH:/path/to/osquery/bin
     Replace '/path/to/osquery/bin' with the actual path where osquery is installed.
     
- Administrative Privileges: Running this script may require administrative privileges, especially to access
  detailed process and network information:
  * On Linux or macOS, run the script with 'sudo python3 port_authority.py.
  * On Windows, run your command prompt as an Administrator and execute the script.

- This script utilises built-in subprocess to run osquery commands, hence no additional Python libraries are required for its execution. 
  Simply ensure you have Python 3 installed.

- Run the script with Python 3 by using the command 'python3 port_authority.py.
