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
------------------
## 1984detector.py
This script is an entropy tester designed to detect hidden malware in benign files. It combines Sample Entropy with Shingling to identify potential threats.

Current Development Stage - This script is a proof of concept and currently under development. It is computationally intensive due to the entropy testing method used. Optimisations will be considered after thorough testing of the algorithms.

Future Optimisation Plans - The script will be enhanced to calculate Sample Entropy more efficiently. Proposed improvements include implementing Fast Approximate Entropy calculation to reduce computational load, utilising GPU for accelerated processing, and optimising CPU usage through vectorised operations with NumPy and multi-threading that bypasses the Global Interpreter Lock with libraries like Numba.


# Understanding Sample Entropy

## What Is Sample Entropy?

- Sample Entropy (SampEn) is a statistical measure that quantifies the regularity or complexity within a time series or sequence.
- It assesses the likelihood that patterns of data that are similar for a certain length \( m \) remain similar at the next point \( m + 1 \).
- Mathematically, it's defined as:  
  `Sample Entropy = -ln(Number of matching sequences of length m+1 / Number of matching sequences of length m)`


### Parameters
- **m**: Length of the sequences to compare.
- **r**: Tolerance for accepting matches (typically a percentage of the standard deviation of the data).

### Application Without Shingling
- When applied directly to data (like the bytes of a file), Sample Entropy treats each data point as an individual element in the sequence.
- It evaluates the complexity based on the occurrence of patterns across the entire dataset without considering local context.

# Understanding Shingling

## What Is Shingling?
- Shingling involves breaking data into overlapping subsequences called shingles.
- Each shingle is a contiguous sequence of \( k \) elements from the original data.
- For example, with data \([a, b, c, d, e]\) and \( k = 3 \), the shingles are:
  - \([a, b, c]\)
  - \([b, c, d]\)
  - \([c, d, e]\)

### Purpose of Shingling
- **Captures Local Patterns**: By focusing on sequences of elements, shingling preserves the local structure and patterns within the data.
- **Reduces Dimensionality**: It condenses the data into meaningful units for analysis.

# Combining Sample Entropy with Shingling

## Process
1. **Create Shingles**:
   - Divide the data into overlapping shingles of length \( k \).
   - This transforms the original data into a new sequence of shingles.
2. **Apply Sample Entropy**:
   - Treat the sequence of shingles as the new dataset.
   - Calculate Sample Entropy on this sequence using chosen \( m \) and \( r \) values.

## Benefits Over Using Sample Entropy Alone

### Enhanced Local Pattern Detection
- **Local Context**: Shingling preserves the order and relationships between data points within each shingle.
- **Subtle Anomalies**: Anomalies that affect specific regions or sequences in the data are more likely to be detected.
  - *Example*: In file analysis, malicious code may alter certain sequences of bytes. Shingling helps in detecting these local changes.

### Improved Sensitivity to Structural Changes
- **Pattern Complexity**: By analysing sequences of elements, the method becomes sensitive to changes in the structural complexity of the data.
- **Sequence-Level Analysis**: Sample Entropy with Shingling can detect disruptions in the expected sequence patterns.

### Noise Reduction
- **Smoothing Effect**: Shingling can mitigate the impact of random noise by focusing on larger patterns rather than individual data points.
- **Consistent Patterns**: It emphasizes consistent patterns over isolated anomalies.

### Flexibility in Analysis
- **Adjustable Granularity**: The shingle size \( k \) can be adjusted to capture different levels of detail.
- **Customizable Parameters**: Allows for tuning \( k \), \( m \), and \( r \) to suit the specific characteristics of the data and the anomalies being targeted.

### Computational Efficiency
- **Reduced Complexity per Element**: Working with shingles can reduce the number of elements compared to the raw data, especially if \( k \) is large relative to the data size.
- **Parallel Processing Opportunities**: Shingled data can be more amenable to parallel processing techniques.

## Limitations of Using Sample Entropy Alone
- **Lack of Contextual Information**: Without shingling, Sample Entropy analyses individual data points or minimal sequences, potentially missing patterns that emerge over longer sequences.
- **Sensitivity to Data Length**: In raw data, short sequences may not capture the complexity needed for meaningful entropy calculations.
- **Ineffective for Complex Structures**: For data with inherent sequence structures (like text or code), Sample Entropy alone may not effectively capture important patterns.

# Practical Implications

## Anomaly Detection in Files
- **Sample Entropy Alone**:
  - May detect overall randomness or regularity but could miss localised anomalies.
  - Less effective at detecting inserted code or data that affects specific sequences.
- **Sample Entropy with Shingling**:
  - **Detects Localised Changes**: Better at identifying anomalies that affect specific sequences within the file.
  - **Identifies Structural Alterations**: More sensitive to changes in the order and structure of data points.

## Performance Considerations
- **Trade-off**:
  - *Sample Entropy Alone*: Simpler computation but potentially less informative.
  - *With Shingling*: More computationally intensive due to increased data complexity but provides richer information.








