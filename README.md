KDDNetFlow Extractor
A Python-based network traffic analyzer designed to extract and preprocess features for the KDD Cup 1999 dataset. This tool captures live network traffic, analyzes TCP/UDP/ICMP protocols, and generates structured connection records in CSV format, ready for machine learning or intrusion detection tasks.

## Features
- Live Packet Capture: Sniffs network traffic from a specified interface.

- Protocol Analysis: Extracts detailed features for TCP, UDP, and ICMP connections.

- Feature Extraction: Aggregates connection statistics (e.g., duration, bytes, flags) for KDD-compatible output.

- CSV Output: Generates structured datasets in CSV format for easy integration with ML pipelines.

- Service Mapping: Maps ports to services using the IANA database.

- Real-Time Visualization: Displays critical connection details in a color-coded console table.

## Use Cases
- Intrusion Detection: Prepare datasets for training ML models on network intrusion detection.

- Network Forensics: Analyze live traffic for suspicious patterns.

- Research: Extract features for academic or experimental purposes.

## Requirements
- Python 3.6+
- Wireshark/TSHARK (for packet capture)
- Linux/WinPcap (Windows) for raw socket access
  
## Installation
  - Clone the repository
  - cd KDDNetFlow-Extractor
  - Install dependencies
  - pip install -r requirements.txt
  - Install Wireshark/TSHARK:
  - Linux:   sudo apt-get install wireshark-tshark
  - Windows: Download and install Wireshark.
  
