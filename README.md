# Network Traffic Sniffer

## Objective

The script is a basic network packet sniffer designed to capture and display network traffic in real-time. It allows users to select an interface (Ethernet, WiFI, Bluetooth), then prints a summary of each packet captured on that interface. It ensures the script runs with administrator privileges, which is required for sniffing.

### Skills Learned

- Packet Sniffing with Scapy
- Windows WMI Querying
- Regex Pattern Matching
- Privilege Elevation
- Command-line Argument Parsing

### Tools Used

- Python Standard Library
- Scapy
- Windows Management Instrumentation

## Steps
1. Privilege Check
2. Interface Detection
3. Interface Selection
4. Packet Sniffing
