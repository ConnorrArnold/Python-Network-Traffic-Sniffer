# Python Network Traffic Sniffer

## 📋 Overview

This script captures and displays live network packets on a user-selected interface (Ethernet, Wi-Fi, or Bluetooth). It enforces administrator privilege checks before execution and uses Windows WMI to detect available network interfaces dynamically.

---

## ✨ Features

- 🖥️ **Interface Selection** - Dynamically detects and lists available network adapters via Windows WMI
- 📦 **Live Packet Capture** - Captures and prints real-time packet summaries using Scapy
- 🔐 **Privilege Enforcement** - Verifies administrator rights before execution (required for raw socket access)
- 🔎 **Regex-Based Filtering** - Parses and matches interface names using pattern matching
- ⚙️ **CLI Argument Parsing** - Supports command-line flags for flexible usage

---

## 🛠️ Tools and Technologies

| Tool | Purpose |
|---|---|
| Python | Core scripting language |
| Scapy | Packet capture and analysis |
| WMI (Windows Management Instrumentation) | Network interface detection |
| argparse | Command-line argument parsing |
| re (Regex) | Interface name pattern matching |

---

## ⚙️ Requirements

- Windows OS
- Python 3.x
- Administrator privileges
- Required packages:

```bash
pip install scapy
pip install wmi
```

---

## 🚀 Usage

Run the script as Administrator:

```bash
python sniffer.py
```

You will be prompted to select a network interface:

```
Available Interfaces:
[0] Ethernet
[1] Wi-Fi
[2] Bluetooth Network Connection

Select interface: 1
[*] Sniffing on Wi-Fi...
Ether / IP / TCP 192.168.1.5:52301 > 142.250.80.46:443 S
Ether / IP / UDP 192.168.1.1:53 > 192.168.1.5:61234
Ether / IP / ICMP 192.168.1.5 > 8.8.8.8 echo-request
```

---

## 🧠 Skills Demonstrated

- Packet sniffing with Scapy on live interfaces
- Windows WMI querying for dynamic hardware/interface enumeration
- Privilege escalation checks for security-sensitive tooling
- Regex pattern matching for interface name parsing
- CLI tool design with argument parsing

---

## ⚠️ Disclaimer

This tool is intended for educational and authorized network monitoring purposes only. Only use it on networks you own or have explicit permission to monitor.
