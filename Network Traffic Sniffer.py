import sys
import ctypes
import argparse
import re
import wmi
from scapy.all import sniff, get_if_list

def normalize_guid(guid):
    return guid.replace("{", "").replace("}", "").lower()

def get_npf_to_friendly_map():
    c = wmi.WMI()
    npf_map = {}
    for nic in c.Win32_NetworkAdapter():
        guid = getattr(nic, "GUID", None)
        name = getattr(nic, "NetConnectionID", None) or getattr(nic, "Name", None)
        if guid and name:
            npf_map[normalize_guid(guid)] = name
    return npf_map

def extract_guid_from_npf(iface):
    match = re.search(r"\{([A-F0-9\-]+)\}", iface, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None

def select_interface():
    interfaces = get_if_list()
    npf_map = get_npf_to_friendly_map()
    while True:
        print("Detected interfaces:")
        for idx, iface in enumerate(interfaces):
            guid = extract_guid_from_npf(iface)
            friendly = npf_map.get(guid, "Unknown")
            print(f"{idx + 1}. {iface}  [{friendly}]")
        try:
            sel_idx = int(input("Select interface number to sniff on: ").strip()) - 1
            if 0 <= sel_idx < len(interfaces):
                return interfaces[sel_idx]
            else:
                print("Invalid selection. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def packet_callback(packet):
    print(packet.summary())

def require_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    if not is_admin:
        print("This script requires administrator privileges")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def main():
    require_admin()
    parser = argparse.ArgumentParser(description="Simple Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Interface to sniff on")
    args = parser.parse_args()

    interface = args.interface if args.interface else select_interface()
    print(f"[*] Sniffing on {interface} (no filter)")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    main()