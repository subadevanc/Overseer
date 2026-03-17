"""
Run this to find the correct interface for pcap_bridge.py
"""
from scapy.arch.windows import get_windows_if_list

print("\nAll interfaces on this machine:\n")
for i, iface in enumerate(get_windows_if_list()):
    ips = iface.get("ips", [])
    print(f"[{i}] {iface['name']}")
    print(f"     Description: {iface.get('description','')}")
    print(f"     IPs: {ips}")
    print()
