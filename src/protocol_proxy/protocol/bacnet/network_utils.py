"""
network_utils.py
Utility functions for local network and Wi-Fi scanning.
These are not BACnet-specific and are used for general network visibility.
"""

import psutil
import ipaddress
import subprocess

def get_connected_networks():
    """
    Enumerate all IP subnets/networks the local machine is currently connected to.
    Returns a list of (interface, subnet) tuples.
    """
    networks = []
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if getattr(addr, 'family', None) == psutil.AF_INET or getattr(addr, 'family', None) == 2:
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask:
                    try:
                        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        networks.append((interface, str(net)))
                    except Exception:
                        pass
    return networks

def scan_wifi_windows():
    """
    Scan for all Wi-Fi networks in range (Windows only).
    Returns a list of dicts with 'ssid' and 'bssid'.
    """
    output = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"])
    networks = []
    lines = output.decode("utf-8", errors="ignore").splitlines()
    current_ssid = None
    for line in lines:
        line = line.strip()
        if line.startswith("SSID "):
            current_ssid = line.split(" : ")[-1]
        elif line.startswith("BSSID") and current_ssid:
            bssid = line.split(" : ")[-1]
            networks.append({"ssid": current_ssid, "bssid": bssid})
    return networks
