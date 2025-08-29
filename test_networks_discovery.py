import sys
import os

# Add 'src' directory to sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

# Import the BACnet network discovery function for testing
from protocol_proxy.protocol.bacnet.bacnet_proxy import tempNameGoaltoSendUserlistNetwork

def print_networks_summary(active_networks, label):
    print(f"\nSummary: {label} ({len(active_networks)}):")
    for net, info in active_networks.items():
        print(f"  {net}: {info}")

def run_network_discovery():
    print("Starting full network discovery (BACnet, routing table, ARP, common)...")
    active_networks = tempNameGoaltoSendUserlistNetwork()
    print_networks_summary(active_networks, "Active networks found (no suspected address)")

    suspected_address = "192.168.1.0/24"
    active_networks_with_address = tempNameGoaltoSendUserlistNetwork(suspected_address=suspected_address)
    print_networks_summary(active_networks_with_address, f"Active networks found (with suspected address {suspected_address})")

if __name__ == "__main__":
    run_network_discovery()
