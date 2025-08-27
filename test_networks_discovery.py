import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from protocol_proxy.protocol.bacnet.bacnet_proxy import tempNameGoaltoSendUserlistNetwork

def run_network_discovery():
    print("Starting full network discovery (BACnet, routing table, ARP, common)...")
    active_networks = tempNameGoaltoSendUserlistNetwork()
    print("\nActive networks found:")
    print(active_networks)

if __name__ == "__main__":
    run_network_discovery()
