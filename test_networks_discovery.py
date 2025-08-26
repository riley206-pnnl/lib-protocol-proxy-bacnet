import sys
import os

# Add src to sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from protocol_proxy.protocol.bacnet.bacnet_proxy import nmap_probe_routed_networks

def run_router_probe():
    print("Starting nmap probe of routed networks from Windows routing table...")
    active_networks = nmap_probe_routed_networks()
    print("\nActive routed networks dictionary:")
    print(active_networks)

if __name__ == "__main__":
    run_router_probe()
