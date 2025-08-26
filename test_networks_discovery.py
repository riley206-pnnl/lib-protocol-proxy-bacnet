import sys
import os

# Add src to sys.path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from protocol_proxy.protocol.bacnet.bacnet_proxy import nmap_probe_common_router_points

def run_router_probe():
    print("Starting nmap probe of common router points in all private subnets...")
    nmap_probe_common_router_points()

if __name__ == "__main__":
    run_router_probe()
