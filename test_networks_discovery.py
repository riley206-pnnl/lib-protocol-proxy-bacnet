import sys
import os

# Add workspace root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import asyncio
import logging
from src.protocol_proxy.protocol.bacnet.bacnet_proxy import BACnetProxy

NETWORKS_TO_TEST = [
    ("10.71.129.147", "iot network"),
    ("130.20.0.0", "devices"),
    ("172.18.229.0", "staff"),
]

async def run_discovery():
    logging.basicConfig(level=logging.DEBUG)
    bacnet_network = 1
    vendor_id = 999
    object_name = 'Test BACnet Proxy'
    for address, label in NETWORKS_TO_TEST:
        print(f"\n--- Testing {label} ({address}) ---")
        proxy = BACnetProxy(address, bacnet_network=bacnet_network, vendor_id=vendor_id, object_name=object_name)
        await proxy.start()
        print(f"Discovering on {address}...")
        proxy.bacnet.discover(networks="known", limits=(0, 4194303), global_broadcast=True, reset=True)
        print(f"Discovery initiated for {label} ({address}).")
        await proxy.stop()

if __name__ == "__main__":
    try:
        asyncio.run(run_discovery())
    except KeyboardInterrupt:
        print('Test run interrupted.')
    except Exception as e:
        print(f'Error during test run: {e}')

if __name__ == "__main__":
    try:
        asyncio.run(run_discovery())
    except KeyboardInterrupt:
        print('Test run interrupted.')
    except Exception as e:
        print(f'Error during test run: {e}')
