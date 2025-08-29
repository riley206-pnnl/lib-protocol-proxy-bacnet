print("[run_bacnet_proxy] Starting script.")
import sys
import asyncio
import os


print("[run_bacnet_proxy] Setting up sys.path for src imports.")
repo_src_path = os.path.join(os.path.dirname(__file__), "src")
if repo_src_path not in sys.path:
    sys.path.insert(0, repo_src_path)

print("[run_bacnet_proxy] Importing BACnet class...")
from protocol_proxy.protocol.bacnet.bacnet_proxy import BACnet
print("[run_bacnet_proxy] BACnet import successful.")

async def main(local_device_address=None):

    print("[main] Entered main function.")
    if not local_device_address:
        print("[main] No local_device_address provided, attempting auto-detect...")
        try:
            import socket
            print("[main] Trying socket auto-detect...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_device_address = s.getsockname()[0]
            s.close()
            print(f"[main] Socket auto-detect success: {local_device_address}")
        except Exception:
            print("[main] Socket auto-detect failed, trying gethostbyname...")
            try:
                local_device_address = socket.gethostbyname(socket.gethostname())
                print(f"[main] gethostbyname success: {local_device_address}")
            except Exception:
                local_device_address = "127.0.0.1"
                print("[main] All auto-detect methods failed, using 127.0.0.1")
        print(f"Auto-detected local IP address: {local_device_address}")

    print(f"[main] Using local device address: {local_device_address}")
    print("[main] Creating BACnet instance...")
    bacnet = BACnet(local_device_address)
    print("[main] BACnet instance created.")

    # Call discover (async task)
    print("[main] Calling discover() with unicast_targets...")
    bacnet.discover(networks="known", limits=(0, 4194303), global_broadcast=False, reset=True, unicast_targets=["192.168.1.100"])
    print("[main] discover called. Waiting for async tasks to complete...")
    await asyncio.sleep(5)

    # Test collect_networks
    try:
        print("[main] Calling collect_networks('known')...")
        networks = await bacnet.collect_networks("known")
        print("[main] collect_networks returned.")
        print("Discovered networks:", networks)
    except Exception as e:
        print(f"[main] Error calling collect_networks: {e}")

    # Test what_is_network_number
    try:
        print("[main] Calling what_is_network_number()...")
        net_num = await bacnet.what_is_network_number()
        print(f"[main] what_is_network_number returned: {net_num}")
    except Exception as e:
        print(f"[main] Error calling what_is_network_number: {e}")

    # Test whois_router_to_network
    try:
        print("[main] Calling whois_router_to_network()...")
        routers = await bacnet.whois_router_to_network()
        print(f"[main] whois_router_to_network returned: {routers}")
    except Exception as e:
        print(f"[main] Error calling whois_router_to_network: {e}")

    # Test query_device
    try:
        print("[main] Calling query_device()...")
        device_info = await bacnet.query_device(local_device_address)
        print(f"[main] query_device returned: {device_info}")
    except Exception as e:
        print(f"[main] Error calling query_device: {e}")

    # Clean up
    print("[main] Cleaning up BACnet app...")
    if hasattr(bacnet, 'app') and bacnet.app:
        bacnet.app.close()
    print("[main] Done.")

if __name__ == "__main__":
    print("[run_bacnet_proxy] Running main()...")
    asyncio.run(main())