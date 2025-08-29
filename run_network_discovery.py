import asyncio
from protocol_proxy.protocol.bacnet.bacnet_proxy import BACnetProxy

async def main():
    # TODO: Replace with your actual BACnet device address
    proxy = BACnetProxy(local_device_address="YOUR_DEVICE_ADDRESS")
    results = await proxy.run_network_discovery_internal()
    print(results)

if __name__ == "__main__":
    asyncio.run(main())
