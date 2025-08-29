#!/usr/bin/env python3
"""
Test script for the integrated BACnet Proxy with Network Discovery
Demonstrates the network discovery functionality integrated into bacnet_proxy.py
"""

import asyncio
import json
import logging
import os
import sys

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def test_integrated_bacnet_proxy():
    """Test the integrated BACnet proxy with network discovery."""
    print("🚀 Testing Integrated BACnet Proxy with Network Discovery...")
    
    # Import the integrated BACnet proxy
    try:
        from protocol_proxy.protocol.bacnet.bacnet_proxy import BACnetProxy
        print("✅ Successfully imported integrated BACnetProxy")
    except ImportError as e:
        print(f"❌ Failed to import BACnetProxy: {e}")
        return
    
    # Set up temp directory
    temp_dir = os.path.join(os.path.dirname(__file__), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    
    # Create mock BACnet proxy instance (without actual BACnet connection)
    print("📡 Creating BACnet Proxy instance...")
    try:
        # Note: In a real scenario, you'd provide actual BACnet parameters
        # For testing, we'll create a minimal instance
        proxy = BACnetProxy(
            local_device_address="192.168.1.100:47808",
            temp_dir=temp_dir,
            bacnet_network=0,
            vendor_id=999,
            object_name="Test BACnet Proxy"
        )
        print("✅ BACnet Proxy instance created successfully")
    except Exception as e:
        print(f"❌ Failed to create BACnet Proxy: {e}")
        return
    
    # Test network discovery
    print("\n🔍 Testing network discovery functionality...")
    try:
        discovery_results = await proxy.run_network_discovery_internal()
        
        # Display results
        scan_summary = discovery_results.get("scan_summary", {})
        print(f"📊 NETWORK DISCOVERY RESULTS:")
        print(f"   🌐 Networks discovered: {scan_summary.get('total_subnets_detected', 0)}")
        print(f"   📍 Local IP: {scan_summary.get('local_ip_used', 'unknown')}")
        print(f"   📄 Results saved to: {temp_dir}/network_discovery_results.json")
        
    except Exception as e:
        print(f"❌ Network discovery failed: {e}")
        return
    
    # Test target search
    print("\n🎯 Testing target network search...")
    try:
        # Use custom target networks for testing
        custom_targets = {
            "10.71.129.0/24": {
                "name": "IoT Network",
                "target_ip": "10.71.129.147",
                "description": "IoT device network - searching for 10.71.129.147"
            },
            "130.20.0.0/24": {
                "name": "Device Network", 
                "target_ip": "130.20.0.0",
                "description": "General devices network - searching for 130.20.0.0"
            },
            "172.18.229.0/24": {
                "name": "Staff Network",
                "target_ip": "172.18.229.0", 
                "description": "Staff network - searching for 172.18.229.0"
            }
        }
        
        search_results = proxy.search_target_networks_internal(custom_targets)
        
        # Display results
        analysis_summary = search_results.get("analysis_summary", {})
        print(f"🎯 TARGET SEARCH RESULTS:")
        print(f"   📊 Target networks searched: {analysis_summary.get('target_networks_searched', 0)}")
        print(f"   ✅ Targets found: {analysis_summary.get('targets_found', 0)}")
        print(f"   ❌ Targets missing: {analysis_summary.get('targets_missing', 0)}")
        print(f"   📈 Success rate: {analysis_summary.get('success_rate_percent', 0):.1f}%")
        
        # Show found targets
        found_targets = search_results.get("found_targets", [])
        if found_targets:
            print(f"\n🎉 FOUND TARGET NETWORKS:")
            for i, target in enumerate(found_targets, 1):
                print(f"   {i}. {target['target']} ({target['cidr']}) - IP: {target['target_ip']}")
        
    except Exception as e:
        print(f"❌ Target search failed: {e}")
        return
    
    # Show file locations
    print(f"\n💾 RESULTS SAVED TO:")
    print(f"   📄 Network discovery: {temp_dir}/network_discovery_results.json")
    print(f"   📄 Network list: {temp_dir}/found_networks_subnets.json")
    print(f"   📄 Target search: {temp_dir}/target_search_results.json")
    
    print(f"\n✅ All integrated BACnet Proxy tests completed successfully!")


def main():
    """Main test function."""
    print("=" * 60)
    print("🧪 Integrated BACnet Proxy Network Discovery Test")
    print("=" * 60)
    
    try:
        asyncio.run(test_integrated_bacnet_proxy())
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
