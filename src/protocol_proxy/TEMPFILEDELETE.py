import json
import time
import asyncio
import ipaddress
import subprocess
import platform
import concurrent.futures
import os
from threading import Lock

def main():
    print("Debug: Starting network and subnet discovery...")
    #this will be removed later for testing 
    # Create temp directory if it doesn't exist this will be removed later for testing 
    temp_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "temp")
    os.makedirs(temp_dir, exist_ok=True)
    print(f"📁 Using temp directory: {temp_dir}")

    # Run the network discovery with automatic address detection
    asyncio.run(run_network_discovery(temp_dir))
    

    #this will be removed later for testing 
    # After network discovery is complete, search through results for targets
    search_json_for_targets(temp_dir)


# check if need to add apple functionality? or just worry about linux
def get_system_route_info():
    """Get routing table information to discover connected networks.""" 
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception as e:
        print(f"Could not get routing info: {e}")
        return None


def parse_routing_table(route_output, local_ip):
    """Parse routing table to find actual network segments."""
    discovered_networks = []
    
    if not route_output:
        return discovered_networks
    
    try:
        for line in route_output.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Windows route parsing
            if platform.system().lower() == "windows":
                if "0.0.0.0" in line and "255.255.255.255" in line:
                    continue  # Skip default route
                parts = line.split()
                if len(parts) >= 4 and '.' in parts[0] and '.' in parts[1]:
                    try:
                        network_addr = parts[0]
                        netmask = parts[1]
                        
                        if network_addr != "0.0.0.0":
                            # Convert to CIDR
                            net = ipaddress.IPv4Network(f"{network_addr}/{netmask}", strict=False)
                            discovered_networks.append({
                                "subnet_cidr": str(net),
                                "source": "routing_table",
                                "description": "Network found in system routing table"
                            })
                    except:
                        continue
            else:
                # Linux route parsing
                if line.startswith('default'):
                    continue
                parts = line.split()
                if len(parts) >= 1 and '/' in parts[0]:
                    try:
                        net = ipaddress.IPv4Network(parts[0], strict=False)
                        discovered_networks.append({
                            "subnet_cidr": str(net),
                            "source": "routing_table", 
                            "description": "Network found in system routing table"
                        })
                    except:
                        continue
                        
    except Exception as e:
        print(f"Error parsing routing table: {e}")
    
    return discovered_networks


def ping_host(ip_address, timeout=1):
    """Ping a single IP address to test connectivity."""
    try:
        if platform.system().lower() == "windows":
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), str(ip_address)]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), str(ip_address)]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
        return result.returncode == 0
    except:
        return False


def test_network_connectivity(network_cidr, max_hosts=10):
    """Test connectivity to a network by pinging sample hosts."""
    try:
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        
        # For large networks, test only a sample of hosts
        hosts_to_test = []
        if network.num_addresses > max_hosts:
            # Test network address + 1, + 2, and a few random ones
            hosts_to_test = list(network.hosts())[:max_hosts]
        else:
            hosts_to_test = list(network.hosts())[:max_hosts]
        
        # Test connectivity with threading for speed
        reachable_hosts = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(ping_host, str(ip)): ip for ip in hosts_to_test}
            
            for future in concurrent.futures.as_completed(future_to_ip, timeout=15):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        reachable_hosts.append(str(ip))
                except:
                    continue
        
        return len(reachable_hosts) > 0, reachable_hosts
        
    except Exception as e:
        return False, []


async def discover_active_networks(local_ip):
    """Discover networks with actual connectivity testing."""
    discovered_networks = []
    lock = Lock()
    
    print("🔍 Performing real network discovery...")
    
    # Step 1: Get networks from routing table
    print("  📋 Analyzing system routing table...")
    route_info = get_system_route_info()
    routing_networks = parse_routing_table(route_info, local_ip)
    
    print(f"  📊 Found {len(routing_networks)} networks in routing table")
    for net in routing_networks:
        discovered_networks.append(net)
    
    # Step 2: Test common private ranges with connectivity probing
    print("  🌐 Testing common private network ranges...")
    common_ranges = [
        "192.168.1.0/24", "192.168.0.0/24", "192.168.2.0/24",
        "10.0.0.0/24", "10.1.0.0/24", "10.0.1.0/24",
        "172.16.0.0/24", "172.17.0.0/24", "172.18.0.0/24"
    ]
    
    # Test connectivity to ranges in parallel
    def test_range(range_cidr):
        is_reachable, hosts = test_network_connectivity(range_cidr, max_hosts=5)
        if is_reachable:
            with lock:
                network_info = {
                    "subnet_cidr": range_cidr,
                    "source": "connectivity_test",
                    "description": f"Network verified by connectivity test ({len(hosts)} hosts reachable)",
                    "reachable_hosts": hosts,
                    "contains_local_ip": ipaddress.IPv4Address(local_ip) in ipaddress.IPv4Network(range_cidr, strict=False)
                }
                discovered_networks.append(network_info)
                print(f"    ✅ {range_cidr} - {len(hosts)} hosts reachable")
        else:
            print(f"    ❌ {range_cidr} - no connectivity")
    
    # Test ranges concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(test_range, common_ranges)
    
    # Step 3: Discover networks based on local IP
    print("  🏠 Discovering networks from local IP configuration...")
    try:
        # Test different subnet sizes around local IP
        local_ip_obj = ipaddress.IPv4Address(local_ip)
        
        # Test /24, /22, /20 networks containing local IP
        for prefix_len in [24, 22, 20]:
            try:
                local_network = ipaddress.IPv4Network(f"{local_ip}/{prefix_len}", strict=False)
                
                # Test connectivity to this network
                is_reachable, hosts = test_network_connectivity(str(local_network), max_hosts=8)
                
                if is_reachable:
                    network_info = {
                        "subnet_cidr": str(local_network),
                        "source": "local_ip_analysis",
                        "description": f"Local network /{prefix_len} with {len(hosts)} reachable hosts",
                        "reachable_hosts": hosts,
                        "contains_local_ip": True,
                        "priority": "high"
                    }
                    
                    # Avoid duplicates
                    if not any(net["subnet_cidr"] == str(local_network) for net in discovered_networks):
                        discovered_networks.append(network_info)
                        print(f"    ✅ Local network: {local_network} - {len(hosts)} hosts")
                        
            except Exception as e:
                print(f"    ❌ Error testing /{prefix_len}: {e}")
                
    except Exception as e:
        print(f"  ❌ Error in local IP analysis: {e}")
    
    print(f"🎯 Network discovery complete: {len(discovered_networks)} active networks found")
    return discovered_networks


async def run_network_discovery(temp_dir=None):
    """Run REAL network and subnet discovery with connectivity testing."""
    if temp_dir is None:
        temp_dir = "."
    
    print("🚀 Starting REAL network discovery with connectivity testing...")
    
    # Step 1: Auto-detect local IP address
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))  # Connect to Google DNS
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    print(f"📍 Local IP detected: {local_ip}")
    
    # Step 2: Initialize network data structure
    network_data = {
        "local_ip": local_ip,
        "networks_found": [],
        "subnets_detected": [],
        "broadcast_addresses": []
    }
    
    # Step 3: Perform real network discovery with connectivity testing
    print("⏱️  Starting comprehensive network discovery (this may take 30-60 seconds)...")
    discovered_networks = await discover_active_networks(local_ip)
    
    # Step 4: Process discovered networks
    for network_info in discovered_networks:
        try:
            network = ipaddress.IPv4Network(network_info["subnet_cidr"], strict=False)
            
            # Add full network information
            full_network_info = {
                "network": str(network.network_address),
                "netmask": str(network.netmask),
                "broadcast": str(network.broadcast_address),
                "subnet_cidr": network_info["subnet_cidr"],
                "source": network_info["source"],
                "description": network_info["description"],
                "contains_local_ip": network_info.get("contains_local_ip", False),
                "priority": network_info.get("priority", "standard"),
                "reachable_hosts": network_info.get("reachable_hosts", [])
            }
            
            network_data["subnets_detected"].append(full_network_info)
            network_data["broadcast_addresses"].append(str(network.broadcast_address))
            
        except Exception as e:
            print(f"❌ Error processing network {network_info.get('subnet_cidr', 'unknown')}: {e}")
    
    print(f"✅ Discovery complete: {len(network_data['subnets_detected'])} active networks found")
    
    # Step 5: Save results
    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_summary": {
            "total_networks_found": len(network_data["networks_found"]),
            "total_subnets_detected": len(network_data["subnets_detected"]),
            "total_broadcast_addresses": len(network_data["broadcast_addresses"]),
            "local_ip_used": local_ip,
            "scanning_mode": "real_connectivity_discovery"
        },
        "network_information": network_data,
        "target_address_check": {}
    }
    
    # Save files to temp directory
    results_file = os.path.join(temp_dir, "network_discovery_results.json")
    networks_file = os.path.join(temp_dir, "found_networks_subnets.json")
    
    with open(results_file, "w") as f:
        json.dump(results, f, indent=4)
    
    with open(networks_file, "w") as f:
        json.dump({
            "timestamp": results["timestamp"],
            "local_ip": local_ip,
            "networks": network_data["networks_found"],
            "subnets": network_data["subnets_detected"],
            "broadcast_addresses": network_data["broadcast_addresses"],
            "target_networks": {},
            "summary": {
                "total_networks": len(network_data["networks_found"]),
                "total_subnets": len(network_data["subnets_detected"]),
                "total_broadcast_addresses": len(network_data["broadcast_addresses"]),
                "target_networks_found": 0,
                "scanning_mode": "real_connectivity_discovery"
            }
        }, f, indent=4)
    
    print("💾 Network discovery data saved for analysis")

#======================================================================================================================================================
# Target Network Search and Analysis Function for testing
def search_json_for_targets(temp_dir=None):
    """
    Comprehensive target network search and analysis function.
    Loads discovery results and provides detailed analysis with enhanced output.
    """
    if temp_dir is None:
        temp_dir = "."
        
    print("\n" + "="*60)
    print("🎯 POST-PROCESSING: Network Analysis & Target Search")
    print("="*60)
    
    # Load and validate discovery results
    networks_file = os.path.join(temp_dir, "found_networks_subnets.json")
    try:
        with open(networks_file, "r") as f:
            results = json.load(f)
        print("✅ Successfully loaded network discovery results")
    except FileNotFoundError:
        print(f"❌ Error: {networks_file} not found. Run network discovery first.")
        return
    except json.JSONDecodeError as e:
        print(f"❌ Error reading {networks_file}: {e}")
        return
    
    # Extract data from discovery results
    discovered_subnets = results.get("subnets", [])
    local_ip = results.get("local_ip", "unknown")
    
    # Display comprehensive discovery summary
    print(f"\n📊 COMPREHENSIVE NETWORK DISCOVERY SUMMARY:")
    print(f"  📍 Local IP detected: {local_ip}")
    print(f"  🌐 Total subnets discovered: {len(discovered_subnets)}")
    print(f"  📅 Scan timestamp: {results.get('timestamp', 'Unknown')}")
    
    # Categorize and display discovered networks by type
    local_networks = [s for s in discovered_subnets if s.get('contains_local_ip', False)]
    remote_networks = [s for s in discovered_subnets if not s.get('contains_local_ip', False)]
    
    print(f"\n🏠 LOCAL NETWORKS ({len(local_networks)}):")
    for i, subnet in enumerate(local_networks, 1):
        status = "⭐ CONTAINS LOCAL IP" if subnet.get('contains_local_ip') else ""
        print(f"  {i:2d}. {subnet['subnet_cidr']} (via {subnet['source']}) {status}")
        if 'description' in subnet:
            print(f"      📝 {subnet['description']}")
    
    print(f"\n🌐 REMOTE NETWORKS ({len(remote_networks)}):")
    for i, subnet in enumerate(remote_networks[:10], 1):  # Show first 10 remote networks
        print(f"  {i:2d}. {subnet['subnet_cidr']} (via {subnet['source']})")
        if 'description' in subnet:
            print(f"      📝 {subnet['description']}")
    
    if len(remote_networks) > 10:
        print(f"      ... and {len(remote_networks) - 10} more remote networks")
    
    # Target network definitions
    target_networks = {
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
    
    print(f"\n🔍 TARGET NETWORK SEARCH:")
    print(f"Searching for {len(target_networks)} specific target networks...")
    print("Target networks to find:")
    for cidr, info in target_networks.items():
        print(f"  🎯 {info['name']}: {cidr} (Target IP: {info['target_ip']})")
        print(f"     📄 {info['description']}")
    print()
    
    # Perform detailed target search analysis
    found_targets = []
    missing_targets = []
    
    for target_cidr, target_info in target_networks.items():
        print(f"🔎 Analyzing: {target_info['name']} ({target_cidr})")
        print(f"   🎯 Target IP: {target_info['target_ip']}")
        
        # Search for target network in discovered subnets
        found_in_subnets = []
        for subnet in discovered_subnets:
            # Direct CIDR match
            if subnet["subnet_cidr"] == target_cidr:
                found_in_subnets.append(subnet)
                print(f"   ✅ Direct match found: {subnet['subnet_cidr']}")
            
            # Check if target IP falls within any discovered subnet
            try:
                target_ip_obj = ipaddress.IPv4Address(target_info['target_ip'])
                subnet_network = ipaddress.IPv4Network(subnet["subnet_cidr"], strict=False)
                
                if target_ip_obj in subnet_network and subnet not in found_in_subnets:
                    found_in_subnets.append(subnet)
                    print(f"   ✅ IP range match: {subnet['subnet_cidr']} contains {target_info['target_ip']}")
            except (ipaddress.AddressValueError, ValueError):
                continue
        
        if found_in_subnets:
            print(f"   🎉 SUCCESS: Found in {len(found_in_subnets)} subnet(s)")
            for subnet in found_in_subnets:
                priority = "🔥 HIGH PRIORITY" if subnet.get('contains_local_ip') else "📍 REMOTE"
                print(f"     - {subnet['subnet_cidr']} ({subnet['source']}) {priority}")
            
            found_targets.append({
                "target": target_info['name'],
                "cidr": target_cidr,
                "target_ip": target_info['target_ip'],
                "found_in_subnets": found_in_subnets
            })
        else:
            print(f"   ❌ NOT FOUND: Target not detected in any discovered subnet")
            missing_targets.append({
                "target": target_info['name'],
                "cidr": target_cidr,
                "target_ip": target_info['target_ip']
            })
        print()  # Add spacing between targets
    
    # Generate comprehensive final summary report
    print("="*60)
    print("📋 FINAL ANALYSIS SUMMARY")
    print("="*60)
    
    success_rate = len(found_targets) / len(target_networks) * 100 if target_networks else 0
    
    print(f"📊 DISCOVERY STATISTICS:")
    print(f"   🌐 Total subnets discovered: {len(discovered_subnets)}")
    print(f"   🏠 Local networks found: {len(local_networks)}")
    print(f"   🌍 Remote networks found: {len(remote_networks)}")
    print(f"   🎯 Target networks searched: {len(target_networks)}")
    print(f"   ✅ Targets successfully found: {len(found_targets)}")
    print(f"   ❌ Targets missing: {len(missing_targets)}")
    print(f"   📈 Discovery success rate: {success_rate:.1f}%")
    print(f"   📍 Local machine IP: {local_ip}")
    
    if found_targets:
        print(f"\n🎉 SUCCESSFULLY DISCOVERED TARGETS ({len(found_targets)}):")
        for i, target in enumerate(found_targets, 1):
            print(f"  {i}. 📍 {target['target']} ({target['cidr']})")
            print(f"     🎯 Target IP: {target['target_ip']}")
            print(f"     🌐 Available via {len(target['found_in_subnets'])} network path(s):")
            for subnet in target['found_in_subnets']:
                local_indicator = " (⭐ LOCAL PATH)" if subnet.get('contains_local_ip') else ""
                print(f"       - {subnet['subnet_cidr']} (via {subnet['source']}){local_indicator}")
            print()
    
    if missing_targets:
        print(f"❌ MISSING TARGETS ({len(missing_targets)}):")
        for i, target in enumerate(missing_targets, 1):
            print(f"  {i}. 🔍 {target['target']} ({target['cidr']})")
            print(f"     🎯 Target IP: {target['target_ip']}")
            print(f"     ❌ Status: Not reachable via any discovered network path")
        
        print(f"\n💡 TROUBLESHOOTING SUGGESTIONS FOR MISSING TARGETS:")
        print(f"   🔧 Network Connectivity:")
        print(f"      - Missing targets may be on isolated network segments")
        print(f"      - Check if VPN or routing connections are required")
        print(f"      - Verify network bridges or gateway configurations")
        print(f"   🔍 Network Discovery:")
        print(f"      - Verify target network ranges are correctly specified")
        print(f"      - Consider expanding discovery scope to additional IP ranges")
        print(f"      - Check if target networks use non-standard subnet masks")
        print(f"   🛡️ Security Considerations:")
        print(f"      - Target networks may be behind firewalls or access controls")
        print(f"      - Verify network permissions and security policies")
    
    # Save detailed search results with enhanced metadata
    search_results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "analysis_summary": {
            "local_ip": local_ip,
            "total_subnets_discovered": len(discovered_subnets),
            "local_networks_count": len(local_networks),
            "remote_networks_count": len(remote_networks),
            "target_networks_searched": len(target_networks),
            "targets_found": len(found_targets),
            "targets_missing": len(missing_targets),
            "success_rate_percent": success_rate
        },
        "found_targets": found_targets,
        "missing_targets": missing_targets,
        "local_networks": local_networks,
        "discovery_metadata": {
            "scan_timestamp": results.get('timestamp', 'Unknown'),
            "total_discovered_subnets": len(discovered_subnets)
        }
    }
    
    try:
        results_file = os.path.join(temp_dir, "target_search_results.json")
        with open(results_file, "w") as f:
            json.dump(search_results, f, indent=4)
        print(f"\n💾 RESULTS SAVED:")
        print(f"   📄 Complete analysis: {results_file}")
        print(f"   📄 Network discovery data: {os.path.join(temp_dir, 'found_networks_subnets.json')}")
        print(f"   📄 Raw discovery results: {os.path.join(temp_dir, 'network_discovery_results.json')}")
    except Exception as e:
        print(f"❌ Error saving search results: {e}")
    
    print("="*60)
    print("🎯 Network Discovery and Target Analysis Complete!")
    print("="*60)



    

if __name__ == "__main__":
    main()
