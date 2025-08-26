import asyncio
# --- Placeholder for callback decorator ---
def callback(func):
    return func
import psutil
import ipaddress
import json
import logging
import sys
import time
import traceback
import typing as t
import logging

from argparse import ArgumentParser
from datetime import datetime
from math import floor
from typing import Optional, Type

from bacpypes3.pdu import Address, LocalBroadcast
from bacpypes3.app import Application
from bacpypes3.basetypes import DateTime, PropertyReference
from bacpypes3.constructeddata import AnyAtomic
from bacpypes3.lib.batchread import BatchRead, DeviceAddressObjectPropertyReference
from bacpypes3.pdu import Address, PDUData
from bacpypes3.apdu import (ConfirmedPrivateTransferACK, ConfirmedPrivateTransferError, ConfirmedPrivateTransferRequest,
                            ErrorRejectAbortNack, TimeSynchronizationRequest, AbortPDU, ErrorPDU, RejectPDU)
from bacpypes3.primitivedata import ClosingTag, Date, Null, ObjectIdentifier, ObjectType, OpeningTag, Tag, TagList, Time
from bacpypes3.vendor import get_vendor_info

## Removed missing import: protocol_proxy.ipc
from protocol_proxy.proxy import launch
from protocol_proxy.proxy.asyncio import AsyncioProtocolProxy

logging.basicConfig(filename='/tmp/bacnet_proxy.log', level=logging.DEBUG,
                    format='%(asctime)s - %(message)s')
_log = logging.getLogger(__name__)


class BACnetProxy(AsyncioProtocolProxy):
    def __init__(self, local_device_address, bacnet_network=0, vendor_id=999, object_name='VOLTTRON BACnet Proxy',
                 **kwargs):
        _log.debug('IN BACNETPROXY __init__')
        super(BACnetProxy, self).__init__(**kwargs)
        self.bacnet = BACnet(local_device_address, bacnet_network, vendor_id, object_name, **kwargs)
        self.loop = asyncio.get_event_loop()
        
        # Cache for object-list to avoid re-reading on every page request
        # Format: {device_key: (object_list, timestamp)}
        self._object_list_cache = {}
        self._cache_timeout = 300

        self.register_callback(self.confirmed_private_transfer_endpoint, 'CONFIRMED_PRIVATE_TRANSFER', provides_response=True)
        self.register_callback(self.query_device_endpoint, 'QUERY_DEVICE', provides_response=True)
        self.register_callback(self.read_property_endpoint, 'READ_PROPERTY', provides_response=True)
        self.register_callback(self.read_property_multiple_endpoint, 'READ_PROPERTY_MULTIPLE', provides_response=True)
        self.register_callback(self.time_synchronization_endpoint, 'TIME_SYNCHRONIZATION', provides_response=True)
        self.register_callback(self.send_object_user_lock_time_endpoint, 'SEND_OBJECT_USER_LOCK_TIME', provides_response=True)
        self.register_callback(self.write_property_endpoint, 'WRITE_PROPERTY', provides_response=True)
        self.register_callback(self.read_device_all_endpoint, 'READ_DEVICE_ALL', provides_response=True)
        self.register_callback(self.who_is_endpoint, 'WHO_IS', provides_response=True)
        self.register_callback(self.scan_subnet_endpoint, 'SCAN_SUBNET', provides_response=True, timeout=300)
        self.register_callback(self.read_object_list_names_endpoint, 'READ_OBJECT_LIST_NAMES', provides_response=True, timeout=300)
        self.register_callback(self.read_object_list_names_endpoint, 'READ_OBJECT_LIST', provides_response=True, timeout=300)
        self.register_callback(self.clear_cache_endpoint, 'CLEAR_CACHE', provides_response=True)
        self.register_callback(self.get_cache_stats_endpoint, 'GET_CACHE_STATS', provides_response=True)

    def _handle_bacnet_response(self, result):
        """Helper method to handle BACnet responses and convert errors to JSON-serializable format."""
        if isinstance(result, AbortPDU):
            return {
                "error": "AbortPDU",
                "reason": str(result.apduAbortRejectReason) if hasattr(result, 'apduAbortRejectReason') else "Unknown abort reason",
                "details": str(result)
            }
        elif isinstance(result, ErrorPDU):
            return {
                "error": "ErrorPDU", 
                "error_class": str(result.errorClass) if hasattr(result, 'errorClass') else "Unknown",
                "error_code": str(result.errorCode) if hasattr(result, 'errorCode') else "Unknown",
                "details": str(result)
            }
        elif isinstance(result, RejectPDU):
            return {
                "error": "RejectPDU",
                "reason": str(result.apduAbortRejectReason) if hasattr(result, 'apduAbortRejectReason') else "Unknown reject reason",
                "details": str(result)
            }
        elif isinstance(result, ErrorRejectAbortNack):
            return {
                "error": "ErrorRejectAbortNack",
                "details": str(result)
            }
        else:
            return result

    @callback
    async def confirmed_private_transfer_endpoint(self, _, raw_message: bytes):
        """Endpoint for confirmed private transfer."""
        message = json.loads(raw_message.decode('utf8'))
        address = Address(message['address'])
        vendor_id = message['vendor_id']
        service_number = message['service_number']
        # TODO: from_json may be an AI hallucination. Need to check this. chagne to fix error 
        service_parameters = TagList(message.get('service_parameters', []))
        result = await self.bacnet.confirmed_private_transfer(address, vendor_id, service_number, service_parameters)
        return json.dumps(result).encode('utf8')

    @callback
    async def query_device_endpoint(self, _, raw_message: bytes):
        """Endpoint for querying a device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['address']
        property_name = message.get('property_name', 'object-identifier')
        result = await self.bacnet.query_device(address, property_name)
        
        # Handle BACnet responses (including errors)
        handled_result = self._handle_bacnet_response(result)
        return json.dumps(handled_result).encode('utf8')

    @callback
    async def read_property_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading a property from a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        object_identifier = message['object_identifier']
        property_identifier = message['property_identifier']
        property_array_index = message.get('property_array_index', None)
        result = await self.bacnet.read_property(address, object_identifier, property_identifier, property_array_index)
        def make_jsonable(val):
            if isinstance(val, (list, tuple)):
                return [make_jsonable(v) for v in val]
            if isinstance(val, (bytes, bytearray)):
                return val.hex()
            if hasattr(val, 'as_tuple'):
                return str(val)
            if hasattr(val, '__dict__') and not isinstance(val, type):
                return {k: make_jsonable(v) for k, v in val.__dict__.items()}
            if hasattr(val, '__class__') and 'Error' in val.__class__.__name__:
                return str(val)
            import ipaddress
            if isinstance(val, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                return str(val)
            return val
        jsonable_result = make_jsonable(result)
        try:
            if isinstance(result, ErrorRejectAbortNack):
                error_response = {
                    "error": type(result).__name__,
                    "details": str(result)
                }
                return json.dumps(error_response).encode('utf8')
            return json.dumps(jsonable_result).encode('utf8')
        except TypeError as e:
            error_response = {
                "error": "SerializationError",
                "details": str(e),
                "raw_type": str(type(result)),
                "raw_str": str(result)
            }
            return json.dumps(error_response).encode('utf8')

    @callback
    async def read_property_multiple_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading multiple properties from a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        read_specifications = message['read_specifications']
        result = await self.bacnet.read_property_multiple(address, read_specifications)
        
        # Handle BACnet responses (including errors)
        handled_result = self._handle_bacnet_response(result)
        return json.dumps(handled_result).encode('utf8')

    @callback
    async def send_object_user_lock_time_endpoint(self, _, raw_message: bytes):
        """Endpoint for sending an object user lock time to a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = Address(message['address'])
        device_id = message['device_id']
        object_id = message['object_id']
        lock_interval = message['lock_interval']
        result = await self.bacnet.send_object_user_lock_time(address, device_id, object_id, lock_interval)
        return json.dumps(result).encode('utf8')

    @callback
    async def time_synchronization_endpoint(self, _, raw_message: bytes):
        """Endpoint for setting time on a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = Address(message['address'])
        date_time = datetime.fromisoformat(message['date_time']) if hasattr(message, 'date_time') else None
        result = await self.bacnet.send_object_user_lock_time(address, date_time)
        return json.dumps(result).encode('utf8')

    @callback
    async def write_property_endpoint(self, _, raw_message: bytes):
        """Endpoint for writing a property to a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        object_identifier = message['object_identifier']
        property_identifier = message['property_identifier']
        value = message['value']
        priority = message['priority']
        property_array_index = message.get('property_array_index', None)
        result = await self.bacnet.write_property(address, object_identifier, property_identifier, value, priority,
                                            property_array_index)
        return json.dumps(result).encode('utf8')

    @callback
    async def write_property_multiple_endpoint(self, _, raw_message: bytes):
        """Endpoint for writing multiple properties to a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        write_specifications = message['write_specifications']
        result = await self.bacnet.read_property(address, write_specifications)
        return json.dumps(result).encode('utf8')

    @callback
    async def read_device_all_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading all properties from a BACnet device."""
        try:
            message = json.loads(raw_message.decode('utf8'))
            device_address = message['device_address']
            device_object_identifier = message['device_object_identifier']
            result = await self.read_device_all(device_address, device_object_identifier)
            if not result:
                return json.dumps({"error": "No data returned from read_device_all"}).encode('utf8')
            def make_jsonable(val):
                if isinstance(val, (str, int, float, bool)):
                    return val
                if isinstance(val, (list, tuple, set)):
                    return [make_jsonable(v) for v in val]
                if isinstance(val, (bytes, bytearray)):
                    return val.hex()
                if hasattr(val, '__dict__') and not isinstance(val, type):
                    return {str(k): make_jsonable(v) for k, v in val.__dict__.items()}
                # TODO: Replace this forced string conversion with proper BACnet object serialization
                return f"FORCED:{str(val)}"
            jsonable_result = {str(k): make_jsonable(v) for k, v in result.items()}
            return json.dumps(jsonable_result).encode('utf8')
        except Exception as e:
            tb = traceback.format_exc()
            return json.dumps({"error": str(e), "traceback": tb}).encode('utf8')

    @callback
    async def who_is_endpoint(self, _, raw_message: bytes):
        """Endpoint for WHO-IS discovery."""
        message = json.loads(raw_message.decode('utf8'))
        device_instance_low = message.get('device_instance_low', 0)
        device_instance_high = message.get('device_instance_high', 4194303)
        dest = message.get('dest', '255.255.255.255:47808')
        apdu_timeout = message.get('apdu_timeout', None)  # Keep for backward compatibility but don't use
        result = await self.who_is(device_instance_low, device_instance_high, dest)
        return json.dumps(result).encode('utf8')

    @callback
    async def scan_subnet_endpoint(self, _, raw_message: bytes):
        """Endpoint for subnet scanning."""
        message = json.loads(raw_message.decode('utf8'))
        network_str = message['network']
        whois_timeout = message.get('whois_timeout', 3.0)
        result = await self.scan_subnet(network_str, whois_timeout)
        return json.dumps(result).encode('utf8')

    @callback
    async def read_object_list_names_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading object-list and object-names from a BACnet device with pagination."""
        try:
            message = json.loads(raw_message.decode('utf8'))
            device_address = message['device_address']
            device_object_identifier = message['device_object_identifier']
            page = message.get('page', 1)
            page_size = message.get('page_size', 100)
            
            logging.getLogger(__name__).info(f"read_object_list_names_endpoint called for device {device_address}, page {page}, page_size {page_size}")
            
            # Check if the BACnet application is still connected
            if not hasattr(self.bacnet, 'app') or self.bacnet.app is None:
                return json.dumps({"status": "error", "error": "BACnet application not available"}).encode('utf8')
            
            result = await self.read_object_list_names_paginated(device_address, device_object_identifier, page, page_size)
            
            logging.getLogger(__name__).info(f"read_object_list_names_paginated returned response with status: {result.get('status')}")
            
            # Check for error in the result
            if result.get('status') == 'error':
                logging.getLogger(__name__).error(f"Error in read_object_list_names_paginated: {result['error']}")
                return json.dumps(result).encode('utf8')
            
            def make_jsonable(val):
                if isinstance(val, (str, int, float, bool)):
                    # Special handling for integer units - convert to EngineeringUnits name
                    if isinstance(val, int):
                        # Check if this looks like a BACnet EngineeringUnits value
                        try:
                            from bacpypes3.basetypes import EngineeringUnits
                            # Try to convert the integer to an EngineeringUnits enum
                            engineering_unit = EngineeringUnits(val)
                            unit_str = str(engineering_unit)
                            # Handle BACnet EngineeringUnits string format
                            if unit_str.startswith('EngineeringUnits(') and unit_str.endswith(')'):
                                return unit_str[17:-1]  # Remove "EngineeringUnits(" and ")"
                            else:
                                return unit_str
                        except (ImportError, ValueError, TypeError):
                            # If conversion fails, return the original value
                            pass
                    return val
                if val is None:
                    return None
                if isinstance(val, (list, tuple, set)):
                    return [make_jsonable(v) for v in val]
                if isinstance(val, dict):
                    return {str(k): make_jsonable(v) for k, v in val.items()}
                if isinstance(val, (bytes, bytearray)):
                    return val.hex()
                # Handle BACnet EngineeringUnits and other enum-like objects
                if hasattr(val, '__class__') and 'EngineeringUnits' in str(val.__class__):
                    # This is a BACnet EngineeringUnits object
                    unit_str = str(val)
                    if unit_str.startswith('EngineeringUnits(') and unit_str.endswith(')'):
                        return unit_str[17:-1]  # Remove "EngineeringUnits(" and ")"
                    else:
                        return unit_str
                if hasattr(val, 'name') and hasattr(val, 'value'):
                    # This is likely a standard Python enum
                    return str(val.name)
                if hasattr(val, 'name') and not hasattr(val, 'value'):
                    # Handle other enum-like objects that only have name
                    return str(val.name)
                if hasattr(val, '__str__'):
                    val_str = str(val)
                    # Skip conversion to FORCED if it looks like an error object
                    if 'ErrorType' in val_str or 'Error' in type(val).__name__:
                        return None
                    # Check if it's a BACnet EngineeringUnits string representation
                    if 'EngineeringUnits:' in val_str or 'EngineeringUnits(' in val_str:
                        # Extract the unit name from various formats
                        import re
                        match = re.search(r'EngineeringUnits(?:\(|:)\s*([^>)]+)', val_str)
                        if match:
                            return match.group(1).strip()
                    return val_str
                return str(val)
            
            # Make the results jsonable
            if 'results' in result:
                jsonable_results = {}
                for obj_id, properties in result['results'].items():
                    if isinstance(properties, dict):
                        # Special handling for units property
                        processed_properties = {}
                        for prop_name, prop_value in properties.items():
                            if prop_name == 'units' and isinstance(prop_value, int):
                                # Convert numeric units to EngineeringUnits name
                                try:
                                    from bacpypes3.basetypes import EngineeringUnits
                                    engineering_unit = EngineeringUnits(prop_value)
                                    # Get the string representation and extract the unit name
                                    unit_str = str(engineering_unit)
                                    # BACnet EngineeringUnits string format is like "EngineeringUnits(amperes)"
                                    # or just the name directly, so we need to handle both cases
                                    if unit_str.startswith('EngineeringUnits(') and unit_str.endswith(')'):
                                        unit_name = unit_str[17:-1]  # Remove "EngineeringUnits(" and ")"
                                    else:
                                        unit_name = unit_str
                                    processed_properties[prop_name] = unit_name
                                    logging.getLogger(__name__).debug(f"Converted units {prop_value} to {unit_name} for {obj_id}")
                                except (ImportError, ValueError, TypeError) as e:
                                    logging.getLogger(__name__).warning(f"Failed to convert units {prop_value} for {obj_id}: {e}")
                                    processed_properties[prop_name] = make_jsonable(prop_value)
                            else:
                                processed_properties[prop_name] = make_jsonable(prop_value)
                        jsonable_results[str(obj_id)] = processed_properties
                    else:
                        jsonable_results[str(obj_id)] = make_jsonable(properties)
                result['results'] = jsonable_results
            
            logging.getLogger(__name__).info(f"Sending paginated response with {len(result.get('results', {}))} object names")
            
            return json.dumps(result).encode('utf8')
        except Exception as e:
            tb = traceback.format_exc()
            logging.getLogger(__name__).error(f"Exception in read_object_list_names_endpoint: {e}\n{tb}")
            return json.dumps({"status": "error", "error": str(e), "traceback": tb}).encode('utf8')

    @callback
    async def clear_cache_endpoint(self, _, raw_message: bytes):
        """Endpoint for clearing cache."""
        message = json.loads(raw_message.decode('utf8'))
        device_address = message.get('device_address', None)
        device_object_identifier = message.get('device_object_identifier', None)
        
        if device_address:
            self._clear_cache_for_device(device_address, device_object_identifier)
            result = {"status": "success", "message": f"Cache cleared for device {device_address}"}
        else:
            self._object_list_cache.clear()
            result = {"status": "success", "message": "All cache cleared"}
        
        return json.dumps(result).encode('utf8')

    @callback
    async def get_cache_stats_endpoint(self, _, raw_message: bytes):
        """Endpoint for getting cache statistics."""
        result = self._get_cache_stats()
        return json.dumps(result).encode('utf8')

    @classmethod
    def get_unique_remote_id(cls, unique_remote_id: tuple) -> tuple:
        """Get a unique identifier for the proxy server
         given a unique_remote_id and protocol-specific set of parameters."""
        return unique_remote_id[0:2]  # TODO: How can we know what the first two params really are?
                                      #  (Ideally they are address and port.)
                                      #  Consider named tuple?

    async def scan_subnet(self, network_str: str, whois_timeout: float = 3.0) -> list:
        start_time = time.time()
        max_scan_duration = 280  # 280 seconds to leave buffer for callback timeout
        _log.info(f"Starting IP range scan for network: {network_str} with Who-Is timeout: {whois_timeout}s, max scan duration: {max_scan_duration}s")
        try:
            net = ipaddress.IPv4Network(network_str, strict=False)
        except ValueError as e:
            _log.error(f"Invalid network string '{network_str}': {e}")
            return []
        
        # Check if the network is too large and warn
        num_hosts = net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses  # Subtract network and broadcast
        if num_hosts > 1000:
            _log.warning(f"Large network scan requested: {num_hosts} hosts. This may take a long time.")
            
        tasks = []
        semaphore = asyncio.Semaphore(20)

        async def scan_host(ip_obj):
            async with semaphore:
                try:
                    ip_str = str(ip_obj)
                    _log.debug(f"Scanning host {ip_str}")
                    # Use who_is to discover devices at this IP (note: removed apdu_timeout parameter)
                    discovered = await self.who_is(0, 4194303, f"{ip_str}:47808")
                    if discovered:
                        _log.debug(f"Found {len(discovered)} devices at {ip_str}")
                        return discovered
                except Exception as e:
                    _log.debug(f"Error scanning {ip_obj}: {e}")
                    return []

        for ip_address_obj in net.hosts():
            if time.time() - start_time > max_scan_duration:
                _log.warning(f"Scan time limit reached ({max_scan_duration}s), stopping early")
                break
            tasks.append(scan_host(ip_address_obj))

        _log.debug(f"Created {len(tasks)} scan_host tasks for network {network_str}.")
        gathered_results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed_time = time.time() - start_time
        _log.debug(f"Finished gathering {len(gathered_results)} scan_host results for network {network_str} in {elapsed_time:.2f} seconds.")
        
        discovered_devices_final = []
        scan_aborted = False
        
        for result_item in gathered_results:
            if isinstance(result_item, Exception):
                _log.debug(f"Exception in scan result: {result_item}")
                continue
            if isinstance(result_item, list):
                discovered_devices_final.extend(result_item)

        final_message = f"IP range scan for {network_str} {'partially completed (time limit reached)' if scan_aborted else 'complete'}. Total devices found: {len(discovered_devices_final)}. Scan time: {elapsed_time:.2f}s"
        _log.info(final_message)
        
        # Add scan metadata to help with debugging
        if scan_aborted:
            discovered_devices_final.append({"scan_status": "aborted", "reason": "time_limit_reached"})
        
        return discovered_devices_final

    async def read_device_all(self, device_address: str, device_object_identifier: str) -> dict:
        properties = [
            "object-identifier",
            "object-name",
            "object-type",
            "system-status",
            "vendor-name",
            "vendor-identifier",
            "model-name",
            "firmware-revision",
            "application-software-version",
            "location",
            "description",
            "protocol-version",
            "protocol-revision",
            "protocol-services-supported",
            "protocol-object-types-supported",
            "object-list",
            "structured-object-list",
            "max-apdu-length-accepted",
            "segmentation-supported",
            "max-segments-accepted",
            "vt-classes-supported",
            "active-vt-sessions",
            "local-time",
            "local-date",
            "utc-offset",
            "daylight-savings-status",
            "apdu-segment-timeout",
            "apdu-timeout",
            "number-of-apdu-retries",
            "time-synchronization-recipients",
            "max-master",
            "max-info-frames",
            "device-address-binding",
            "database-revision",
            "configuration-files",
            "last-restore-time",
            "backup-failure-timeout",
            "backup-preparation-time",
            "restore-preparation-time",
            "restore-completion-time",
            "backup-and-restore-state",
            "active-cov-subscriptions",
            "last-restart-reason",
            "time-of-device-restart",
            "restart-notification-recipients",
            "utc-time-synchronization-recipients",
            "time-synchronization-interval",
            "align-intervals",
            "interval-offset",
            "serial-number",
            "property-list",
            "status-flags",
            "event-state",
            "reliability",
            "event-detection-enable",
            "notification-class",
            "event-enable",
            "acked-transitions",
            "notify-type",
            "event-time-stamps",
            "event-message-texts",
            "event-message-texts-config",
            "reliability-evaluation-inhibit",
            "active-cov-multiple-subscriptions",
            "audit-notification-recipient",
            "audit-level",
            "auditable-operations",
            "device-uuid",
            "tags",
            "profile-location",
            "deployed-profile-location",
            "profile-name",
        ]
        device_obj = ObjectIdentifier(device_object_identifier)
        daopr_list = [
            DeviceAddressObjectPropertyReference(
                key=prop,
                device_address=device_address,
                object_identifier=device_obj,
                property_reference=PropertyReference(prop)
            ) for prop in properties
        ]
        results = {}
        def callback(key, value):
            logging.getLogger(__name__).debug(f"BatchRead callback: key={key}, value={value}")
            results[key] = value
        batch = BatchRead(daopr_list)
        try:
            await asyncio.wait_for(batch.run(self.bacnet.app, callback=callback), timeout=30)
        except asyncio.TimeoutError:
            logging.getLogger(__name__).error("BatchRead timed out after 30 seconds!")
            results['error'] = 'Timeout waiting for BACnet device response.'
        except Exception as e:
            logging.getLogger(__name__).exception(f"Exception in BatchRead: {e}")
            results['error'] = str(e)
        return results

    async def _get_cached_object_list(self, device_address: str, device_object_identifier: str):
        """
        Get object-list from cache if available and not expired, otherwise read from device.
        Returns the object-list or None if there was an error.
        """
        cache_key = f"{device_address}:{device_object_identifier}"
        current_time = time.time()
        
        # Check cache first
        if cache_key in self._object_list_cache:
            object_list, timestamp = self._object_list_cache[cache_key]
            if current_time - timestamp < self._cache_timeout:
                _log.debug(f"Using cached object-list for {cache_key}")
                return object_list
        
        # Cache miss or expired - read from device
        try:
            _log.debug(f"Reading object-list from device {device_address}")
            object_list = await self.bacnet.read_property(device_address, device_object_identifier, "object-list")
            if object_list:
                self._object_list_cache[cache_key] = (object_list, current_time)
                _log.debug(f"Cached object-list for {cache_key} with {len(object_list)} objects")
                return object_list
        except Exception as e:
            _log.error(f"Error reading object-list from {device_address}: {e}")
            return None

    def _clear_cache_for_device(self, device_address: str, device_object_identifier: str = None):
        """Clear cache for a specific device or all devices."""
        if device_object_identifier:
            cache_key = f"{device_address}:{device_object_identifier}"
            if cache_key in self._object_list_cache:
                del self._object_list_cache[cache_key]
                _log.debug(f"Cleared cache for {cache_key}")
        else:
            # Clear all entries for this device address
            keys_to_remove = [key for key in self._object_list_cache.keys() if key.startswith(f"{device_address}:")]
            for key in keys_to_remove:
                del self._object_list_cache[key]
            _log.debug(f"Cleared cache for all objects at {device_address}")

    def _get_cache_stats(self):
        """Get cache statistics for debugging."""
        current_time = time.time()
        stats = {
            "total_entries": len(self._object_list_cache),
            "entries": []
        }
        
        for cache_key, (object_list, timestamp) in self._object_list_cache.items():
            age = current_time - timestamp
            stats["entries"].append({
                "device": cache_key,
                "object_count": len(object_list) if object_list else 0,
                "age_seconds": age,
                "expired": age > self._cache_timeout
            })
        
        return stats

    async def read_object_list_names_paginated(self, device_address: str, device_object_identifier: str, page: int = 1, page_size: int = 100) -> dict:
        """
        Reads the object-list from a device (with caching), then reads object-name, units, and present-value for a specific page of objects.
        Returns a paginated response with results and pagination metadata.
        
        The results dict will contain object identifiers as keys, with each value being a dict containing:
        - 'object-name': The name of the object
        - 'units': The units property of the object (if available)
        - 'present-value': The current value of the object (if available)
        """
        _log.info(f"Starting read_object_list_names_paginated for device {device_address}, page {page}, page_size {page_size}")
        
        # Validate pagination parameters
        if page < 1:
            return {"error": "Page number must be >= 1"}
        if page_size < 1 or page_size > 1000:
            return {"error": "Page size must be between 1 and 1000"}
        
        # Step 1: Get object-list from cache or read from device
        object_list = await self._get_cached_object_list(device_address, device_object_identifier)
        
        if object_list is None:
            return {"error": "Failed to read object-list from device"}
        
        total_objects = len(object_list)
        total_pages = (total_objects + page_size - 1) // page_size
        
        _log.info(f"Object-list has {total_objects} objects, {total_pages} total pages")
        
        # Calculate pagination bounds
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        # Get the page of objects
        page_objects = object_list[start_idx:end_idx]
        
        if not page_objects:
            return {"error": "No objects found for this page"}
        
        # Step 2: Prepare batch read for object-name, units, and present-value of each object
        daopr_list = []
        
        for objid in page_objects:
            # Read object-name
            daopr_list.append(DeviceAddressObjectPropertyReference(
                key=f"{objid}:object-name",
                device_address=device_address,
                object_identifier=objid,
                property_reference=PropertyReference("object-name")
            ))
            # Read units (if applicable)
            daopr_list.append(DeviceAddressObjectPropertyReference(
                key=f"{objid}:units",
                device_address=device_address,
                object_identifier=objid,
                property_reference=PropertyReference("units")
            ))
            # Read present-value (if applicable)
            daopr_list.append(DeviceAddressObjectPropertyReference(
                key=f"{objid}:present-value",
                device_address=device_address,
                object_identifier=objid,
                property_reference=PropertyReference("present-value")
            ))
        
        _log.info(f"Prepared batch read for {len(daopr_list)} objects on page {page}")
        
        # Step 3: Execute batch read
        raw_results = {}
        def callback(key, value):
            logging.getLogger(__name__).debug(f"BatchRead callback: key={key}, value={value}")
            raw_results[key] = value
        
        batch = BatchRead(daopr_list)
        try:
            await asyncio.wait_for(batch.run(self.bacnet.app, callback=callback), timeout=90)
            logging.getLogger(__name__).info(f"BatchRead completed successfully with {len(raw_results)} raw results for page {page}")
            
            # Check if we have any results after the batch read
            if not raw_results:
                logging.getLogger(__name__).warning("BatchRead completed but no results were received")
                return {"status": "error", "error": "No results received from BACnet device"}
            
            # Process raw results to organize by object identifier
            results = {}
            for key, value in raw_results.items():
                if ':' in key:
                    obj_id, property_name = key.rsplit(':', 1)
                    if obj_id not in results:
                        results[obj_id] = {}
                    results[obj_id][property_name] = value
                else:
                    # Fallback for any keys without property suffix
                    results[key] = value
            
        except asyncio.TimeoutError:
            logging.getLogger(__name__).error(f"BatchRead timed out after 90 seconds for page {page}!")
            return {"status": "error", "error": "Timeout waiting for BACnet device response after 90 seconds"}
        except Exception as e:
            logging.getLogger(__name__).exception(f"Exception in BatchRead for page {page}: {e}")
            return {"status": "error", "error": f"BatchRead failed: {str(e)}"}
        
        # Return paginated response
        return {
            "status": "done",
            "results": results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_objects,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_previous": page > 1
            }
        }

    async def who_is(self, device_instance_low: int, device_instance_high: int, dest: str):
        destination_addr = dest if isinstance(dest, Address) else Address(dest)
        _log.debug(f"Sending Who-Is to {destination_addr} (low_id: {device_instance_low}, high_id: {device_instance_high})")
        
        app_instance = None
        try:
            app_instance = self.bacnet.app
            # Perform WHO-IS discovery (note: bacpypes3 who_is doesn't accept apdu_timeout parameter)
            i_am_responses = await app_instance.who_is(device_instance_low, device_instance_high, destination_addr)
            _log.debug(f"Received {len(i_am_responses)} I-Am response(s) from {destination_addr}")
            
            devices_found = []
            if i_am_responses:
                for i_am_pdu in i_am_responses:
                    device_info = {
                        "pduSource": str(i_am_pdu.pduSource),
                        "deviceIdentifier": i_am_pdu.iAmDeviceIdentifier,
                        "maxAPDULengthAccepted": i_am_pdu.maxAPDULengthAccepted,
                        "segmentationSupported": str(i_am_pdu.segmentationSupported),
                        "vendorID": i_am_pdu.vendorID,
                    }
                    devices_found.append(device_info)
            return devices_found
        except asyncio.TimeoutError:
            _log.warning(f"Who-Is timeout for {destination_addr}")
            return []
        except ErrorRejectAbortNack as e_bac:
            _log.warning(f"BACnet error during Who-Is: {e_bac}")
            return []
        except Exception as e_gen:
            _log.error(f"General error during Who-Is: {e_gen}")
            return []


class BACnet:
    def __init__(self, local_device_address, bacnet_network=0, vendor_id=999, object_name='VOLTTRON BACnet Proxy',
                 device_info_cache=None, router_info_cache=None, ase_id=None, **_):
        _log.debug('WELCOME BAC')
        # come back here after i finish debugging
        self.learned_networks = set()  # Track discovered BACnet networks
        self.router_responses = []
        self.discovered_devices = {}
        vendor_info = get_vendor_info(vendor_id)
        device_object_class = vendor_info.get_object_class(ObjectType.device)
        device_object = device_object_class(objectIdentifier=('device', vendor_id), objectName=object_name)
        network_port_object_class = vendor_info.get_object_class(ObjectType.networkPort)
        network_port_object = network_port_object_class(local_device_address,
                                                        objectIdentifier=("network-port", bacnet_network),
                                                        objectName="NetworkPort-1", networkNumber=bacnet_network,
                                                        networkNumberQuality="configured")
        self.app = Application.from_object_list(
            [device_object, network_port_object],
            device_info_cache=device_info_cache,  # TODO: If these should be passed in, add to args & launch.
            router_info_cache=router_info_cache,
            aseID=ase_id
        )
        _log.debug(f'WE HAVE AN APP: {self.app.device_info_cache}')
    # NPDU handler registration not needed in BACpypes3; handled via async indication in Application subclass


    async def query_device(self, address: str, property_name: str = 'object-identifier'):
        """
        Returns properties about the device at the given address.
        If a different property name is not given, this will be the object-id.
        This function allows unicast discovery.
        This can get everything from device if it is using read_property_multiple and ALL
        """
        _log.debug('IN QUERY DEVICE METHOD')
        return await self.read_property(device_address=address, object_identifier='device:4194303', property_identifier=property_name)




















    def discover(
        self,
        networks: t.Union[str, t.List[int], int] = "known",
        limits: t.Tuple[int, int] = (0, 4194303),
        global_broadcast: bool = False,
        reset: bool = False,
        unicast_targets: t.Optional[t.List[str]] = None,
        extra_subnets: t.Optional[t.List[str]] = None,
    ) -> None:
        """
        Initiates the discovery process to locate BACnet devices on the network asynchronously, then calls on discovery.
        """
        print(f"[discover] Called with networks={networks}, limits={limits}, global_broadcast={global_broadcast}, reset={reset}, unicast_targets={unicast_targets}")
        try:
            print("[discover] Getting asyncio loop...")
            loop = asyncio.get_running_loop()
        except RuntimeError:
            print("[discover] No running loop, creating new event loop.")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        print("[discover] Scheduling _discover task...")
        asyncio.create_task(
            self._discover(
                networks=networks,
                limits=limits,
                global_broadcast=global_broadcast,
                reset=reset,
                unicast_targets=unicast_targets,
                extra_subnets=extra_subnets
            )
        )

    async def _discover(
        self,
        networks: t.Union[str, t.List[int], int],
        limits: t.Tuple[int, int],
        global_broadcast: bool,
        reset: bool,
        timeout: int = 30,
        unicast_targets: t.Optional[t.List[str]] = None,
        extra_subnets: t.Optional[t.List[str]] = None,
    ) -> None:
        """
        Internal method to handle discovery logic.

        Updates the `discovered_devices` attribute.
        """
        print(f"[_discover] Starting BACnet network discovery with networks={networks}, global_broadcast={global_broadcast}, reset={reset}, timeout={timeout}")
        _log.debug(f"Starting network discovery with parameters: {locals()}")
        if reset:
            print("[_discover] Resetting learned_networks.")
            self.learned_networks = set()
            self.router_responses = []

        # Collect networks (focus only on networks/routers)
        print("[_discover] Collecting BACnet networks and routers...")
        network_set = await self.collect_networks(networks, global_broadcast)
        print(f"[_discover] Networks discovered: {network_set}")

        # Print router responses
        if hasattr(self, 'router_responses') and self.router_responses:
            print(f"[_discover] Routers discovered:")
            for src, router_pdu in self.router_responses:
                print(f"  Router at {src}, networks: {getattr(router_pdu, 'iartnNetworkList', [])}")
        else:
            print("[_discover] No routers discovered.")

        print(f"[_discover] Network discovery complete. Total networks found: {len(network_set)}")
        # Device discovery logic removed

        # Actively send Who-Is to unicast_targets if provided
        if unicast_targets:
            print(f"[_discover] Sending unicast Who-Is to: {unicast_targets}")
            from bacpypes3.pdu import Address
            from bacpypes3.apdu import WhoIsRequest
            for target_ip in unicast_targets:
                try:
                    request = WhoIsRequest()
                    request.pduDestination = Address(target_ip)
                    print(f"[_discover] Sending Who-Is to {target_ip}")
                    await self.app.indication(request)
                except Exception as e:
                    print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")

        # If no networks/routers found, brute-force probe BACnet network numbers and local subnets
        if not network_set:
            print("[_discover] No BACnet networks found, brute-forcing BACnet network numbers and local IP subnets...")
            # Brute-force BACnet network numbers 1–100
            from bacpypes3.npdu import WhoIsRouterToNetwork
            from bacpypes3.pdu import Address, GlobalBroadcast
            BRUTE_FORCE_NET_RANGE = range(1, 101)
            for net_num in BRUTE_FORCE_NET_RANGE:
                try:
                    npdu = WhoIsRouterToNetwork(net_num)
                    npdu.pduDestination = GlobalBroadcast()
                    print(f"[_discover] Probing BACnet network number: {net_num}")
                    await self.app.indication(npdu)
                except Exception as e:
                    print(f"[_discover] Failed to probe BACnet network {net_num}: {e}")
            print("[_discover] Brute-force BACnet network number probing complete.")

            # Brute-force probe local IP subnets (as before)
            HOST_LIMIT = 256  # Maximum number of hosts to probe per subnet
            # Probe all local subnets, filtering out loopback and link-local networks
            local_subnets = [net for iface, net in get_connected_networks()]
            filtered_subnets = []
            for net in local_subnets:
                # Always scan detected local subnets (excluding loopback/link-local) AND brute-force all private ranges
                # Scan detected subnets
                for net in filtered_subnets:
                    try:
                        net_obj = ipaddress.IPv4Network(net, strict=False)
                        num_hosts = net_obj.num_addresses - 2 if net_obj.num_addresses > 2 else net_obj.num_addresses
                        print(f"[_discover] Probing subnet: {net} ({num_hosts} hosts)")
                        ip_count = 0
                        for ip in net_obj.hosts():
                            ip_count += 1
                            target_ip = str(ip)
                            print(f"    Probing IP: {target_ip} [IP {ip_count}/{num_hosts}]")
                            try:
                                request = WhoIsRequest()
                                request.pduDestination = Address(target_ip)
                                await self.app.indication(request)
                            except Exception as e:
                                print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                    except Exception as e:
                        print(f"[_discover] Invalid filtered subnet {net}: {e}")

                # Brute-force ALL common private /24 subnets every time
                print("[_discover] Brute-forcing ALL common private /24 subnets in addition to detected subnets...")
                total_subnets = 256 + 256*256 + 16*256
                subnet_count = 0
                # 192.168.0.0/24 to 192.168.255.0/24
                for i in range(256):
                    net = f"192.168.{i}.0/24"
                    subnet_count += 1
                    try:
                        net_obj = ipaddress.IPv4Network(net, strict=False)
                        print(f"[_discover] Probing brute subnet: {net} (254 hosts) [Subnet {subnet_count}/{total_subnets}]")
                        ip_count = 0
                        for ip in net_obj.hosts():
                            ip_count += 1
                            target_ip = str(ip)
                            print(f"    Probing IP: {target_ip} [IP {ip_count}/254]")
                            try:
                                request = WhoIsRequest()
                                request.pduDestination = Address(target_ip)
                                await self.app.indication(request)
                            except Exception as e:
                                print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                    except Exception as e:
                        print(f"[_discover] Invalid brute subnet {net}: {e}")
                # 10.0.0.0/24 to 10.255.255.0/24
                for i in range(256):
                    for j in range(256):
                        net = f"10.{i}.{j}.0/24"
                        subnet_count += 1
                        try:
                            net_obj = ipaddress.IPv4Network(net, strict=False)
                            print(f"[_discover] Probing brute subnet: {net} (254 hosts) [Subnet {subnet_count}/{total_subnets}]")
                            ip_count = 0
                            for ip in net_obj.hosts():
                                ip_count += 1
                                target_ip = str(ip)
                                print(f"    Probing IP: {target_ip} [IP {ip_count}/254]")
                                try:
                                    request = WhoIsRequest()
                                    request.pduDestination = Address(target_ip)
                                    await self.app.indication(request)
                                except Exception as e:
                                    print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                        except Exception as e:
                            print(f"[_discover] Invalid brute subnet {net}: {e}")
                # 172.16.0.0/24 to 172.31.255.0/24
                for i in range(16, 32):
                    for j in range(256):
                        net = f"172.{i}.{j}.0/24"
                        subnet_count += 1
                        try:
                            net_obj = ipaddress.IPv4Network(net, strict=False)
                            print(f"[_discover] Probing brute subnet: {net} (254 hosts) [Subnet {subnet_count}/{total_subnets}]")
                            ip_count = 0
                            for ip in net_obj.hosts():
                                ip_count += 1
                                target_ip = str(ip)
                                print(f"    Probing IP: {target_ip} [IP {ip_count}/254]")
                                try:
                                    request = WhoIsRequest()
                                    request.pduDestination = Address(target_ip)
                                    await self.app.indication(request)
                                except Exception as e:
                                    print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                        except Exception as e:
                            print(f"[_discover] Invalid brute subnet {net}: {e}")
                # No subnets detected, brute-force all common private /24 subnets
                print("[_discover] No local subnets detected, brute-forcing ALL common private /24 subnets...")
                # 192.168.0.0/24 to 192.168.255.0/24
                total_subnets = 256 + 256*256 + 16*256
                subnet_count = 0
                # 192.168.0.0/24 to 192.168.255.0/24
                for i in range(256):
                    net = f"192.168.{i}.0/24"
                    subnet_count += 1
                    try:
                        net_obj = ipaddress.IPv4Network(net, strict=False)
                        print(f"[_discover] Probing brute subnet: {net} (254 hosts) [Subnet {subnet_count}/{total_subnets}]")
                        ip_count = 0
                        for ip in net_obj.hosts():
                            ip_count += 1
                            target_ip = str(ip)
                            print(f"    Probing IP: {target_ip} [IP {ip_count}/254]")
                            try:
                                request = WhoIsRequest()
                                request.pduDestination = Address(target_ip)
                                await self.app.indication(request)
                            except Exception as e:
                                print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                    except Exception as e:
                        print(f"[_discover] Invalid brute subnet {net}: {e}")
                # 10.0.0.0/24 to 10.255.255.0/24
                for i in range(256):
                    for j in range(256):
                        net = f"10.{i}.{j}.0/24"
                        subnet_count += 1
                        try:
                            net_obj = ipaddress.IPv4Network(net, strict=False)
                            print(f"[_discover] Probing brute subnet: {net} (254 hosts) [Subnet {subnet_count}/{total_subnets}]")
                            ip_count = 0
                            for ip in net_obj.hosts():
                                ip_count += 1
                                target_ip = str(ip)
                                print(f"    Probing IP: {target_ip} [IP {ip_count}/254]")
                                try:
                                    request = WhoIsRequest()
                                    request.pduDestination = Address(target_ip)
                                    await self.app.indication(request)
                                except Exception as e:
                                    print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                        except Exception as e:
                            print(f"[_discover] Invalid brute subnet {net}: {e}")
                # 172.16.0.0/24 to 172.31.255.0/24
                for i in range(16, 32):
                    for j in range(256):
                        net = f"172.{i}.{j}.0/24"
                        subnet_count += 1
                        try:
                            net_obj = ipaddress.IPv4Network(net, strict=False)
                            print(f"[_discover] Probing brute subnet: {net} (254 hosts) [Subnet {subnet_count}/{total_subnets}]")
                            ip_count = 0
                            for ip in net_obj.hosts():
                                ip_count += 1
                                target_ip = str(ip)
                                print(f"    Probing IP: {target_ip} [IP {ip_count}/254]")
                                try:
                                    request = WhoIsRequest()
                                    request.pduDestination = Address(target_ip)
                                    await self.app.indication(request)
                                except Exception as e:
                                    print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                        except Exception as e:
                            print(f"[_discover] Invalid brute subnet {net}: {e}")
                # 10.0.0.0/24 to 10.255.255.0/24
                for i in range(256):
                    for j in range(256):
                        net = f"10.{i}.{j}.0/24"
                        try:
                            net_obj = ipaddress.IPv4Network(net, strict=False)
                            print(f"[_discover] Probing brute subnet: {net} (254 hosts)")
                            for ip in net_obj.hosts():
                                target_ip = str(ip)
                                try:
                                    request = WhoIsRequest()
                                    request.pduDestination = Address(target_ip)
                                    await self.app.indication(request)
                                except Exception as e:
                                    print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                        except Exception as e:
                            print(f"[_discover] Invalid brute subnet {net}: {e}")
                # 172.16.0.0/24 to 172.31.255.0/24
                for i in range(16, 32):
                    for j in range(256):
                        net = f"172.{i}.{j}.0/24"
                        try:
                            net_obj = ipaddress.IPv4Network(net, strict=False)
                            print(f"[_discover] Probing brute subnet: {net} (254 hosts)")
                            for ip in net_obj.hosts():
                                target_ip = str(ip)
                                try:
                                    request = WhoIsRequest()
                                    request.pduDestination = Address(target_ip)
                                    await self.app.indication(request)
                                except Exception as e:
                                    print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                        except Exception as e:
                            print(f"[_discover] Invalid brute subnet {net}: {e}")
            else:
                for net in filtered_subnets:
                    try:
                        net_obj = ipaddress.IPv4Network(net, strict=False)
                        num_hosts = net_obj.num_addresses - 2 if net_obj.num_addresses > 2 else net_obj.num_addresses
                        print(f"[_discover] Probing subnet: {net} ({num_hosts} hosts)")
                        ip_count = 0
                        for ip in net_obj.hosts():
                            ip_count += 1
                            target_ip = str(ip)
                            print(f"    Probing IP: {target_ip} [IP {ip_count}/{num_hosts}]")
                            try:
                                request = WhoIsRequest()
                                request.pduDestination = Address(target_ip)
                                await self.app.indication(request)
                            except Exception as e:
                                print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                    except Exception as e:
                        print(f"[_discover] Invalid filtered subnet {net}: {e}")
            # Probe any extra subnets specified by the user
            if extra_subnets:
                for net in extra_subnets:
                    try:
                        net_obj = ipaddress.IPv4Network(net, strict=False)
                        num_hosts = net_obj.num_addresses - 2 if net_obj.num_addresses > 2 else net_obj.num_addresses
                        if num_hosts > HOST_LIMIT:
                            print(f"[_discover] Skipping extra subnet {net} (too large: {num_hosts} hosts)")
                            continue
                        print(f"[_discover] Probing extra subnet: {net} ({num_hosts} hosts)")
                        for ip in net_obj.hosts():
                            target_ip = str(ip)
                            try:
                                request = WhoIsRequest()
                                request.pduDestination = Address(target_ip)
                                await self.app.indication(request)
                            except Exception as e:
                                print(f"[_discover] Failed to send Who-Is to {target_ip}: {e}")
                    except Exception as e:
                        print(f"[_discover] Invalid extra subnet {net}: {e}")
            print("[_discover] Brute-force probing complete.")

    async def collect_networks(self, networks: t.Union[str, t.List[int], int], global_broadcast: bool = False) -> t.Set[int]:
        """
        Collects BACnet network numbers to discover devices from.

        Parameters:
        - networks: A list or single network number. If "known", uses `learned_networks`.
        - global_broadcast: Indicates whether routers should be discovered globally.

        Returns:
        - A set of network numbers to query.
        """
        network_set = self.learned_networks.copy()

        # Add the local network number if available
        local_network = await self.what_is_network_number()
        if local_network:
            network_set.add(local_network)

        # Discover routers to networks
        routers = await self.whois_router_to_network()
        if not routers:
            routers = await self.whois_router_to_network(global_broadcast=True)

        for _, response in routers:
            network_set.update(response.iartnNetworkList)

        # Expand network set based on user-specified networks
        if isinstance(networks, list):
            network_set.update(int(n) for n in networks if n < 65535)
        elif isinstance(networks, int) and networks < 65535:
            network_set.add(networks)
        elif networks == "known":
            pass  # Keep the current learned networks

        return network_set

    def _process_iam_responses(self, responses: t.List[t.Tuple[object, t.Optional[int]]]) -> None:
        """
        Processes I-Am responses from BACnet devices and updates `discovered_devices`.

        Parameters:
        - responses: List of tuples containing the I-Am response and network number.
        """
        for iam_request, network_number in responses:
            # Handle both dict and object types for device info
            if isinstance(iam_request, dict):
                objid = iam_request.get("deviceIdentifier")
                device_address = iam_request.get("pduSource")
                vendor_id = iam_request.get("vendorID")
            else:
                objid = getattr(iam_request, "iAmDeviceIdentifier", None)
                device_address = getattr(iam_request, "pduSource", None)
                vendor_id = getattr(iam_request, "vendorID", None)
            key = str(objid)
            if key not in self.discovered_devices:
                self.discovered_devices[key] = {
                    "object_instance": objid,
                    "address": device_address,
                    "network_number": {network_number} if network_number is not None else set(),
                    "vendor_id": vendor_id,
                    "vendor_name": "unknown",
                }
            else:
                self.discovered_devices[key]["network_number"].add(network_number)

    async def what_is_network_number(self) -> t.Optional[int]:
        """
        Returns the local BACnet network number by querying the network port object.
        """
        try:
            # Try to read the network number property from the local network port object
            result = await self.read_property(
                device_address="local",
                object_identifier="network-port:0",
                property_identifier="network-number"
            )
            if isinstance(result, int):
                return result
            # Only call get_value if not an error type
            if hasattr(result, 'get_value') and not isinstance(result, ErrorRejectAbortNack):
                return result.get_value()
        except Exception as e:
            _log.error(f"Error getting local network number: {e}")
        return None

    async def whois_router_to_network(self, global_broadcast: bool = False) -> list:
        """
        Discovers routers to other BACnet networks using Who-Is-Router-To-Network service.
        Returns a list of tuples (source, response) for each discovered router.
        """
        try:
            self.router_responses = []
            # Build and send Who-IsRouterToNetwork NPDU
            from bacpypes3.npdu import WhoIsRouterToNetwork
            from bacpypes3.pdu import Address, GlobalBroadcast
            npdu = WhoIsRouterToNetwork()
            destination = GlobalBroadcast() if global_broadcast else Address("255.255.255.255")
            npdu.pduDestination = destination
            await self.app.indication(npdu)
            # Wait for responses (simple sleep, could be improved with event/queue)
            await asyncio.sleep(3)
            return self.router_responses
        except Exception as e:
            _log.error(f"Error during router discovery: {e}")
            return []

    def indication(self, pdu):
        # NPDU handler for router discovery
        from bacpypes3.npdu import IAmRouterToNetwork
        if isinstance(pdu, IAmRouterToNetwork):
            self.router_responses.append((getattr(pdu, "pduSource", None), pdu))
  






















# --- Utility functions below should be moved to a separate file (e.g., network_utils.py) for better organization ---
import psutil, ipaddress, socket, subprocess

def get_connected_networks():
    """
    Returns a list of (interface, subnet) tuples for all IPv4 interfaces.
    """
    networks = []
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if getattr(addr, 'family', None) == socket.AF_INET or getattr(addr, 'family', None) == 2:
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
    Scans for Wi-Fi networks on Windows using netsh.
    Returns a list of dicts with ssid and bssid.
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

def nmap_probe_common_router_points(max_workers=10):
    import nmap
    import time
    import concurrent.futures

    # Only probe the most common subnets
    common_subnets = [
        "192.168.0.0/24",
        "192.168.1.0/24",
        "10.0.0.0/24",
        "10.1.1.0/24",
        "172.16.0.0/24",
        "172.16.1.0/24",
    ]

    def probe_subnet(subnet, last_time_holder):
        scanner = nmap.PortScanner()
        net_base = subnet[:-4]
        probe_ips = [f"{net_base}1", f"{net_base}254"]
        subnet_start = time.time()
        found = False
        for ip in probe_ips:
            try:
                scanner.scan(hosts=ip, arguments='-sn --host-timeout 5s')
                live_hosts = [host for host in scanner.all_hosts() if scanner[host].state() == 'up']
                if live_hosts:
                    found = True
                    break
            except Exception as e:
                print(f"Error probing {ip}: {e}")
        subnet_end = time.time()
        subnet_time = subnet_end - subnet_start
        diff_since_last = subnet_start - last_time_holder[0]
        last_time_holder[0] = subnet_end
        return (subnet, found, subnet_time, diff_since_last)

    start_time = time.time()
    last_time_holder = [start_time]

    total_subnets = len(common_subnets)
    print(f"Total common subnets to probe: {total_subnets}")

    active_subnets = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(probe_subnet, subnet, last_time_holder)
            for subnet in common_subnets
        ]
        for idx, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            subnet, found, subnet_time, diff_since_last = future.result()
            print(f"[{idx}/{total_subnets}] Subnet: {subnet}")
            print(f"  Probe time: {subnet_time:.2f} seconds")
            print(f"  Difference since last probe: {diff_since_last:.2f} seconds")
            if found:
                print(f"  Active network found!")
                active_subnets.append(subnet)

    total_elapsed = time.time() - start_time
    print(f"\nProbe complete. Active networks found ({len(active_subnets)}):")
    for subnet in active_subnets:
        print(f"  {subnet}")
    print(f"Total elapsed time: {total_elapsed:.2f} seconds")
    return active_subnets  # <-- Add this line!
def nmap_probe_routed_networks(max_workers=10):
    import subprocess
    import re
    import ipaddress
    import nmap
    import time
    import concurrent.futures

    def get_windows_routed_networks():
        routed_networks = {}
        try:
            output = subprocess.check_output(["netstat.exe", "-r"], text=True)
            for line in output.splitlines():
                match = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    dest, netmask, gateway, interface = match.groups()
                    try:
                        net = ipaddress.IPv4Network(f"{dest}/{netmask}", strict=False)
                        # Only add valid, non-loopback, non-broadcast networks
                        if not net.is_loopback and not net.is_multicast and not net.is_link_local and net.prefixlen >= 24:
                            routed_networks[str(net)] = {
                                "gateway": gateway,
                                "interface": interface
                            }
                    except Exception:
                        pass
        except Exception as e:
            print(f"Error running netstat.exe -r: {e}")
        return routed_networks

    routed_networks = get_windows_routed_networks()
    print(f"Windows routed networks found: {list(routed_networks.keys())}")

    def probe_subnet(subnet):
        scanner = nmap.PortScanner()
        net_base = subnet.split('/')[0].rsplit('.', 1)[0] + '.'
        probe_ips = [f"{net_base}1", f"{net_base}254"]
        found = False
        for ip in probe_ips:
            try:
                scanner.scan(hosts=ip, arguments='-sn --host-timeout 5s')
                live_hosts = [host for host in scanner.all_hosts() if scanner[host].state() == 'up']
                if live_hosts:
                    found = True
                    break
            except Exception as e:
                print(f"Error probing {ip}: {e}")
        return subnet if found else None

    active_networks = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(probe_subnet, subnet) for subnet in routed_networks]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"Active network found: {result}")
                active_networks[result] = routed_networks[result]

    print(f"\nProbe complete. Active routed networks found ({len(active_networks)}):")
    for subnet, info in active_networks.items():
        print(f"  {subnet}: {info}")
    return active_networks
def get_windows_routed_networks():
    import subprocess
    import re
    import ipaddress
    routed_networks = {}
    try:
        output = subprocess.check_output(["netstat.exe", "-r"], text=True)
        for line in output.splitlines():
            # Look for lines like: "Network Destination        Netmask          Gateway       Interface  Metric"
            match = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                dest, netmask, gateway, interface = match.groups()
                try:
                    net = ipaddress.IPv4Network(f"{dest}/{netmask}", strict=False)
                    routed_networks[str(net)] = {
                        "gateway": gateway,
                        "interface": interface
                    }
                except Exception:
                    pass
    except Exception as e:
        print(f"Error running netstat.exe -r: {e}")
    return routed_networks
async def run_proxy(local_device_address, **kwargs):
    bp = BACnetProxy(local_device_address, **kwargs)
    # Removed call to bp.start(); not required or not implemented


def launch_bacnet(parser: ArgumentParser) -> tuple[ArgumentParser, Type[AsyncioProtocolProxy]]:
    parser.add_argument('--local-device-address', type=str, required=True,
                        help='Address on the local machine of this BACnet Proxy.')
    parser.add_argument('--bacnet-network', type=int, default=0,
                        help='The BACnet port as an offset from 47808.')
    parser.add_argument('--vendor-id', type=int, default=999,
                        help='The BACnet vendor ID to use for the local device of this BACnet Proxy.')
    parser.add_argument('--object-name', type=str, default='VOLTTRON BACnet Proxy',
                        help='The name of the local device for this BACnet Proxy.')
    return parser, BACnetProxy


if __name__ == '__main__':
    sys.exit(launch(launch_bacnet))

def run_router_probe():
    print("Starting nmap probe of routed networks from Windows routing table...")
    active_networks = nmap_probe_routed_networks()
    print("\nActive routed networks dictionary:")
    print(active_networks)

if __name__ == "__main__":
    run_router_probe()

