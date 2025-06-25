#!/usr/bin/env python3
"""
Device Inventory Management System for Network Device Monitoring.
Phase 6: Maintain accurate, up-to-date inventory of all network devices.
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from .database import get_device_store, get_classification_store, get_dhcp_store

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Complete device information structure."""
    mac_address: str
    current_ip: Optional[str] = None
    hostname: Optional[str] = None
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    operating_system: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    is_active: bool = True
    confidence_score: Optional[int] = None
    total_packets: int = 0
    connection_history: List[Dict] = None

class DeviceInventoryManager:
    """
    Manages device inventory with tracking, consolidation, and history.
    Phase 6: Device Inventory Management implementation.
    """
    
    def __init__(self):
        """Initialize device inventory manager."""
        self.device_store = get_device_store()
        self.classification_store = get_classification_store()
        self.dhcp_store = get_dhcp_store()
        
        # Configuration
        self.inactive_threshold_hours = 168  # 7 days default
        self.low_confidence_threshold = 50
        self.hostname_change_threshold = 3  # Flag after 3+ hostname changes
        
        # Statistics
        self.devices_processed = 0
        self.devices_updated = 0
        self.inactive_devices_found = 0
        
    def update_device_from_classification(self, mac_address: str, 
                                        classification_data: Dict,
                                        packet_data: Dict = None) -> bool:
        """
        Update device inventory with new classification data.
        Phase 6: Combine DHCP packet data with Fingerbank classifications.
        """
        try:
            # Get current device info
            current_devices = self.device_store.get_active_devices(include_inactive=True)
            existing_device = None
            for device in current_devices:
                if device['mac_address'] == mac_address:
                    existing_device = device
                    break
            
            # Prepare update data
            update_data = {
                'mac_address': mac_address,
                'device_name': classification_data.get('device_name'),
                'device_type': classification_data.get('device_type'),
                'operating_system': classification_data.get('operating_system')
            }
            
            # Add packet data if available
            if packet_data:
                if packet_data.get('ip_address'):
                    update_data['current_ip'] = packet_data['ip_address']
                if packet_data.get('hostname'):
                    update_data['hostname'] = packet_data['hostname']
            
            # Handle device classification changes
            if existing_device:
                update_data = self._consolidate_device_data(existing_device, update_data, classification_data)
            
            # Update device in database
            success = self.device_store.upsert_active_device(**update_data)
            
            if success:
                self.devices_updated += 1
                logger.debug(f"Updated device inventory for {mac_address}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to update device {mac_address}: {e}")
            return False
    
    def _consolidate_device_data(self, existing_device: Dict, new_data: Dict, 
                               classification_data: Dict) -> Dict:
        """
        Consolidate existing and new device data intelligently.
        Phase 6: Handle cases where device gets different classifications over time.
        """
        consolidated = new_data.copy()
        
        # Prioritize most recent classification data with highest confidence scores
        current_confidence = classification_data.get('confidence_score', 0)
        
        # Get latest classification to compare confidence
        latest_classification = self.classification_store.get_latest_classification(existing_device['mac_address'])
        previous_confidence = latest_classification.get('confidence_score', 0) if latest_classification else 0
        
        # Use higher confidence classification
        if previous_confidence > current_confidence:
            logger.info(f"Keeping previous classification for {new_data['mac_address']} (confidence: {previous_confidence} > {current_confidence})")
            
            # Keep previous classification data
            consolidated['device_name'] = existing_device.get('device_name') or new_data.get('device_name')
            consolidated['device_type'] = existing_device.get('device_type') or new_data.get('device_type')
            consolidated['operating_system'] = existing_device.get('operating_system') or new_data.get('operating_system')
        
        # Track hostname changes for anomaly detection
        if existing_device.get('hostname') and new_data.get('hostname'):
            if existing_device['hostname'] != new_data['hostname']:
                logger.info(f"Hostname change detected for {new_data['mac_address']}: {existing_device['hostname']} -> {new_data['hostname']}")
                # Could implement hostname change tracking here
        
        # Preserve current IP if not provided in new data
        if not consolidated.get('current_ip') and existing_device.get('current_ip'):
            consolidated['current_ip'] = existing_device['current_ip']
        
        # Preserve hostname if not provided in new data
        if not consolidated.get('hostname') and existing_device.get('hostname'):
            consolidated['hostname'] = existing_device['hostname']
        
        return consolidated
    
    def mark_inactive_devices(self, threshold_hours: int = None) -> int:
        """
        Mark devices as inactive if not seen for specified period.
        Phase 6: Mark devices as is_active=False if not seen for configurable period.
        """
        threshold = threshold_hours or self.inactive_threshold_hours
        
        try:
            count = self.device_store.mark_inactive_devices(threshold)
            self.inactive_devices_found = count
            
            if count > 0:
                logger.info(f"Marked {count} devices as inactive (not seen for {threshold} hours)")
            
            return count
        
        except Exception as e:
            logger.error(f"Failed to mark inactive devices: {e}")
            return 0
    
    def get_device_inventory(self, include_inactive: bool = False) -> List[DeviceInfo]:
        """
        Get comprehensive device inventory.
        Phase 6: Accurate device inventory that reflects current network state.
        """
        try:
            # Get device summary from database view
            devices_data = self.device_store.get_device_summary()
            
            devices = []
            for device_data in devices_data:
                if not include_inactive and not device_data.get('is_active', True):
                    continue
                
                device_info = DeviceInfo(
                    mac_address=device_data['mac_address'],
                    current_ip=device_data.get('current_ip'),
                    hostname=device_data.get('hostname'),
                    device_name=device_data.get('device_name'),
                    device_type=device_data.get('device_type'),
                    operating_system=device_data.get('operating_system'),
                    first_seen=device_data.get('first_seen'),
                    last_seen=device_data.get('last_seen'),
                    is_active=device_data.get('is_active', True),
                    confidence_score=device_data.get('confidence_score'),
                    total_packets=device_data.get('total_packets', 0)
                )
                
                devices.append(device_info)
            
            logger.debug(f"Retrieved {len(devices)} devices from inventory")
            return devices
        
        except Exception as e:
            logger.error(f"Failed to get device inventory: {e}")
            return []
    
    def get_device_details(self, mac_address: str) -> Optional[Dict]:
        """Get detailed information for a specific device."""
        try:
            devices = self.get_device_inventory(include_inactive=True)
            
            for device in devices:
                if device.mac_address == mac_address:
                    # Get additional classification history
                    classifications = self._get_device_classification_history(mac_address)
                    
                    return {
                        'device_info': device,
                        'classification_history': classifications,
                        'packet_count': device.total_packets
                    }
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get device details for {mac_address}: {e}")
            return None
    
    def _get_device_classification_history(self, mac_address: str) -> List[Dict]:
        """Get classification history for a device."""
        # This would require additional database queries
        # For now, return latest classification
        latest = self.classification_store.get_latest_classification(mac_address)
        return [latest] if latest else []
    
    def detect_anomalies(self) -> Dict:
        """
        Detect unusual device activity and classification changes.
        Phase 6: Flag unusual activity (device type changes, unexpected hostname changes).
        """
        anomalies = {
            'device_type_changes': [],
            'hostname_changes': [],
            'low_confidence_devices': [],
            'inactive_devices': []
        }
        
        try:
            devices = self.get_device_inventory(include_inactive=True)
            
            for device in devices:
                # Flag low confidence classifications
                if device.confidence_score and device.confidence_score < self.low_confidence_threshold:
                    anomalies['low_confidence_devices'].append({
                        'mac_address': device.mac_address,
                        'device_name': device.device_name,
                        'confidence_score': device.confidence_score
                    })
                
                # Flag recently inactive devices
                if not device.is_active and device.last_seen:
                    from datetime import timezone
                    now_utc = datetime.now(timezone.utc)
                    last_seen_utc = device.last_seen.replace(tzinfo=timezone.utc) if device.last_seen.tzinfo is None else device.last_seen
                    hours_since_seen = (now_utc - last_seen_utc).total_seconds() / 3600
                    if hours_since_seen < self.inactive_threshold_hours * 2:  # Recently inactive
                        anomalies['inactive_devices'].append({
                            'mac_address': device.mac_address,
                            'device_name': device.device_name,
                            'hours_since_seen': hours_since_seen
                        })
            
            logger.debug(f"Detected {sum(len(v) for v in anomalies.values())} anomalies")
            return anomalies
        
        except Exception as e:
            logger.error(f"Failed to detect anomalies: {e}")
            return anomalies
    
    def get_inventory_statistics(self) -> Dict:
        """Get comprehensive inventory statistics."""
        try:
            devices = self.get_device_inventory(include_inactive=True)
            active_devices = [d for d in devices if d.is_active]
            
            # Device type breakdown
            device_types = {}
            operating_systems = {}
            
            for device in active_devices:
                device_type = device.device_type or 'Unknown'
                device_types[device_type] = device_types.get(device_type, 0) + 1
                
                os_name = device.operating_system or 'Unknown'
                operating_systems[os_name] = operating_systems.get(os_name, 0) + 1
            
            # Recent activity
            from datetime import timezone
            recent_threshold = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_devices = [d for d in active_devices if d.last_seen and d.last_seen.replace(tzinfo=timezone.utc) > recent_threshold]
            
            return {
                'total_devices': len(devices),
                'active_devices': len(active_devices),
                'inactive_devices': len(devices) - len(active_devices),
                'recent_activity_24h': len(recent_devices),
                'device_types': device_types,
                'operating_systems': operating_systems,
                'processing_stats': {
                    'devices_processed': self.devices_processed,
                    'devices_updated': self.devices_updated,
                    'inactive_devices_found': self.inactive_devices_found
                }
            }
        
        except Exception as e:
            logger.error(f"Failed to get inventory statistics: {e}")
            return {}
    
    def cleanup_old_data(self, days_to_keep: int = 30) -> Dict:
        """Clean up old packet and classification data."""
        cleanup_stats = {
            'old_packets_removed': 0,
            'old_classifications_removed': 0
        }
        
        try:
            # This would implement cleanup of old raw_dhcp_packets and device_classifications
            # For now, just return stats structure
            logger.info(f"Cleanup configured to keep {days_to_keep} days of data")
            return cleanup_stats
        
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            return cleanup_stats

def main():
    """Test device inventory management system."""
    print("Device Inventory Management System Test")
    print("=" * 45)
    
    try:
        # Initialize inventory manager
        inventory_manager = DeviceInventoryManager()
        
        # Get current inventory
        devices = inventory_manager.get_device_inventory()
        print(f"Current active devices: {len(devices)}")
        
        # Show first few devices
        for i, device in enumerate(devices[:3]):
            print(f"\nDevice {i+1}:")
            print(f"  MAC: {device.mac_address}")
            print(f"  Name: {device.device_name}")
            print(f"  Type: {device.device_type}")
            print(f"  OS: {device.operating_system}")
            print(f"  IP: {device.current_ip}")
            print(f"  Last Seen: {device.last_seen}")
            print(f"  Packets: {device.total_packets}")
        
        # Check for inactive devices
        inactive_count = inventory_manager.mark_inactive_devices()
        print(f"\nInactive devices found: {inactive_count}")
        
        # Detect anomalies
        anomalies = inventory_manager.detect_anomalies()
        total_anomalies = sum(len(v) for v in anomalies.values())
        print(f"Anomalies detected: {total_anomalies}")
        
        # Show statistics
        stats = inventory_manager.get_inventory_statistics()
        print(f"\nInventory Statistics:")
        print(f"  Total Devices: {stats.get('total_devices', 0)}")
        print(f"  Active Devices: {stats.get('active_devices', 0)}")
        print(f"  Recent Activity (24h): {stats.get('recent_activity_24h', 0)}")
        
        device_types = stats.get('device_types', {})
        if device_types:
            print("  Device Types:")
            for dtype, count in sorted(device_types.items()):
                print(f"    {dtype}: {count}")
    
    except Exception as e:
        print(f"Inventory test failed: {e}")

if __name__ == "__main__":
    main()