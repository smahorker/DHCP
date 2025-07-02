#!/usr/bin/env python3
"""
MAC Address Vendor Lookup for Network Device Monitoring System.
Uses OUI (Organizationally Unique Identifier) database to identify device manufacturers.
"""

import os
import csv
import json
import logging
import requests
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MACVendorLookup:
    """
    MAC address vendor lookup using OUI database.
    Provides manufacturer identification from MAC addresses.
    """
    
    def __init__(self, oui_file_path: Optional[str] = None):
        """Initialize MAC vendor lookup."""
        self.oui_database = {}
        self.oui_file_path = oui_file_path or self._get_default_oui_path()
        self.last_updated = None
        
        # Statistics
        self.lookups_performed = 0
        self.successful_lookups = 0
        self.cache_hits = 0
        
        # Load OUI database
        self._load_oui_database()
        
        logger.info("MAC Vendor Lookup initialized")
    
    def _get_default_oui_path(self) -> str:
        """Get default path for OUI database file."""
        current_dir = Path(__file__).parent
        return str(current_dir / "oui_database.csv")
    
    def _load_oui_database(self):
        """Load OUI database from file or download if needed."""
        try:
            if os.path.exists(self.oui_file_path):
                self._load_from_file()
            else:
                logger.info("OUI database not found, downloading...")
                self.download_oui_database()
        except Exception as e:
            logger.error(f"Failed to load OUI database: {e}")
            # Load minimal built-in database as fallback
            self._load_builtin_database()
    
    def _load_from_file(self):
        """Load OUI database from CSV file."""
        try:
            with open(self.oui_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    oui = row['oui'].upper().replace(':', '').replace('-', '')
                    self.oui_database[oui] = {
                        'vendor': row['vendor'],
                        'vendor_full': row.get('vendor_full', row['vendor']),
                        'country': row.get('country', ''),
                        'updated': row.get('updated', '')
                    }
            
            self.last_updated = datetime.fromtimestamp(os.path.getmtime(self.oui_file_path))
            logger.info(f"Loaded {len(self.oui_database)} OUI entries from database")
            
        except Exception as e:
            logger.error(f"Error loading OUI database from file: {e}")
            self._load_builtin_database()
    
    def _load_builtin_database(self):
        """Load minimal built-in OUI database as fallback."""
        builtin_ouis = {
            # Apple
            '00:03:93': 'Apple, Inc.',
            '00:05:02': 'Apple, Inc.',
            '00:0A:95': 'Apple, Inc.',
            '00:0D:93': 'Apple, Inc.',
            '00:10:FA': 'Apple, Inc.',
            '00:11:24': 'Apple, Inc.',
            '00:13:E8': 'Apple, Inc.',
            '00:14:51': 'Apple, Inc.',
            '00:16:CB': 'Apple, Inc.',
            '00:17:F2': 'Apple, Inc.',
            '00:19:E3': 'Apple, Inc.',
            '00:1B:63': 'Apple, Inc.',
            '00:1E:C2': 'Apple, Inc.',
            '00:1F:5B': 'Apple, Inc.',
            '00:21:E9': 'Apple, Inc.',
            '00:22:41': 'Apple, Inc.',
            '00:23:12': 'Apple, Inc.',
            '00:23:DF': 'Apple, Inc.',
            '00:24:36': 'Apple, Inc.',
            '00:25:00': 'Apple, Inc.',
            '00:25:4B': 'Apple, Inc.',
            '00:25:BC': 'Apple, Inc.',
            '00:26:08': 'Apple, Inc.',
            '00:26:4A': 'Apple, Inc.',
            '00:26:B0': 'Apple, Inc.',
            '00:26:BB': 'Apple, Inc.',
            '2C:F0:5D': 'Apple, Inc.',
            '3C:07:54': 'Apple, Inc.',
            '88:1F:A1': 'Apple, Inc.',
            
            # Samsung
            '00:12:FB': 'Samsung Electronics Co.,Ltd',
            '00:15:99': 'Samsung Electronics Co.,Ltd',
            '00:16:32': 'Samsung Electronics Co.,Ltd',
            '00:17:C9': 'Samsung Electronics Co.,Ltd',
            '00:18:AF': 'Samsung Electronics Co.,Ltd',
            '00:1A:8A': 'Samsung Electronics Co.,Ltd',
            '00:1B:98': 'Samsung Electronics Co.,Ltd',
            '00:1D:25': 'Samsung Electronics Co.,Ltd',
            '00:1E:7D': 'Samsung Electronics Co.,Ltd',
            '00:21:19': 'Samsung Electronics Co.,Ltd',
            '00:23:39': 'Samsung Electronics Co.,Ltd',
            '00:24:54': 'Samsung Electronics Co.,Ltd',
            '5C:F9:38': 'Samsung Electronics Co.,Ltd',
            '44:85:00': 'Samsung Electronics Co.,Ltd',
            
            # Google
            '00:1A:11': 'Google, Inc.',
            '00:11:32': 'Google, Inc.',
            'F4:F5:E8': 'Google, Inc.',
            'DA:A1:19': 'Google, Inc.',
            
            # Raspberry Pi
            'B8:27:EB': 'Raspberry Pi Foundation',
            'DC:A6:32': 'Raspberry Pi Foundation',
            'E4:5F:01': 'Raspberry Pi Foundation',
            
            # Nintendo
            '04:A1:51': 'Nintendo Co., Ltd.',
            '00:09:BF': 'Nintendo Co., Ltd.',
            '00:16:56': 'Nintendo Co., Ltd.',
            '00:17:AB': 'Nintendo Co., Ltd.',
            '00:19:1D': 'Nintendo Co., Ltd.',
            '00:1A:E9': 'Nintendo Co., Ltd.',
            '00:1B:7A': 'Nintendo Co., Ltd.',
            '00:1C:BE': 'Nintendo Co., Ltd.',
            '00:1E:35': 'Nintendo Co., Ltd.',
            '00:1F:32': 'Nintendo Co., Ltd.',
            '00:21:47': 'Nintendo Co., Ltd.',
            '00:22:AA': 'Nintendo Co., Ltd.',
            '00:24:1E': 'Nintendo Co., Ltd.',
            '00:24:44': 'Nintendo Co., Ltd.',
            '00:25:A0': 'Nintendo Co., Ltd.',
            
            # Amazon
            '8C:85:90': 'Amazon Technologies Inc.',
            '00:FC:8B': 'Amazon Technologies Inc.',
            '34:D2:70': 'Amazon Technologies Inc.',
            '38:F7:3D': 'Amazon Technologies Inc.',
            '4C:EF:C0': 'Amazon Technologies Inc.',
            '50:DC:E7': 'Amazon Technologies Inc.',
            '68:37:E9': 'Amazon Technologies Inc.',
            '6C:56:97': 'Amazon Technologies Inc.',
            '74:75:48': 'Amazon Technologies Inc.',
            '84:D6:D0': 'Amazon Technologies Inc.',
            'AC:63:BE': 'Amazon Technologies Inc.',
            'B0:7B:25': 'Amazon Technologies Inc.',
            'CC:F4:11': 'Amazon Technologies Inc.',
            'F0:27:2D': 'Amazon Technologies Inc.',
            'FC:65:DE': 'Amazon Technologies Inc.',
            
            # Philips
            'DC:A6:32': 'Philips Lighting BV',
            '00:17:88': 'Philips Electronics Nederland B.V.',
            
            # Common networking vendors
            'AA:BB:CC': 'Generic/Unknown Vendor',
            '50:C7:BF': 'ARRIS Group, Inc.',
            '78:45:C4': 'ARRIS Group, Inc.',
        }
        
        for oui, vendor in builtin_ouis.items():
            clean_oui = oui.replace(':', '').upper()
            self.oui_database[clean_oui] = {
                'vendor': vendor,
                'vendor_full': vendor,
                'country': '',
                'updated': 'builtin'
            }
        
        logger.info(f"Loaded {len(self.oui_database)} built-in OUI entries")
    
    def download_oui_database(self) -> bool:
        """Download OUI database from IEEE."""
        try:
            logger.info("Downloading OUI database from IEEE...")
            
            # IEEE OUI database URL
            url = "http://standards-oui.ieee.org/oui/oui.csv"
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse the CSV data
            lines = response.text.strip().split('\n')
            
            # Create OUI database file
            with open(self.oui_file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['oui', 'vendor', 'vendor_full', 'country', 'updated'])
                
                for line in lines[1:]:  # Skip header
                    try:
                        parts = line.split(',')
                        if len(parts) >= 3:
                            registry = parts[0].strip().strip('"')
                            assignment = parts[1].strip().strip('"')
                            organization = parts[2].strip().strip('"')
                            
                            if registry and assignment and organization:
                                writer.writerow([assignment, organization, organization, '', datetime.now().isoformat()])
                    except Exception as e:
                        logger.debug(f"Error parsing OUI line: {e}")
                        continue
            
            logger.info(f"Successfully downloaded OUI database to {self.oui_file_path}")
            self._load_from_file()
            return True
            
        except Exception as e:
            logger.error(f"Failed to download OUI database: {e}")
            logger.info("Using built-in OUI database instead")
            self._load_builtin_database()
            return False
    
    def lookup_vendor(self, mac_address: str) -> Dict[str, Optional[str]]:
        """
        Look up vendor information for a MAC address.
        
        Args:
            mac_address: MAC address in any standard format
            
        Returns:
            Dictionary with vendor information
        """
        self.lookups_performed += 1
        
        try:
            # Normalize MAC address - extract first 6 characters (OUI)
            clean_mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
            
            if len(clean_mac) < 6:
                return self._get_unknown_result(mac_address, "Invalid MAC address format")
            
            oui = clean_mac[:6]
            
            # Check cache/database
            if oui in self.oui_database:
                self.successful_lookups += 1
                self.cache_hits += 1
                
                vendor_info = self.oui_database[oui]
                return {
                    'mac_address': mac_address,
                    'oui': f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}",
                    'vendor': vendor_info['vendor'],
                    'vendor_full': vendor_info['vendor_full'],
                    'country': vendor_info.get('country', ''),
                    'confidence': 'high',
                    'source': 'oui_database'
                }
            else:
                return self._get_unknown_result(mac_address, "OUI not found in database")
                
        except Exception as e:
            logger.debug(f"Error looking up vendor for {mac_address}: {e}")
            return self._get_unknown_result(mac_address, f"Lookup error: {e}")
    
    def _get_unknown_result(self, mac_address: str, reason: str) -> Dict[str, Optional[str]]:
        """Return unknown vendor result."""
        clean_mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
        oui = clean_mac[:6] if len(clean_mac) >= 6 else clean_mac
        
        return {
            'mac_address': mac_address,
            'oui': f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}" if len(oui) >= 6 else oui,
            'vendor': 'Unknown',
            'vendor_full': 'Unknown Vendor',
            'country': '',
            'confidence': 'none',
            'source': 'unknown',
            'reason': reason
        }
    
    def bulk_lookup(self, mac_addresses: list) -> Dict[str, Dict]:
        """Perform bulk vendor lookup for multiple MAC addresses."""
        results = {}
        
        for mac in mac_addresses:
            results[mac] = self.lookup_vendor(mac)
        
        return results
    
    def get_vendor_statistics(self) -> Dict:
        """Get vendor lookup statistics."""
        success_rate = (self.successful_lookups / self.lookups_performed * 100) if self.lookups_performed > 0 else 0
        
        return {
            'total_lookups': self.lookups_performed,
            'successful_lookups': self.successful_lookups,
            'cache_hits': self.cache_hits,
            'success_rate': success_rate,
            'database_size': len(self.oui_database),
            'last_updated': self.last_updated.isoformat() if self.last_updated else None
        }
    
    def is_known_mobile_vendor(self, vendor: str) -> bool:
        """Check if vendor is known mobile device manufacturer."""
        mobile_vendors = [
            'apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oppo', 'vivo', 
            'oneplus', 'lg electronics', 'sony', 'motorola', 'nokia', 'htc'
        ]
        
        return any(mobile_vendor in vendor.lower() for mobile_vendor in mobile_vendors)
    
    def is_known_iot_vendor(self, vendor: str) -> bool:
        """Check if vendor is known IoT device manufacturer."""
        iot_vendors = [
            'raspberry pi', 'philips', 'amazon', 'google', 'nest', 'ring',
            'tp-link', 'netgear', 'linksys', 'belkin', 'asus', 'd-link'
        ]
        
        return any(iot_vendor in vendor.lower() for iot_vendor in iot_vendors)
    
    def suggest_device_type_from_vendor(self, vendor: str, hostname: str = None) -> str:
        """Suggest device type based on vendor and hostname."""
        vendor_lower = vendor.lower()
        hostname_lower = (hostname or '').lower()
        
        # Mobile device vendors
        if self.is_known_mobile_vendor(vendor):
            if any(keyword in hostname_lower for keyword in ['iphone', 'ipad', 'android', 'galaxy', 'pixel']):
                return 'Mobile Device'
            elif any(keyword in hostname_lower for keyword in ['macbook', 'imac', 'laptop']):
                return 'Computer'
            else:
                return 'Mobile Device'  # Default for mobile vendors
        
        # Gaming vendors
        elif 'nintendo' in vendor_lower:
            return 'Gaming Console'
        elif any(keyword in vendor_lower for keyword in ['sony', 'microsoft']) and any(keyword in hostname_lower for keyword in ['playstation', 'xbox', 'console']):
            return 'Gaming Console'
        
        # IoT and smart home
        elif self.is_known_iot_vendor(vendor):
            if 'raspberry pi' in vendor_lower:
                return 'Single Board Computer'
            elif any(keyword in vendor_lower for keyword in ['philips', 'nest', 'ring']):
                return 'Smart Home Device'
            elif 'amazon' in vendor_lower and any(keyword in hostname_lower for keyword in ['echo', 'alexa']):
                return 'Smart Speaker'
            else:
                return 'IoT Device'
        
        # Network equipment
        elif any(keyword in vendor_lower for keyword in ['cisco', 'netgear', 'tp-link', 'linksys', 'asus', 'd-link', 'arris', 'motorola']):
            return 'Network Device'
        
        # Computers
        elif any(keyword in vendor_lower for keyword in ['dell', 'hp', 'lenovo', 'asus', 'acer', 'msi']):
            return 'Computer'
        
        else:
            return 'Unknown'

def main():
    """Test MAC vendor lookup functionality."""
    print("🔍 MAC Vendor Lookup Test")
    print("=" * 35)
    
    # Test MAC addresses from our database
    test_macs = [
        "2c:f0:5d:12:34:56",  # Apple iPhone
        "04:a1:51:33:44:55",  # Nintendo Switch
        "b8:27:eb:11:22:33",  # Raspberry Pi
        "8c:85:90:77:88:99",  # Amazon Echo
        "5c:f9:38:98:76:54",  # Samsung
        "44:85:00:12:34:56",  # Samsung TV
        "dc:a6:32:55:66:77",  # Philips Hue
        "00:11:32:45:78:90",  # Google Chromecast
        "aa:bb:cc:dd:ee:ff"   # Unknown vendor
    ]
    
    try:
        # Initialize MAC vendor lookup
        mac_lookup = MACVendorLookup()
        
        print(f"📊 Database loaded with {len(mac_lookup.oui_database)} OUI entries")
        print()
        
        # Test lookups
        for mac in test_macs:
            result = mac_lookup.lookup_vendor(mac)
            print(f"🔍 {mac}")
            print(f"   Vendor: {result['vendor']}")
            print(f"   OUI: {result['oui']}")
            print(f"   Confidence: {result['confidence']}")
            
            # Test device type suggestion
            device_type = mac_lookup.suggest_device_type_from_vendor(result['vendor'])
            print(f"   Suggested Type: {device_type}")
            print()
        
        # Show statistics
        stats = mac_lookup.get_vendor_statistics()
        print(f"📈 Lookup Statistics:")
        print(f"   Total lookups: {stats['total_lookups']}")
        print(f"   Success rate: {stats['success_rate']:.1f}%")
        print(f"   Database size: {stats['database_size']} vendors")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    main()