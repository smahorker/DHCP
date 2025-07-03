#!/usr/bin/env python3
"""
Enhanced classification system with fallback mechanisms for 100% detection rate.
"""

import re
from typing import Dict, Optional, Tuple

class EnhancedFallbackClassifier:
    """
    Fallback classification when Fingerbank fails or lacks data.
    Target: 100% detection rate for common devices.
    """
    
    def __init__(self):
        # Hostname pattern database for OS detection
        self.hostname_patterns = {
            # Windows patterns
            r'(?i).*win(?:dows)?.*': 'Windows',
            r'(?i).*desktop.*': 'Windows',
            r'(?i).*pc.*': 'Windows',
            r'(?i).*workstation.*': 'Windows',
            
            # Apple patterns  
            r'(?i).*macbook.*': 'macOS',
            r'(?i).*imac.*': 'macOS',
            r'(?i).*mac.*': 'macOS',
            r'(?i).*iphone.*': 'iOS',
            r'(?i).*ipad.*': 'iPadOS',
            r'(?i).*apple.*': 'iOS/macOS',
            
            # Android patterns
            r'(?i).*android.*': 'Android',
            r'(?i).*galaxy.*': 'Android',
            r'(?i).*pixel.*': 'Android',
            r'(?i).*oneplus.*': 'Android',
            r'(?i).*samsung.*': 'Android',
            
            # Smart Home/IoT patterns
            r'(?i).*ring.*': 'Linux',
            r'(?i).*nest.*': 'Linux',
            r'(?i).*echo.*': 'Fire OS',
            r'(?i).*alexa.*': 'Fire OS',
            r'(?i).*firetv.*': 'Fire OS',
            r'(?i).*fire.*tv.*': 'Fire OS',
            r'(?i).*chromecast.*': 'Chrome OS',
            r'(?i).*esp_.*': 'Embedded OS',
            r'(?i).*esp32.*': 'Embedded OS',
            r'(?i).*esp8266.*': 'Embedded OS',
            
            # Gaming Consoles
            r'(?i).*ps[0-9].*': 'PlayStation OS',
            r'(?i).*playstation.*': 'PlayStation OS',
            r'(?i).*xbox.*': 'Xbox OS',
            r'(?i).*nintendo.*': 'Nintendo OS',
            
            # Printers
            r'(?i).*printer.*': 'Embedded OS',
            r'(?i).*hp.*print.*': 'Embedded OS',
            r'(?i).*canon.*print.*': 'Embedded OS',
            r'(?i).*epson.*print.*': 'Embedded OS',
            
            # Linux/Unix patterns
            r'(?i).*ubuntu.*': 'Linux',
            r'(?i).*debian.*': 'Linux', 
            r'(?i).*linux.*': 'Linux',
            r'(?i).*raspberrypi.*': 'Linux',
            r'(?i).*raspberry.*': 'Linux',
            r'(?i).*pfsense.*': 'FreeBSD',
            r'(?i).*freebsd.*': 'FreeBSD',
            
            # Network devices
            r'(?i).*router.*': 'RouterOS/Linux',
            r'(?i).*gateway.*': 'Linux',
            r'(?i).*switch.*': 'Linux',
            r'(?i).*access.*point.*': 'Linux'
        }
        
        # Vendor class patterns for OS detection
        self.vendor_class_patterns = {
            r'(?i)msft.*': 'Windows',
            r'(?i)microsoft.*': 'Windows',
            r'(?i)android.*': 'Android',
            r'(?i)aaplbm.*': 'macOS',
            r'(?i)aaplphone.*': 'iOS',
            r'(?i)apple.*': 'iOS/macOS',
            r'(?i)linux.*': 'Linux',
            r'(?i)ubuntu.*': 'Linux'
        }
        
        # Device type patterns - prioritized by specificity
        self.device_type_patterns = {
            # High specificity patterns (exact device identification)
            r'(?i).*iphone.*': 'Phone',
            r'(?i).*ipad.*': 'Tablet', 
            r'(?i).*galaxy.*': 'Phone',
            r'(?i).*pixel.*': 'Phone',
            
            # Smart Home/IoT devices (high specificity)
            r'(?i).*ring.*camera.*': 'Smart Camera',
            r'(?i).*ring.*doorbell.*': 'Smart Camera',
            r'(?i).*nest.*thermostat.*': 'Smart Thermostat',
            r'(?i).*nest.*cam.*': 'Smart Camera',
            r'(?i).*echo.*dot.*': 'Smart Speaker',
            r'(?i).*echo.*show.*': 'Smart Speaker',
            r'(?i).*echo.*studio.*': 'Smart Speaker',
            r'(?i).*alexa.*': 'Smart Speaker',
            r'(?i).*chromecast.*': 'Streaming Device',
            r'(?i).*firetv.*stick.*': 'Streaming Device',
            r'(?i).*fire.*tv.*': 'Streaming Device',
            r'(?i).*apple.*tv.*': 'Streaming Device',
            r'(?i).*roku.*': 'Streaming Device',
            r'(?i).*hue.*bridge.*': 'Smart Hub',
            r'(?i).*hue.*': 'Smart Lighting',
            r'(?i).*philips.*hue.*': 'Smart Lighting',
            
            # Gaming Consoles
            r'(?i).*ps[0-9].*console.*': 'Gaming Console',
            r'(?i).*ps[0-9].*': 'Gaming Console',
            r'(?i).*playstation.*': 'Gaming Console',
            r'(?i).*xbox.*': 'Gaming Console',
            r'(?i).*nintendo.*': 'Gaming Console',
            
            # Printers
            r'(?i).*printer.*': 'Printer',
            r'(?i).*hp.*print.*': 'Printer',
            r'(?i).*canon.*print.*': 'Printer',
            r'(?i).*epson.*print.*': 'Printer',
            
            # IoT/Embedded devices
            r'(?i).*esp_.*': 'IoT Device',
            r'(?i).*esp32.*': 'IoT Device',
            r'(?i).*esp8266.*': 'IoT Device',
            r'(?i).*raspberry.*': 'Single Board Computer',
            r'(?i).*raspberrypi.*': 'Single Board Computer',
            
            # Mobile devices (medium specificity)
            r'(?i).*(android|mobile|phone).*': 'Phone',
            r'(?i).*(tablet).*': 'Tablet',
            
            # Computers (medium specificity)
            r'(?i).*(macbook|laptop|notebook).*': 'Laptop',
            r'(?i).*(desktop|pc|workstation|imac).*': 'Desktop',
            r'(?i).*(server).*': 'Server',
            
            # Network devices (medium specificity)
            r'(?i).*(router|gateway|switch|access.?point).*': 'Network Device',
            r'(?i).*(camera|cam).*': 'Camera',
            r'(?i).*(tv|television|smart.?tv).*': 'Smart TV'
        }
        
        # DHCP fingerprint to OS mapping (common patterns)
        self.dhcp_fingerprint_patterns = {
            # Windows patterns
            r'1,15,3,6,44,46,47,31,33,121,249,43': 'Windows 10/11',
            r'1,15,3,6,44,46,47,31,33,249,43': 'Windows 10',
            r'1,3,6,15,31,33,43,44,46,47,119,121,249,252': 'Windows 7/8',
            
            # Apple patterns  
            r'1,121,3,6,15,119,252,95,44,46': 'iOS/macOS',
            r'1,3,6,15,119,95,252,44,46,47': 'macOS',
            
            # Android patterns
            r'1,3,6,15,26,28,51,58,59,43': 'Android',
            r'1,3,6,12,15,26,28,51,58,59': 'Android',
            
            # Linux patterns
            r'1,28,2,3,15,6,119,12,44,47,26,121,42': 'Linux'
        }

        self.vendor_rules = {
            'apple': {'operating_system': 'iOS/macOS', 'device_type': 'Computer'},
            'samsung': {'operating_system': 'Android', 'device_type': 'Phone'},
            'microsoft': {'operating_system': 'Windows', 'device_type': 'Desktop'},
            'google': {'operating_system': 'Android', 'device_type': 'Phone'},
            'amazon': {'operating_system': 'Fire OS', 'device_type': 'Tablet'},
            'hp': {'operating_system': 'Windows', 'device_type': 'Printer'},
            'dell': {'operating_system': 'Windows', 'device_type': 'Laptop'},
            'netgear': {'operating_system': 'RouterOS/Linux', 'device_type': 'Network Device'},
            'linksys': {'operating_system': 'RouterOS/Linux', 'device_type': 'Network Device'},
            'cisco': {'operating_system': 'IOS', 'device_type': 'Network Device'},
            'ubiquiti': {'operating_system': 'UniFi OS', 'device_type': 'Network Device'},
        }

        # IoT patterns - MUST be hostname-specific to avoid vendor conflicts
        self.iot_device_patterns = {
            # Smart Speakers (hostname-based only)
            r'(google.*home|nest.*mini|nest.*hub)': {'operating_system': 'Google Assistant', 'device_type': 'Smart Speaker'},
            r'(echo.*dot|echo.*show|echo.*studio|alexa.*device)': {'operating_system': 'Fire OS', 'device_type': 'Smart Speaker'},
            r'(homepod|apple.*speaker)': {'operating_system': 'audioOS', 'device_type': 'Smart Speaker'},

            # Smart Cameras (hostname-based only)
            r'(ring.*camera|ring.*doorbell)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},
            r'(nest.*cam|google.*cam)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},
            r'(arlo.*cam|arlo.*camera)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},
            r'(wyze.*cam|wyze.*camera)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},
            r'(blink.*cam|blink.*camera)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},

            # Smart Thermostats (hostname-based only)
            r'(nest.*thermostat|google.*thermostat)': {'operating_system': 'Linux', 'device_type': 'Smart Thermostat'},
            r'(ecobee)': {'operating_system': 'Linux', 'device_type': 'Smart Thermostat'},
            r'(honeywell.*thermostat)': {'operating_system': 'Linux', 'device_type': 'Smart Thermostat'},

            # Smart Plugs (hostname-based only - FIXED)
            r'(kasa.*plug|smart.*plug|tp.*link.*plug)': {'operating_system': 'Linux', 'device_type': 'Smart Plug'},
            r'(wemo.*plug|belkin.*plug)': {'operating_system': 'Linux', 'device_type': 'Smart Plug'},
            r'(amazon.*plug|alexa.*plug)': {'operating_system': 'Linux', 'device_type': 'Smart Plug'},

            # Smart Lighting (hostname-based only)
            r'(philips.*hue|hue.*bridge|hue.*bulb)': {'operating_system': 'Linux', 'device_type': 'Smart Lighting'},
            r'(lifx.*bulb|lifx.*strip)': {'operating_system': 'Linux', 'device_type': 'Smart Lighting'},

            # IoT Development Boards (hostname-based only)
            r'(esp.*[0-9]+|esp_[0-9]+|arduino.*[0-9]+)': {'operating_system': 'Embedded OS', 'device_type': 'IoT Device'},
            r'(nodemcu|wemos|lolin)': {'operating_system': 'Embedded OS', 'device_type': 'IoT Device'},
        }
    
    def _classify_by_iot_signature(self, hostname: str, vendor: str) -> Tuple[Optional[str], Optional[str]]:
        """Classify a device based on IoT device signatures - HOSTNAME ONLY to avoid vendor conflicts."""
        # ONLY use hostname to avoid misclassifying vendors like TP-Link
        # TP-Link makes routers AND smart plugs - vendor alone is insufficient
        if not hostname:
            return None, None

        # Check hostname against IoT patterns
        for pattern, classification in self.iot_device_patterns.items():
            if re.search(pattern, hostname, re.IGNORECASE):
                return classification.get('operating_system'), classification.get('device_type')

        return None, None
    
    def _classify_by_vendor_rules(self, vendor: str) -> Tuple[Optional[str], Optional[str]]:
        """Classify a device based on vendor-specific rules."""
        if not vendor:
            return None, None

        for vendor_key, rules in self.vendor_rules.items():
            if vendor_key in vendor.lower():
                return rules.get('operating_system'), rules.get('device_type')

        return None, None
    
    def _classify_by_hardware_manufacturer_context(self, vendor: str, vendor_class: str) -> Optional[str]:
        """
        Comprehensive vendor-based classification with edge case handling.
        Handles multi-product vendors, component manufacturers, and DHCP context.
        """
        if not vendor:
            return None
        
        vendor_lower = vendor.lower()
        vc_lower = vendor_class.lower() if vendor_class else ''
        
        # EDGE CASE 1: Pure Networking Equipment Vendors (high confidence)
        pure_networking_vendors = ['zyxel', 'ubiquiti', 'mikrotik', 'juniper', 'aruba', 'meraki']
        if any(net in vendor_lower for net in pure_networking_vendors):
            return 'Network Device'
        
        # EDGE CASE 2: Multi-Product Vendors (need DHCP context to disambiguate)
        multi_product_vendors = {
            'tp-link': {
                'networking_indicators': ['udhcp', 'busybox', 'dhcpcd', 'openwrt'],
                'iot_indicators': ['kasa', 'smart', 'plug', 'bulb'],
                'default': 'Network Device'  # TP-Link primarily networking
            },
            'netgear': {
                'networking_indicators': ['udhcp', 'busybox', 'dhcpcd'],
                'iot_indicators': ['arlo', 'orbi'],
                'default': 'Network Device'
            },
            'd-link': {
                'networking_indicators': ['udhcp', 'busybox', 'dhcpcd'],
                'iot_indicators': ['dcs', 'camera'],
                'default': 'Network Device'
            },
            'belkin': {
                'networking_indicators': ['udhcp', 'busybox'],
                'iot_indicators': ['wemo', 'smart'],
                'default': 'Network Device'  # Belkin routers more common
            },
            'cisco': {
                'networking_indicators': ['ios', 'nx-os', 'asa'],
                'default': 'Network Device'
            }
        }
        
        for vendor_key, patterns in multi_product_vendors.items():
            if vendor_key in vendor_lower:
                # Check for networking indicators
                if any(indicator in vc_lower for indicator in patterns.get('networking_indicators', [])):
                    return 'Network Device'
                # Check for IoT indicators  
                elif any(indicator in vc_lower for indicator in patterns.get('iot_indicators', [])):
                    return 'IoT Device'
                # Return default for vendor
                else:
                    return patterns.get('default', 'Network Device')
        
        # EDGE CASE 3: Component Manufacturers (chips in various device types)
        component_manufacturers = {
            'intel': {
                'network_indicators': ['dhcpcd', 'pxe', 'amt'],
                'mobile_indicators': ['android-dhcp'],
                'default': 'Computer'  # Intel NICs mostly in computers
            },
            'giga-byte': {'default': 'Computer'},  # Motherboard manufacturer
            'micro-star': {'default': 'Computer'},  # MSI motherboards
            'asrock': {'default': 'Computer'},     # Motherboard manufacturer
            'nvidia': {'default': 'Computer'},     # Graphics cards
            'amd': {'default': 'Computer'},        # CPUs/GPUs
            'realtek': {'default': 'Computer'},    # Network chips
            'broadcom': {'default': 'Computer'},   # Various chips
            'qualcomm': {'default': 'Phone'},      # Mobile processors
            'mediatek': {'default': 'Phone'}       # Mobile processors
        }
        
        for component, context in component_manufacturers.items():
            if component in vendor_lower:
                # Context-aware classification for component manufacturers
                indicators = context.get('network_indicators', [])
                if indicators and any(ind in vc_lower for ind in indicators):
                    return 'Network Device'
                
                indicators = context.get('mobile_indicators', [])
                if indicators and any(ind in vc_lower for ind in indicators):
                    return 'Phone'
                    
                return context.get('default', 'Computer')
        
        # EDGE CASE 4: Primary Device Manufacturers (high confidence)
        device_manufacturers = {
            'apple': {
                'mobile_indicators': ['iphone', 'ios-dhcp'],
                'computer_indicators': ['dhcpcd', 'macos'],
                'default': 'Computer'  # Default to computer for Apple NICs
            },
            'samsung': {
                'mobile_indicators': ['android-dhcp', 'galaxy'],
                'tv_indicators': ['tizen', 'smart-tv'],
                'default': 'Phone'  # Samsung primarily mobile
            },
            'google': {
                'mobile_indicators': ['android-dhcp', 'pixel'],
                'iot_indicators': ['nest', 'chromecast'],
                'default': 'Phone'
            },
            'amazon': {
                'iot_indicators': ['alexa', 'echo', 'fire'],
                'default': 'IoT Device'
            },
            'microsoft': {'default': 'Computer'},
            'dell': {'default': 'Computer'},
            'hp': {'default': 'Computer'},
            'lenovo': {'default': 'Computer'},
            'sony': {
                'gaming_indicators': ['playstation', 'ps4', 'ps5'],
                'default': 'Gaming Console'
            },
            'nintendo': {'default': 'Gaming Console'},
            'xiaomi': {'default': 'Phone'},
            'huawei': {'default': 'Phone'},
            'oneplus': {'default': 'Phone'}
        }
        
        for manufacturer, context in device_manufacturers.items():
            if manufacturer in vendor_lower:
                # Check specific indicators
                for indicator_type in ['mobile_indicators', 'computer_indicators', 'tv_indicators', 'iot_indicators', 'gaming_indicators']:
                    indicators = context.get(indicator_type, [])
                    if indicators and any(ind in vc_lower for ind in indicators):
                        if indicator_type == 'mobile_indicators':
                            return 'Phone'
                        elif indicator_type == 'computer_indicators':
                            return 'Computer'
                        elif indicator_type == 'tv_indicators':
                            return 'Smart TV'
                        elif indicator_type == 'iot_indicators':
                            return 'IoT Device'
                        elif indicator_type == 'gaming_indicators':
                            return 'Gaming Console'
                
                return context.get('default')
        
        # EDGE CASE 5: Virtualization Vendors
        virtual_vendors = ['vmware', 'virtualbox', 'parallels', 'xen', 'kvm']
        if any(virt in vendor_lower for virt in virtual_vendors):
            return 'Virtual Machine'
        
        # EDGE CASE 6: Development Board Vendors
        dev_board_vendors = ['raspberry pi', 'arduino', 'espressif', 'adafruit', 'sparkfun']
        if any(dev in vendor_lower for dev in dev_board_vendors):
            return 'Single Board Computer'
        
        # EDGE CASE 7: Printer Manufacturers
        printer_vendors = ['hp inc', 'canon', 'epson', 'brother', 'lexmark', 'xerox']
        if any(printer in vendor_lower for printer in printer_vendors):
            return 'Printer'
        
        # EDGE CASE 8: Generic OUI assignments (low confidence)
        if 'private' in vendor_lower or 'locally administered' in vendor_lower:
            # Check vendor class for hints
            if 'android' in vc_lower:
                return 'Phone'
            elif 'msft' in vc_lower or 'microsoft' in vc_lower:
                return 'Computer'
            elif 'apple' in vc_lower:
                return 'Computer'
            # Cannot determine from private MAC
            return None
        
        return None
    
    def _resolve_hostname_vendor_conflicts(self, hostname: str, vendor: str, current_device_type: str) -> Optional[str]:
        """Resolve conflicts between hostname and vendor information."""
        if not hostname or not vendor:
            return None
        
        hostname_lower = hostname.lower()
        
        # Device-specific hostname patterns override vendor - ENHANCED PATTERNS
        device_patterns = {
            'Smart Camera': ['ring', 'nest-cam', 'arlo', 'wyze', 'blink', 'eufy-cam', 'camera', 'doorbell'],
            'Smart TV': ['roku', 'firetv', 'fire-tv', 'appletv', 'chromecast', 'smarttv', 'smart-tv', 'smart_tv', 'tv-', '-tv', 'samsung-tv', 'lg-tv', 'sony-tv'],
            'Gaming Console': ['ps4', 'ps5', 'xbox', 'nintendo', 'switch', 'playstation', 'console'],
            'Smart Speaker': ['echo', 'alexa', 'googlehome', 'homepod', 'nest-mini', 'nest-hub'],
            'Phone': ['iphone', 'galaxy', 'pixel', 'oneplus', 'huawei', 'android-phone'],
            'Streaming Device': ['roku', 'firetv', 'chromecast', 'nvidia-shield', 'apple-tv', 'streaming'],
            'Printer': ['printer', 'print', 'hp-', 'canon-', 'epson-', 'brother-'],
            'Smart Thermostat': ['thermostat', 'nest-therm', 'ecobee'],
            'IoT Device': ['esp', 'arduino', 'sensor', 'smart-', 'iot-'],
            'Network Device': ['router', 'gateway', 'switch', 'access-point', 'netgear', 'linksys']
        }
        
        # Check for high-confidence hostname patterns
        for device_type, patterns in device_patterns.items():
            if any(pattern in hostname_lower for pattern in patterns):
                # Only override if different from current classification
                if device_type != current_device_type:
                    return device_type
        
        return None
    
    def _analyze_vendor_class_context(self, vendor_class: str, manufacturer: str) -> Optional[str]:
        """Enhanced vendor class analysis for device type inference with edge case handling."""
        if not vendor_class:
            return None
            
        vc_lower = vendor_class.lower()
        mfg_lower = manufacturer.lower() if manufacturer else ''
        
        # DHCP Client Pattern Analysis with Manufacturer Context
        
        # 1. Linux Embedded/Router DHCP Clients
        embedded_dhcp_patterns = ['udhcp', 'busybox', 'busybox-dhcp', 'dropbear']
        if any(pattern in vc_lower for pattern in embedded_dhcp_patterns):
            # Context-dependent classification
            networking_vendors = ['tp-link', 'zyxel', 'netgear', 'd-link', 'linksys', 'belkin', 'tenda']
            if any(net in mfg_lower for net in networking_vendors):
                return 'Network Device'
            # Could be IoT device with embedded Linux
            return 'IoT Device'
        
        # 2. Standard Linux DHCP Clients
        linux_dhcp_patterns = ['dhcpcd', 'dhclient', 'networkmanager', 'systemd']
        if any(pattern in vc_lower for pattern in linux_dhcp_patterns):
            # Context-dependent classification
            if 'raspberry pi' in mfg_lower or 'espressif' in mfg_lower:
                return 'Single Board Computer'
            elif any(net in mfg_lower for net in ['ubiquiti', 'mikrotik']):
                return 'Network Device'
            # Default to computer for standard Linux DHCP
            return 'Computer'
        
        # 3. Android DHCP Patterns (version-specific) - CONTEXT DEPENDENT
        android_patterns = ['android-dhcp', 'android_dhcp']
        if any(pattern in vc_lower for pattern in android_patterns):
            # EDGE CASE: Component manufacturers with Android DHCP clients
            # Intel NICs in computers running Android emulation or dual-boot
            component_manufacturers = ['intel', 'realtek', 'broadcom', 'nvidia', 'amd']
            if any(comp in mfg_lower for comp in component_manufacturers):
                # Component manufacturer + Android DHCP = Computer with Android emulation
                return 'Computer'
            
            # Extract Android version if present for real mobile devices
            if 'android-dhcp-' in vc_lower:
                # Check manufacturer context for mobile vs embedded
                mobile_manufacturers = ['samsung', 'google', 'huawei', 'xiaomi', 'oneplus', 'lg electronics']
                if any(mobile in mfg_lower for mobile in mobile_manufacturers):
                    return 'Phone'
                # Could be Android TV or embedded device
                return 'IoT Device'  # Conservative for unknown Android devices
            elif 'android-tv' in vc_lower:
                return 'Smart TV'
            else:
                return 'Phone'  # Default Android = phone for known mobile vendors
        
        # 4. Apple DHCP Patterns
        apple_patterns = ['apple', 'aaplbm', 'aaplphone', 'ios-dhcp']
        if any(pattern in vc_lower for pattern in apple_patterns):
            if 'phone' in vc_lower or 'ios' in vc_lower:
                return 'Phone'
            elif 'tv' in vc_lower:
                return 'Streaming Device'
            else:
                return 'Computer'  # Default Apple = computer
        
        # 5. Microsoft/Windows DHCP Patterns
        windows_patterns = ['msft', 'microsoft']
        if any(pattern in vc_lower for pattern in windows_patterns):
            # Check version patterns
            if any(version in vc_lower for version in ['5.0', '6.0', '10.0']):
                return 'Computer'
            return 'Computer'
        
        # 6. Gaming Console Patterns
        gaming_patterns = ['playstation', 'xbox', 'nintendo']
        if any(pattern in vc_lower for pattern in gaming_patterns):
            return 'Gaming Console'
        
        # 7. IoT/Embedded Specific Patterns
        iot_specific_patterns = ['esp32', 'esp8266', 'arduino', 'micropython', 'tasmota', 'nodemcu']
        if any(pattern in vc_lower for pattern in iot_specific_patterns):
            return 'IoT Device'
        
        # 8. Streaming Device Patterns
        streaming_patterns = ['roku', 'chromecast', 'firetv', 'appletv']
        if any(pattern in vc_lower for pattern in streaming_patterns):
            return 'Streaming Device'
        
        # 9. Printer Patterns
        printer_patterns = ['hp-print', 'canon-print', 'epson-print', 'brother-print']
        if any(pattern in vc_lower for pattern in printer_patterns):
            return 'Printer'
        
        # 10. Network Equipment Specific Patterns
        network_specific_patterns = ['openwrt', 'dd-wrt', 'tomato', 'pfsense', 'mikrotik']
        if any(pattern in vc_lower for pattern in network_specific_patterns):
            return 'Network Device'
        
        # 11. Virtual Machine Patterns
        vm_patterns = ['vmware', 'virtualbox', 'xen', 'kvm', 'hyper-v']
        if any(pattern in vc_lower for pattern in vm_patterns):
            return 'Virtual Machine'
        
        # 12. Edge Case: Generic or Unknown Patterns
        # If vendor class is very generic, rely on manufacturer context
        generic_patterns = ['dhcp', 'client', 'unknown']
        if any(pattern in vc_lower for pattern in generic_patterns) and manufacturer:
            # Fall back to manufacturer-based classification
            return self._classify_by_hardware_manufacturer_context(manufacturer, vendor_class)
        
        return None
    
    def classify_by_hostname(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract OS and device type from hostname."""
        if not hostname:
            return None, None
            
        os_detected = None
        device_type = None
        
        # Check hostname patterns for OS
        for pattern, os_name in self.hostname_patterns.items():
            if re.match(pattern, hostname):
                os_detected = os_name
                break
        
        # Check hostname patterns for device type
        for pattern, dev_type in self.device_type_patterns.items():
            if re.match(pattern, hostname):
                device_type = dev_type
                break
                
        return os_detected, device_type
    
    def classify_by_vendor_class(self, vendor_class: str) -> Optional[str]:
        """Extract OS from vendor class."""
        if not vendor_class:
            return None
            
        for pattern, os_name in self.vendor_class_patterns.items():
            if re.match(pattern, vendor_class):
                return os_name
        
        return None
    
    def classify_by_dhcp_fingerprint(self, dhcp_fingerprint: str) -> Optional[str]:
        """Extract OS from DHCP fingerprint pattern."""
        if not dhcp_fingerprint:
            return None
            
        # Remove spaces and normalize
        fp = dhcp_fingerprint.replace(' ', '')
        
        for pattern, os_name in self.dhcp_fingerprint_patterns.items():
            if fp == pattern:
                return os_name
        
        return None
    
    def enhanced_classification(self, hostname: str, vendor_class: str, 
                              dhcp_fingerprint: str, vendor: str) -> Dict:
        """
        Comprehensive classification using all available data with hostname prioritization.
        """
        result = {
            'operating_system': None,
            'device_type': None,
            'confidence': 'low',
            'method': 'fallback',
            'hostname_override': False
        }

        # Method 1: Hostname Analysis (HIGHEST PRIORITY when specific)
        hostname_os = None
        hostname_device_type = None
        hostname_confidence = 'low'
        
        if hostname:
            hostname_os, hostname_device_type = self.classify_by_hostname(hostname)
            
            # Check for high-specificity hostname patterns
            high_specificity_patterns = [
                r'(?i).*iphone.*', r'(?i).*ipad.*', r'(?i).*galaxy.*', r'(?i).*pixel.*',
                r'(?i).*ring.*camera.*', r'(?i).*nest.*thermostat.*', r'(?i).*chromecast.*',
                r'(?i).*firetv.*', r'(?i).*fire.*tv.*', r'(?i).*ps[0-9].*', r'(?i).*xbox.*',
                r'(?i).*printer.*', r'(?i).*hp.*print.*', r'(?i).*echo.*', r'(?i).*alexa.*',
                r'(?i).*smart.*tv.*', r'(?i).*smart-tv.*', r'(?i).*tv-.*', r'(?i).*-tv.*'
            ]
            
            for pattern in high_specificity_patterns:
                if re.match(pattern, hostname):
                    hostname_confidence = 'very_high'
                    break
            
            # Apply hostname results with appropriate confidence
            if hostname_device_type and hostname_confidence == 'very_high':
                result['device_type'] = hostname_device_type
                result['confidence'] = 'high'
                result['method'] = 'hostname_specific'
                result['hostname_override'] = True
            
            if hostname_os and hostname_confidence == 'very_high':
                result['operating_system'] = hostname_os
                if result['confidence'] != 'high':
                    result['confidence'] = 'medium'
                result['method'] = 'hostname_specific'

        # Method 2: DHCP Fingerprint (high confidence)
        if dhcp_fingerprint and not result['hostname_override']:
            os_from_fp = self.classify_by_dhcp_fingerprint(dhcp_fingerprint)
            if os_from_fp and not result['operating_system']:
                result['operating_system'] = os_from_fp
                result['confidence'] = 'high'
                result['method'] = 'dhcp_fingerprint'
        
        # Method 3: Vendor Class (high confidence) 
        if vendor_class and not result['hostname_override']:
            os_from_vc = self.classify_by_vendor_class(vendor_class)
            if os_from_vc and not result['operating_system']:
                result['operating_system'] = os_from_vc
                result['confidence'] = 'high'
                result['method'] = 'vendor_class'

        # Method 4: IoT Signatures (medium confidence)
        if not result['operating_system'] or not result['device_type']:
            os_from_iot, device_type_from_iot = self._classify_by_iot_signature(hostname, vendor)
            
            if not result['operating_system'] and os_from_iot:
                result['operating_system'] = os_from_iot
                if result['confidence'] == 'low':
                    result['confidence'] = 'medium'
                result['method'] = 'iot_signature'
                
            if not result['device_type'] and device_type_from_iot and not result['hostname_override']:
                result['device_type'] = device_type_from_iot

        # Method 5: Vendor-specific rules (medium confidence)
        if not result['operating_system'] or not result['device_type']:
            os_from_vendor, device_type_from_vendor = self._classify_by_vendor_rules(vendor)
            
            if not result['operating_system'] and os_from_vendor:
                result['operating_system'] = os_from_vendor
                if result['confidence'] == 'low':
                    result['confidence'] = 'medium'
                result['method'] = 'vendor_rules'
                
            if not result['device_type'] and device_type_from_vendor and not result['hostname_override']:
                result['device_type'] = device_type_from_vendor
        
        # Method 6: Hostname Analysis (medium confidence for remaining fields)
        if hostname and (not result['operating_system'] or not result['device_type']):
            if not result['operating_system'] and hostname_os:
                result['operating_system'] = hostname_os
                if result['confidence'] == 'low':
                    result['confidence'] = 'medium'
                result['method'] = 'hostname'
                
            if not result['device_type'] and hostname_device_type and not result['hostname_override']:
                result['device_type'] = hostname_device_type
        
        # Method 7: Vendor-based inference (lowest confidence)
        if not result['operating_system'] and vendor:
            if 'apple' in vendor.lower():
                result['operating_system'] = 'iOS/macOS'
                if result['confidence'] == 'low':
                    result['confidence'] = 'low'
                result['method'] = 'vendor_inference'
            elif 'microsoft' in vendor.lower():
                result['operating_system'] = 'Windows'
                if result['confidence'] == 'low':
                    result['confidence'] = 'low'
                result['method'] = 'vendor_inference'
            elif 'samsung' in vendor.lower() and not result['device_type']:
                result['operating_system'] = 'Android'
                if not result['hostname_override']:
                    result['device_type'] = 'Phone'
                if result['confidence'] == 'low':
                    result['confidence'] = 'medium'
                result['method'] = 'vendor_inference'
        
        # Method 8: Vendor Class Context Analysis (NEW)
        if not result['device_type'] and vendor_class:
            vc_device_type = self._analyze_vendor_class_context(vendor_class, vendor)
            if vc_device_type:
                result['device_type'] = vc_device_type
                if result['confidence'] == 'low':
                    result['confidence'] = 'medium'
                result['method'] = 'vendor_class_context'
        
        # Method 9: Hardware Manufacturer Context Analysis (NEW)
        if not result['device_type'] and vendor:
            hardware_type = self._classify_by_hardware_manufacturer_context(vendor, vendor_class)
            if hardware_type:
                result['device_type'] = hardware_type
                if result['confidence'] == 'low':
                    result['confidence'] = 'medium'
                result['method'] = 'hardware_manufacturer_context'
        
        # Method 10: Hostname-Vendor Conflict Resolution (NEW)
        if hostname and vendor and result['device_type']:
            conflict_resolution = self._resolve_hostname_vendor_conflicts(hostname, vendor, result['device_type'])
            if conflict_resolution and conflict_resolution != result['device_type']:
                result['device_type'] = conflict_resolution
                result['confidence'] = 'high'
                result['method'] = 'hostname_conflict_resolution'
                result['hostname_override'] = True
        
        return result

def test_enhanced_classifier():
    """Test the enhanced fallback classifier."""
    classifier = EnhancedFallbackClassifier()
    
    test_cases = [
        {
            'hostname': 'DESKTOP-WIN10',
            'vendor_class': 'MSFT 5.0',
            'dhcp_fingerprint': '1,15,3,6,44,46,47,31,33,121,249,43',
            'vendor': 'Microsoft'
        },
        {
            'hostname': 'MacBook-Pro',
            'vendor_class': 'AAPLBM',
            'dhcp_fingerprint': '1,121,3,6,15,119,252,95,44,46',
            'vendor': 'Apple'
        },
        {
            'hostname': 'android-samsung-galaxy',
            'vendor_class': 'android-dhcp-11',
            'dhcp_fingerprint': '1,3,6,15,26,28,51,58,59,43',
            'vendor': 'Samsung'
        },
        {
            'hostname': 'router',
            'vendor_class': None,
            'dhcp_fingerprint': None,
            'vendor': 'CIMSYS Inc'
        }
    ]
    
    print("Enhanced Fallback Classifier Test")
    print("=" * 40)
    
    for i, case in enumerate(test_cases, 1):
        result = classifier.enhanced_classification(
            case['hostname'], 
            case['vendor_class'],
            case['dhcp_fingerprint'],
            case['vendor']
        )
        
        print(f"Test {i}:")
        print(f"  Input: {case['hostname']}")
        print(f"  Result: {result}")
        print()

if __name__ == "__main__":
    test_enhanced_classifier()