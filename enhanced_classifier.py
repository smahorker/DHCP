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

        self.iot_device_patterns = {
            # Smart Speakers
            r'(google|nest)(home|mini)': {'operating_system': 'Google Assistant', 'device_type': 'Smart Speaker'},
            r'(amazon|echo|alexa)': {'operating_system': 'Fire OS', 'device_type': 'Smart Speaker'},
            r'(homepod|apple.*speaker)': {'operating_system': 'audioOS', 'device_type': 'Smart Speaker'},

            # Smart Cameras
            r'(ring|doorbell)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},
            r'(nest|cam)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},
            r'(arlo)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},
            r'(wyze|cam)': {'operating_system': 'Linux', 'device_type': 'Smart Camera'},

            # Smart Thermostats
            r'(nest|thermostat)': {'operating_system': 'Linux', 'device_type': 'Smart Thermostat'},
            r'(ecobee)': {'operating_system': 'Linux', 'device_type': 'Smart Thermostat'},
            r'(honeywell)': {'operating_system': 'Linux', 'device_type': 'Smart Thermostat'},

            # Smart Plugs
            r'(tp-link|kasa|smart|plug)': {'operating_system': 'Linux', 'device_type': 'Smart Plug'},
            r'(wemo)': {'operating_system': 'Linux', 'device_type': 'Smart Plug'},

            # Smart Lighting
            r'(philips|hue)': {'operating_system': 'Linux', 'device_type': 'Smart Lighting'},
            r'(lifx)': {'operating_system': 'Linux', 'device_type': 'Smart Lighting'},
        }
    
    def _classify_by_iot_signature(self, hostname: str, vendor: str) -> Tuple[Optional[str], Optional[str]]:
        """Classify a device based on IoT device signatures."""
        if not hostname and not vendor:
            return None, None

        # Check hostname against IoT patterns
        if hostname:
            for pattern, classification in self.iot_device_patterns.items():
                if re.search(pattern, hostname, re.IGNORECASE):
                    return classification.get('operating_system'), classification.get('device_type')

        # Check vendor against IoT patterns
        if vendor:
            for pattern, classification in self.iot_device_patterns.items():
                if re.search(pattern, vendor, re.IGNORECASE):
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
                r'(?i).*printer.*', r'(?i).*hp.*print.*', r'(?i).*echo.*', r'(?i).*alexa.*'
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