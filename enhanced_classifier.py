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
            
            # Linux/Unix patterns
            r'(?i).*ubuntu.*': 'Linux',
            r'(?i).*debian.*': 'Linux', 
            r'(?i).*linux.*': 'Linux',
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
        
        # Device type patterns
        self.device_type_patterns = {
            # Mobile devices
            r'(?i).*(iphone|galaxy|pixel|android|mobile|phone).*': 'Phone',
            r'(?i).*(ipad|tablet).*': 'Tablet',
            
            # Computers
            r'(?i).*(macbook|laptop|notebook).*': 'Laptop',
            r'(?i).*(desktop|pc|workstation|imac).*': 'Desktop',
            r'(?i).*(server).*': 'Server',
            
            # Network devices
            r'(?i).*(router|gateway|switch|access.?point).*': 'Network Device',
            r'(?i).*(printer|print).*': 'Printer',
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
            r'(apple|homepod)': {'operating_system': 'audioOS', 'device_type': 'Smart Speaker'},

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
        Comprehensive fallback classification using all available data.
        """
        result = {
            'operating_system': None,
            'device_type': None,
            'confidence': 'low',
            'method': 'fallback'
        }

        # Method 1: IoT Signatures (high confidence)
        os_from_iot, device_type_from_iot = self._classify_by_iot_signature(hostname, vendor)
        if os_from_iot:
            result['operating_system'] = os_from_iot
            result['confidence'] = 'high'
            result['method'] = 'iot_signature'
        if device_type_from_iot:
            result['device_type'] = device_type_from_iot
        
        # Method 2: DHCP Fingerprint (highest confidence)
        if not result['operating_system'] and dhcp_fingerprint:
            os_from_fp = self.classify_by_dhcp_fingerprint(dhcp_fingerprint)
            if os_from_fp:
                result['operating_system'] = os_from_fp
                result['confidence'] = 'high'
                result['method'] = 'dhcp_fingerprint'
        
        # Method 2: Vendor Class (medium confidence)
        if not result['operating_system'] and vendor_class:
            os_from_vc = self.classify_by_vendor_class(vendor_class)
            if os_from_vc:
                result['operating_system'] = os_from_vc
                result['confidence'] = 'medium'
                result['method'] = 'vendor_class'

        # Method 3: Vendor-specific rules (medium confidence)
        if not result['operating_system'] and vendor:
            os_from_vendor, device_type_from_vendor = self._classify_by_vendor_rules(vendor)
            if os_from_vendor:
                result['operating_system'] = os_from_vendor
                result['confidence'] = 'medium'
                result['method'] = 'vendor_rules'
            if not result['device_type'] and device_type_from_vendor:
                result['device_type'] = device_type_from_vendor
        
        # Method 4: Hostname Analysis (lower confidence)
        if hostname:
            os_from_hostname, device_type_from_hostname = self.classify_by_hostname(hostname)
            
            if not result['operating_system'] and os_from_hostname:
                result['operating_system'] = os_from_hostname
                result['confidence'] = 'medium' if result['confidence'] == 'low' else result['confidence']
                result['method'] = 'hostname'
                
            if not result['device_type'] and device_type_from_hostname:
                result['device_type'] = device_type_from_hostname
        
        # Method 4: Vendor-based inference (lowest confidence)
        if not result['operating_system'] and vendor:
            if 'apple' in vendor.lower():
                result['operating_system'] = 'iOS/macOS'
                result['confidence'] = 'low'
                result['method'] = 'vendor_inference'
            elif 'microsoft' in vendor.lower():
                result['operating_system'] = 'Windows'
                result['confidence'] = 'low'
                result['method'] = 'vendor_inference'
            elif 'samsung' in vendor.lower():
                result['operating_system'] = 'Android'
                result['device_type'] = 'Phone'
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