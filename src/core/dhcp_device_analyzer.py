#!/usr/bin/env python3
"""
DHCP Device Analyzer - Fingerbank-First Implementation
Network Device Monitoring System with prioritized Fingerbank API classification
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path

# Import core components
from .dhcp_log_parser import DHCPLogParser, DHCPLogEntry
from .mac_vendor_lookup import MACVendorLookup
from .fingerbank_api import FingerbankAPIClient, DeviceFingerprint
from .enhanced_classifier import EnhancedFallbackClassifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeviceClassificationResult:
    """Complete device classification result with all available information."""
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    vendor_confidence: str = "unknown"
    device_type: Optional[str] = None
    device_name: Optional[str] = None
    operating_system: Optional[str] = None
    classification: Optional[str] = None
    dhcp_fingerprint: Optional[str] = None
    vendor_class: Optional[str] = None
    classification_method: str = "unknown"
    overall_confidence: str = "unknown"
    fingerbank_confidence: Optional[int] = None
    dhcp_fingerprint_confidence: Optional[str] = None
    fingerbank_error: Optional[str] = None
    timestamp: datetime = None

class DHCPFingerprintClassifier:
    """DHCP fingerprint-based device classification."""
    
    def __init__(self):
        """Initialize the DHCP fingerprint classifier."""
        pass
    
    def classify_by_fingerprint(self, fingerprint: str, vendor: str = None, 
                              vendor_class: str = None, hostname: str = None) -> tuple[Optional[str], str]:
        """Classify device based on DHCP fingerprint pattern."""
        if not fingerprint:
            return None, "none"
        
        options = fingerprint.split(',')
        option_count = len(options)
        
        # IoT device detection (minimal options)
        if option_count <= 3:
            return self._classify_minimal_device(vendor, vendor_class)
        elif option_count <= 6:
            return self._classify_smart_device(options, vendor, vendor_class)
        elif option_count >= 10:
            return self._classify_complex_device(options, vendor_class)
        else:  # 7-9 options - mobile devices
            return self._classify_mobile_device(options, vendor)
    
    def _classify_minimal_device(self, vendor: str = None, vendor_class: str = None) -> tuple[str, str]:
        """Classify devices with very minimal DHCP options (IoT)."""
        if vendor:
            vendor_lower = vendor.lower()
            if any(iot_vendor in vendor_lower for iot_vendor in ['espressif', 'murata']):
                return 'IoT Device', 'medium'
            elif 'philips' in vendor_lower:
                return 'Smart Lighting', 'medium'
        return 'IoT Device', 'low'
    
    def _classify_smart_device(self, options: list, vendor: str = None, 
                             vendor_class: str = None) -> tuple[Optional[str], str]:
        """Classify smart home/IoT devices with 4-6 options."""
        if vendor_class:
            vc_lower = vendor_class.lower()
            if any(gaming in vc_lower for gaming in ['ps5', 'nintendo', 'xbox']):
                return 'Gaming Console', 'high'
            elif any(streaming in vc_lower for streaming in ['roku', 'fire tv', 'chromecast']):
                return 'Streaming Device', 'high'
            elif any(smart in vc_lower for smart in ['ring', 'nest', 'hue']):
                return 'Smart Home Device', 'high'
        
        if vendor:
            vendor_lower = vendor.lower()
            if 'amazon' in vendor_lower:
                return 'Smart Speaker', 'medium'
            elif 'philips' in vendor_lower:
                return 'Smart Lighting', 'medium'
            elif 'nintendo' in vendor_lower:
                return 'Gaming Console', 'high'
        
        return 'Smart Home Device', 'low'
    
    def _classify_mobile_device(self, options: list, vendor: str = None) -> tuple[str, str]:
        """Classify mobile devices with 7-9 options."""
        if vendor:
            vendor_lower = vendor.lower()
            if 'apple' in vendor_lower:
                return 'Phone', 'high'
            elif any(mobile_vendor in vendor_lower for mobile_vendor in ['samsung', 'google', 'huawei']):
                return 'Phone', 'high'
        return 'Phone', 'medium'
    
    def _classify_complex_device(self, options: list, vendor_class: str = None) -> tuple[str, str]:
        """Classify complex devices with 10+ options (typically computers)."""
        if vendor_class:
            vc_lower = vendor_class.lower()
            if 'windows' in vc_lower or 'microsoft' in vc_lower:
                return 'Computer', 'high'
            elif 'dhcpcd' in vc_lower or 'linux' in vc_lower:
                return 'Computer', 'high'
        return 'Computer', 'medium'

class OptimizedDHCPDeviceAnalyzer:
    """Optimized DHCP device analyzer with Fingerbank-first classification."""
    
    def __init__(self, fingerbank_api_key: str = None):
        """Initialize the analyzer with all classification components."""
        self.dhcp_parser = DHCPLogParser()
        self.vendor_lookup = MACVendorLookup()
        self.dhcp_fingerprint_classifier = DHCPFingerprintClassifier()
        self.fallback_classifier = EnhancedFallbackClassifier()
        
        # Initialize Fingerbank API client if key provided
        self.fingerbank_client = None
        if fingerbank_api_key:
            try:
                self.fingerbank_client = FingerbankAPIClient(api_key=fingerbank_api_key)
                logger.info("Fingerbank API client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize Fingerbank API client: {e}")
        else:
            logger.info("No Fingerbank API key provided - using local classification only")
        
        # Classification statistics
        self.classification_stats = {
            'vendor_lookup_success': 0,
            'fingerbank_success': 0,
            'dhcp_fingerprint_success': 0,
            'fallback_success': 0,
            'total_devices': 0
        }
    
    def analyze_dhcp_log(self, log_file_path: str) -> List[DeviceClassificationResult]:
        """Analyze DHCP log and classify all devices."""
        logger.info(f"Starting analysis of DHCP log: {log_file_path}")
        
        # Parse DHCP log
        dhcp_entries = self.dhcp_parser.parse_log_file(log_file_path)
        logger.info(f"Parsed {len(dhcp_entries)} DHCP entries")
        
        # Group entries by device (MAC address)
        device_entries = self._group_entries_by_device(dhcp_entries)
        logger.info(f"Found {len(device_entries)} unique devices")
        
        # Classify each device
        results = []
        for mac_address, entries in device_entries.items():
            result = self._classify_device(mac_address, entries)
            results.append(result)
            self.classification_stats['total_devices'] += 1
        
        logger.info(f"Classification complete. Results: {len(results)} devices classified")
        return results
    
    def _group_entries_by_device(self, dhcp_entries: List[DHCPLogEntry]) -> Dict[str, List[DHCPLogEntry]]:
        """Group DHCP entries by MAC address (device)."""
        device_entries = {}
        for entry in dhcp_entries:
            mac = entry.mac_address
            if mac not in device_entries:
                device_entries[mac] = []
            device_entries[mac].append(entry)
        return device_entries
    
    def _get_best_entry(self, entries: List[DHCPLogEntry]) -> DHCPLogEntry:
        """Select the most informative DHCP entry for a device."""
        scored_entries = []
        for entry in entries:
            score = 0
            if entry.hostname:
                score += 3
            if entry.vendor_class:
                score += 2
            if entry.dhcp_fingerprint:
                score += 2
            if entry.message_type == 'ACK':
                score += 1
            scored_entries.append((score, entry))
        
        scored_entries.sort(key=lambda x: x[0], reverse=True)
        return scored_entries[0][1]
    
    def _classify_device(self, mac_address: str, entries: List[DHCPLogEntry]) -> DeviceClassificationResult:
        """
        Classify a single device using Fingerbank-first approach.
        
        New Classification Order:
        1. MAC Vendor Lookup (100% coverage)
        2. Fingerbank API (Primary classification method)
        3. Local Fallback Methods (Only if Fingerbank fails)
        """
        # Get the best entry for classification
        best_entry = self._get_best_entry(entries)
        
        # Initialize result
        result = DeviceClassificationResult(
            mac_address=mac_address,
            ip_address=best_entry.ip_address,
            hostname=best_entry.hostname,
            dhcp_fingerprint=best_entry.dhcp_fingerprint,
            vendor_class=best_entry.vendor_class,
            timestamp=datetime.now()
        )
        
        # Step 1: Vendor lookup (always succeeds)
        vendor_info = self.vendor_lookup.lookup_vendor(mac_address)
        if vendor_info and vendor_info.get('vendor'):
            result.vendor = vendor_info['vendor']
            result.vendor_confidence = vendor_info.get('confidence', 'unknown')
            self.classification_stats['vendor_lookup_success'] += 1
        
        # Step 2: Fingerbank API (Primary Classification Method)
        fingerbank_result = None
        fingerbank_classified = False
        
        if self.fingerbank_client:
            try:
                # Create device fingerprint for Fingerbank
                device_fingerprint = DeviceFingerprint(
                    mac_address=mac_address,
                    dhcp_fingerprint=best_entry.dhcp_fingerprint,
                    dhcp_vendor_class=best_entry.vendor_class,
                    hostname=best_entry.hostname
                )
                
                fingerbank_result = self.fingerbank_client.classify_device(device_fingerprint)
                
                # DIAGNOSTIC LOG: Analyze input data quality
                logger.info(f"DIAGNOSTIC [{mac_address}]: Input data quality assessment:")
                logger.info(f"  - Hostname: {'✓' if best_entry.hostname else '✗'} ({best_entry.hostname or 'None'})")
                logger.info(f"  - Vendor Class: {'✓' if best_entry.vendor_class else '✗'} ({best_entry.vendor_class or 'None'})")
                logger.info(f"  - DHCP Fingerprint: {'✓' if best_entry.dhcp_fingerprint else '✗'} ({best_entry.dhcp_fingerprint or 'None'})")
                logger.info(f"  - MAC Vendor: {result.vendor}")
                
                if fingerbank_result and not fingerbank_result.error_message:
                    result.fingerbank_confidence = fingerbank_result.confidence_score
                    result.device_name = fingerbank_result.device_name
                    
                    # Use Fingerbank classifications as primary
                    if fingerbank_result.device_type:
                        result.device_type = fingerbank_result.device_type
                        result.classification_method = "fingerbank"
                        fingerbank_classified = True
                    
                    if fingerbank_result.operating_system:
                        result.operating_system = fingerbank_result.operating_system
                    
                    self.classification_stats['fingerbank_success'] += 1
                    # DIAGNOSTIC LOG: Fingerbank result analysis
                    logger.info(f"DIAGNOSTIC [{mac_address}]: Fingerbank classification:")
                    logger.info(f"  - Device Name: {fingerbank_result.device_name}")
                    logger.info(f"  - Device Type: {fingerbank_result.device_type}")
                    logger.info(f"  - Confidence Score: {fingerbank_result.confidence_score}")
                    logger.info(f"  - Confidence Level: {fingerbank_result.confidence_level}")
                    
                    # DIAGNOSTIC LOG: Component manufacturer detection
                    component_manufacturers = ['intel', 'giga-byte', 'micro-star', 'asrock', 'nvidia', 'amd']
                    if any(comp in result.vendor.lower() for comp in component_manufacturers):
                        logger.warning(f"DIAGNOSTIC [{mac_address}]: Component manufacturer detected: {result.vendor}")
                        logger.warning(f"  - This may indicate hardware component, not device manufacturer")
                        logger.warning(f"  - Fingerbank classification may be unreliable")
                    
                    logger.debug(f"Fingerbank classified {mac_address}: {fingerbank_result.device_name}")
                else:
                    result.fingerbank_error = fingerbank_result.error_message if fingerbank_result else "No response"
                    
            except Exception as e:
                logger.warning(f"Fingerbank classification failed for {mac_address}: {e}")
                result.fingerbank_error = str(e)
        
        # Step 2.5: Intelligent Routing Decision (NEW - Enhanced vs Fingerbank)
        if fingerbank_classified:
            should_use_enhanced = self._should_route_to_enhanced_classifier(
                fingerbank_result, best_entry, result.vendor
            )
            
            logger.info(f"DIAGNOSTIC [{mac_address}]: Routing decision analysis:")
            logger.info(f"  - Fingerbank confidence: {fingerbank_result.confidence_score}")
            logger.info(f"  - Fingerbank device type: {fingerbank_result.device_type}")
            logger.info(f"  - Should route to enhanced: {should_use_enhanced}")
            
            if should_use_enhanced:
                # Route to enhanced classifier instead of accepting Fingerbank result
                enhanced_result = self._try_enhanced_classification_preferred(best_entry, result.vendor)
                if enhanced_result.get('device_type'):
                    # Use enhanced result instead of Fingerbank
                    result.device_type = enhanced_result['device_type']
                    result.operating_system = enhanced_result.get('operating_system', result.operating_system)
                    result.classification_method = f"enhanced_preferred_{enhanced_result.get('method', 'unknown')}"
                    result.overall_confidence = enhanced_result.get('confidence', 'medium')
                    logger.info(f"ENHANCED PREFERRED: {mac_address} reclassified as {result.device_type} (method: {enhanced_result.get('method')})")
                    self.classification_stats['fallback_success'] += 1  # Count as fallback success
                else:
                    logger.info(f"ENHANCED FAILED: {mac_address} falling back to Fingerbank result")
            
            # Step 2.6: Selective Fingerbank Override (for remaining cases)
            if not should_use_enhanced and best_entry.hostname:
                override_result = self._apply_selective_override(
                    fingerbank_result, best_entry.hostname, result.vendor, result.device_type
                )
                if override_result:
                    result.device_type = override_result['device_type']
                    result.operating_system = override_result.get('operating_system', result.operating_system)
                    result.classification_method = override_result['method']
                    result.overall_confidence = 'high'
                    logger.info(f"Fingerbank override: {mac_address} reclassified as {result.device_type} based on hostname '{best_entry.hostname}'")
        
        # Step 3: Local Fallback Classification (only if Fingerbank failed or unavailable)
        if not fingerbank_classified:
            # Try hostname-specific classification first
            if best_entry.hostname:
                fallback_result = self.fallback_classifier.enhanced_classification(
                    best_entry.hostname,
                    best_entry.vendor_class,
                    best_entry.dhcp_fingerprint,
                    result.vendor
                )
                
                if fallback_result.get('hostname_override') and fallback_result.get('device_type'):
                    result.device_type = fallback_result['device_type']
                    result.classification_method = "hostname_specific"
                    logger.info(f"Hostname fallback: {mac_address} classified as {result.device_type} based on hostname '{best_entry.hostname}'")
                    
                    if fallback_result.get('operating_system') and not result.operating_system:
                        result.operating_system = fallback_result['operating_system']
            
            # Try DHCP fingerprint classification if still no device type
            if not result.device_type and best_entry.dhcp_fingerprint:
                dhcp_device_type, dhcp_confidence = self.dhcp_fingerprint_classifier.classify_by_fingerprint(
                    best_entry.dhcp_fingerprint,
                    result.vendor,
                    best_entry.vendor_class,
                    best_entry.hostname
                )
                
                if dhcp_device_type:
                    result.device_type = dhcp_device_type
                    result.dhcp_fingerprint_confidence = dhcp_confidence
                    result.classification_method = "dhcp_fingerprint"
                    self.classification_stats['dhcp_fingerprint_success'] += 1
                    logger.debug(f"DHCP fingerprint fallback classified {mac_address} as {dhcp_device_type}")
            
            # Enhanced fallback for any remaining gaps
            if not result.device_type or not result.operating_system:
                fallback_result = self.fallback_classifier.enhanced_classification(
                    best_entry.hostname,
                    best_entry.vendor_class,
                    best_entry.dhcp_fingerprint,
                    result.vendor
                )
                
                if not result.device_type and fallback_result.get('device_type'):
                    result.device_type = fallback_result['device_type']
                    result.classification_method = "enhanced_fallback"
                    self.classification_stats['fallback_success'] += 1
                
                if not result.operating_system and fallback_result.get('operating_system'):
                    result.operating_system = fallback_result['operating_system']
        
        # Final result processing
        result.classification = f"{result.device_type or 'Unknown'}"
        result.overall_confidence = self._calculate_overall_confidence(result)
        
        return result
    
    def _should_route_to_enhanced_classifier(self, fingerbank_result, dhcp_entry, vendor: str) -> bool:
        """Determine if enhanced classifier should be used instead of low-confidence Fingerbank."""
        
        # Condition 1: Very low confidence Fingerbank results (primary routing condition)
        if fingerbank_result.confidence_score <= 40:
            logger.info(f"Routing condition 1: Low confidence ({fingerbank_result.confidence_score} ≤ 40)")
            return True
        
        # Condition 2: Hardware Manufacturer classifications (no specific device type)
        if (fingerbank_result.device_hierarchy and 
            'hardware manufacturer' in ' '.join(fingerbank_result.device_hierarchy).lower()):
            logger.info(f"Routing condition 2: Hardware manufacturer classification")
            return True
        
        # Condition 2b: Hardware Manufacturer in device name (alternative check)
        if (fingerbank_result.device_name and 
            'hardware manufacturer' in fingerbank_result.device_name.lower()):
            logger.info(f"Routing condition 2b: Hardware manufacturer in device name")
            return True
        
        # Condition 3: Strong hostname patterns that should always override (regardless of confidence)
        if (dhcp_entry.hostname and 
            self._has_critical_hostname_pattern(dhcp_entry.hostname)):
            logger.info(f"Routing condition 3: Critical hostname pattern override")
            return True
        
        # Condition 4: Minimal DHCP data with strong hostname patterns
        if (dhcp_entry.hostname and 
            fingerbank_result.confidence_score <= 50 and
            self._has_strong_hostname_pattern(dhcp_entry.hostname)):
            logger.info(f"Routing condition 4: Strong hostname pattern with moderate confidence")
            return True
        
        # Condition 5: Component manufacturers (often misclassified by Fingerbank)
        component_manufacturers = ['intel', 'giga-byte', 'micro-star', 'asrock', 'nvidia', 'amd']
        if (any(comp in vendor.lower() for comp in component_manufacturers) and
            fingerbank_result.confidence_score <= 60):
            logger.info(f"Routing condition 5: Component manufacturer with moderate confidence")
            return True
        
        # Condition 6: Network/embedded device vendor classes (enhanced classifier specializes in these)
        if (dhcp_entry.vendor_class and 
            any(pattern in dhcp_entry.vendor_class.lower() for pattern in ['udhcp', 'busybox', 'dhcpcd']) and
            fingerbank_result.confidence_score <= 55):
            logger.info(f"Routing condition 6: Network/embedded vendor class")
            return True
        
        return False
    
    def _has_critical_hostname_pattern(self, hostname: str) -> bool:
        """Check if hostname has critical patterns that should ALWAYS override Fingerbank."""
        hostname_lower = hostname.lower()
        
        # Patterns that are so clear they should override ANY Fingerbank confidence
        critical_patterns = [
            # Device type clearly specified in hostname
            'smart-tv', 'smart_tv', '-tv-', 'tv-', 'samsung-tv', 'lg-tv', 'sony-tv',
            'ring-camera', 'ring-doorbell', 'security-cam', 'ip-camera',
            'ps4-console', 'ps5-console', 'xbox-', 'nintendo-',
            'hp-printer', 'canon-printer', 'epson-printer', 'laser-printer',
            'nest-thermostat', 'smart-thermostat', 'ecobee',
            'firetv-stick', 'roku-stick', 'appletv', 'chromecast',
            'echo-dot', 'echo-show', 'google-home', 'homepod'
        ]
        
        return any(pattern in hostname_lower for pattern in critical_patterns)
    
    def _has_strong_hostname_pattern(self, hostname: str) -> bool:
        """Check if hostname has strong patterns that enhanced classifier handles well."""
        hostname_lower = hostname.lower()
        
        # High-confidence patterns that enhanced classifier excels at
        strong_patterns = [
            'ring-camera', 'ring-doorbell', 'nest-thermostat', 'nest-cam',
            'chromecast', 'firetv', 'fire-tv', 'roku', 'appletv',
            'ps4', 'ps5', 'xbox', 'nintendo', 'switch',
            'esp32', 'esp8266', 'raspberry', 'arduino',
            'printer', 'hp-print', 'canon-print', 'epson-print',
            'echo-', 'alexa-', 'google-home', 'homepod'
        ]
        
        return any(pattern in hostname_lower for pattern in strong_patterns)
    
    def _try_enhanced_classification_preferred(self, dhcp_entry, vendor: str) -> Dict:
        """Try enhanced classification as preferred method over Fingerbank."""
        
        enhanced_result = self.fallback_classifier.enhanced_classification(
            dhcp_entry.hostname,
            dhcp_entry.vendor_class,
            dhcp_entry.dhcp_fingerprint,
            vendor
        )
        
        logger.info(f"Enhanced classifier result: {enhanced_result}")
        
        # Accept enhanced result if it has reasonable confidence
        if enhanced_result.get('confidence') in ['high', 'very_high', 'medium']:
            if enhanced_result.get('device_type'):
                logger.info(f"Enhanced classifier providing: {enhanced_result['device_type']} (confidence: {enhanced_result.get('confidence')})")
                return enhanced_result
        
        # Even accept low confidence if method is hostname-specific (high accuracy)
        if (enhanced_result.get('method') in ['hostname_specific', 'iot_signature'] and
            enhanced_result.get('device_type')):
            logger.info(f"Enhanced classifier hostname-specific override: {enhanced_result['device_type']}")
            return enhanced_result
        
        logger.info(f"Enhanced classifier insufficient confidence/data")
        return {}
    
    def _apply_selective_override(self, fingerbank_result, hostname: str, vendor: str, current_device_type: str) -> Dict:
        """Selectively override Fingerbank results based on confidence and hostname patterns."""
        if not hostname or not fingerbank_result:
            return None
        
        hostname_lower = hostname.lower()
        
        # High-confidence hostname patterns that can override Fingerbank
        high_confidence_patterns = {
            # Smart Home/IoT devices with specific identifiers
            'Smart Camera': [
                'ring-camera', 'ring-doorbell', 'nest-cam', 'arlo-camera', 
                'wyze-cam', 'blink-camera', 'eufy-cam', 'security-camera'
            ],
            'Smart Speaker': [
                'echo-dot', 'echo-show', 'echo-studio', 'google-home', 
                'nest-mini', 'homepod', 'alexa-device'
            ],
            'Smart Thermostat': [
                'nest-thermostat', 'ecobee', 'honeywell-thermostat',
                'smart-thermostat'
            ],
            'Streaming Device': [
                'firetv-stick', 'fire-tv', 'roku-stick', 'chromecast',
                'appletv', 'nvidia-shield', 'streaming-stick'
            ],
            'Gaming Console': [
                'ps4-console', 'ps5-console', 'xbox-one', 'xbox-series',
                'nintendo-switch', 'playstation', 'gaming-console'
            ],
            'Printer': [
                'hp-printer', 'canon-printer', 'epson-printer', 'brother-printer',
                'laser-printer', 'inkjet-printer', 'network-printer'
            ],
            'Smart TV': [
                'smart-tv', 'samsung-tv', 'lg-tv', 'sony-tv',
                'android-tv', 'webos-tv'
            ],
            'Phone': [
                'iphone-', 'galaxy-s', 'pixel-', 'oneplus-',
                'huawei-p', 'xiaomi-mi'
            ]
        }
        
        # Check for high-confidence hostname patterns
        for device_type, patterns in high_confidence_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    # Only override if it's different from current classification
                    if device_type != current_device_type:
                        # Additional validation based on Fingerbank confidence
                        should_override = False
                        
                        # Always override if Fingerbank confidence is low (≤40)
                        if fingerbank_result.confidence_score <= 40:
                            should_override = True
                            reason = f"low_confidence_{fingerbank_result.confidence_score}"
                        
                        # Override moderate confidence (41-60) for clear device type conflicts
                        elif (fingerbank_result.confidence_score <= 60 and 
                              self._is_clear_device_conflict(current_device_type, device_type)):
                            should_override = True
                            reason = f"device_conflict_{fingerbank_result.confidence_score}"
                        
                        # Override high confidence (61+) only for very specific cases
                        elif (fingerbank_result.confidence_score > 60 and 
                              self._is_critical_override_case(hostname_lower, current_device_type, device_type)):
                            should_override = True
                            reason = f"critical_override_{fingerbank_result.confidence_score}"
                        
                        if should_override:
                            return {
                                'device_type': device_type,
                                'operating_system': self._infer_os_from_device_type(device_type, hostname_lower),
                                'method': f'fingerbank_override_{reason}'
                            }
        
        return None
    
    def _is_clear_device_conflict(self, fingerbank_type: str, hostname_type: str) -> bool:
        """Check if there's a clear conflict between Fingerbank and hostname device types."""
        # Define conflicting categories
        device_categories = {
            'mobile': ['Phone', 'Tablet'],
            'computer': ['Computer', 'Laptop', 'Desktop'],
            'smart_home': ['Smart Camera', 'Smart Speaker', 'Smart Thermostat', 'Smart TV'],
            'entertainment': ['Gaming Console', 'Streaming Device', 'Smart TV'],
            'network': ['Network Device', 'Router', 'Access Point'],
            'iot': ['IoT Device', 'Smart Camera', 'Smart Speaker', 'Smart Thermostat']
        }
        
        # Find categories for each type
        fingerbank_category = None
        hostname_category = None
        
        for category, types in device_categories.items():
            if fingerbank_type in types:
                fingerbank_category = category
            if hostname_type in types:
                hostname_category = category
        
        # Clear conflict if they're in different non-overlapping categories
        if (fingerbank_category and hostname_category and 
            fingerbank_category != hostname_category and
            not self._categories_overlap(fingerbank_category, hostname_category)):
            return True
        
        return False
    
    def _categories_overlap(self, cat1: str, cat2: str) -> bool:
        """Check if two device categories can overlap."""
        overlapping_pairs = [
            ('smart_home', 'iot'),
            ('entertainment', 'smart_home'),
            ('entertainment', 'iot')
        ]
        
        return (cat1, cat2) in overlapping_pairs or (cat2, cat1) in overlapping_pairs
    
    def _is_critical_override_case(self, hostname_lower: str, fingerbank_type: str, hostname_type: str) -> bool:
        """Check for critical cases where we should override even high-confidence Fingerbank results."""
        # Very specific device identifiers that are unlikely to be wrong
        critical_patterns = [
            'ring-camera', 'ring-doorbell',  # Ring devices are always cameras
            'ps4-console', 'ps5-console',     # PlayStation consoles
            'xbox-one', 'xbox-series',        # Xbox consoles
            'firetv-stick', 'roku-stick',     # Streaming devices
            'nest-thermostat',                # Nest thermostats
            'hp-printer', 'canon-printer'     # Specific printer models
        ]
        
        for pattern in critical_patterns:
            if pattern in hostname_lower:
                return True
        
        return False
    
    def _infer_os_from_device_type(self, device_type: str, hostname_lower: str) -> str:
        """Infer operating system from device type and hostname patterns."""
        os_mapping = {
            'Smart Camera': 'Linux',
            'Smart Speaker': 'Linux', 
            'Smart Thermostat': 'Linux',
            'Streaming Device': 'Android TV' if 'firetv' in hostname_lower else 'Linux',
            'Gaming Console': 'PlayStation OS' if any(ps in hostname_lower for ps in ['ps4', 'ps5', 'playstation']) 
                             else 'Xbox OS' if 'xbox' in hostname_lower 
                             else 'Nintendo OS',
            'Printer': 'Embedded OS',
            'Smart TV': 'Android TV' if 'android' in hostname_lower else 'webOS' if 'lg' in hostname_lower else 'Tizen',
            'Phone': 'iOS' if 'iphone' in hostname_lower else 'Android'
        }
        
        return os_mapping.get(device_type, 'Unknown')
    
    def _calculate_overall_confidence(self, result: DeviceClassificationResult) -> str:
        """Calculate overall confidence based on available information and methods."""
        confidence_score = 0
        
        # Vendor confidence
        if result.vendor:
            confidence_score += 20
        
        # Classification method confidence
        if result.classification_method == "fingerbank" and result.fingerbank_confidence:
            if result.fingerbank_confidence >= 80:
                confidence_score += 60
            elif result.fingerbank_confidence >= 60:
                confidence_score += 40
            else:
                confidence_score += 20
        elif result.classification_method == "hostname_specific":
            confidence_score += 50
        elif result.classification_method == "dhcp_fingerprint":
            if result.dhcp_fingerprint_confidence == "high":
                confidence_score += 40
            elif result.dhcp_fingerprint_confidence == "medium":
                confidence_score += 25
            else:
                confidence_score += 10
        elif result.classification_method == "enhanced_fallback":
            confidence_score += 15
        
        # Additional information bonus
        if result.hostname:
            confidence_score += 10
        if result.vendor_class:
            confidence_score += 10
        
        # Convert to categorical confidence
        if confidence_score >= 80:
            return "high"
        elif confidence_score >= 50:
            return "medium"
        elif confidence_score >= 30:
            return "low"
        else:
            return "unknown"
    
    def export_results(self, results: List[DeviceClassificationResult], output_file: str = None):
        """Export classification results to JSON file."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"results_{timestamp}.json"
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'total_devices': len(results),
            'classification_stats': self.classification_stats,
            'devices': [
                {
                    'mac_address': r.mac_address,
                    'ip_address': r.ip_address,
                    'hostname': r.hostname,
                    'vendor': r.vendor,
                    'device_type': r.device_type,
                    'device_name': r.device_name,
                    'operating_system': r.operating_system,
                    'classification': r.classification,
                    'classification_method': r.classification_method,
                    'overall_confidence': r.overall_confidence,
                    'fingerbank_confidence': r.fingerbank_confidence,
                    'dhcp_fingerprint_confidence': r.dhcp_fingerprint_confidence,
                    'fingerbank_error': r.fingerbank_error,
                    'dhcp_fingerprint': r.dhcp_fingerprint,
                    'vendor_class': r.vendor_class
                }
                for r in results
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Results exported to {output_file}")
        return output_file

def main():
    """Main function for testing the analyzer."""
    print("DHCP Device Analyzer - Fingerbank-First Implementation")
    print("=" * 60)
    
    # Get API key from environment
    api_key = os.getenv('FINGERBANK_API_KEY')
    if not api_key:
        print("Warning: No FINGERBANK_API_KEY found in environment variables")
        print("Local classification methods will be used as fallback")
    
    # Initialize analyzer
    analyzer = OptimizedDHCPDeviceAnalyzer(fingerbank_api_key=api_key)
    
    # Test with sample log file
    test_log = Path("test_logs/realistic_home_network.log")
    if test_log.exists():
        print(f"Analyzing test log: {test_log}")
        results = analyzer.analyze_dhcp_log(str(test_log))
        
        print(f"\nAnalysis complete: {len(results)} devices classified")
        print("\nClassification Statistics:")
        for method, count in analyzer.classification_stats.items():
            print(f"  {method}: {count}")
        
        # Export results
        output_file = analyzer.export_results(results)
        print(f"\nResults exported to: {output_file}")
        
        return results
    else:
        print(f"Test log file not found: {test_log}")
        return None

if __name__ == "__main__":
    main()