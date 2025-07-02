#!/usr/bin/env python3
"""
DHCP Device Analyzer - Main Integration Class
Combines DHCP parsing, vendor lookup, Fingerbank API, and DHCP fingerprinting
for comprehensive device classification.
"""

import os
import json
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime

# Import core components
from src.core.dhcp_log_parser import DHCPLogParser, DHCPLogEntry
from src.core.mac_vendor_lookup import MACVendorLookup
from src.core.fingerbank_api import FingerbankAPIClient, DeviceFingerprint, DeviceClassification
from enhanced_classifier import EnhancedFallbackClassifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeviceClassificationResult:
    """Comprehensive device classification result combining all methods."""
    # Core identification
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    
    # Vendor information (OUI-based)
    vendor: Optional[str] = None
    vendor_confidence: str = "unknown"
    
    # Device classification
    operating_system: Optional[str] = None
    device_type: Optional[str] = None
    device_name: Optional[str] = None
    
    # Combined classification
    classification: Optional[str] = None
    
    # Confidence scores
    fingerbank_confidence: Optional[int] = None
    dhcp_fingerprint_confidence: Optional[str] = None
    overall_confidence: str = "unknown"
    
    # Raw data
    dhcp_fingerprint: Optional[str] = None
    vendor_class: Optional[str] = None
    
    # Method tracking
    classification_method: Optional[str] = None
    fingerbank_error: Optional[str] = None
    
    # Additional metadata
    timestamp: datetime = None

class DHCPFingerprintClassifier:
    """DHCP fingerprinting classifier for device type detection."""
    
    def __init__(self):
        """Initialize DHCP fingerprint database."""
        # Known DHCP fingerprints mapped to device types
        self.fingerprint_database = {
            # Gaming Consoles (minimal options, gaming-specific patterns)
            '1,3,6,12,15,28': 'Gaming Console',  # PS5, Nintendo Switch
            '1,3,6,12,15,28,42': 'Gaming Console',  # Nintendo Switch with NTP
            
            # Smart Home Devices (very minimal options)
            '1,3,6,15,28': 'Smart Speaker',  # Amazon Echo
            '1,3,6,12': 'Smart Lighting',  # Philips Hue
            '1,3,6,15': 'Smart Camera',  # Ring doorbell
            '1,3,6,12,15': 'Streaming Device',  # Fire TV
            
            # IoT/Embedded devices (basic networking only)
            '1,3,6': 'IoT Device',
            '1,3': 'Basic IoT Device',
            
            # Mobile devices (battery optimized)
            '1,3,6,15,26,28,51,58,59,43': 'Android Phone',
            '1,3,6,15,26,28,51,58,59': 'Android Phone',
            '1,121,3,6,15,119,252,95,44,46': 'iOS Device',
            '1,3,6,15,119,95,252,44,46,47': 'Apple Device',
            
            # Computers (comprehensive options)
            '1,15,3,6,44,46,47,31,33,121,249,43': 'Windows Computer',
            '1,15,3,6,44,46,47,31,33,249,43': 'Windows Computer',
            '1,3,6,15,31,33,43,44,46,47,119,121,249,252': 'Windows Computer',
            '1,28,2,3,15,6,119,12,44,47,26,121,42': 'Linux Computer',  # Raspberry Pi pattern
            
            # Network devices
            '1,3,6,12,15,28,42': 'Network Device',
        }
        
        # Device type patterns based on fingerprint characteristics
        self.iot_indicators = {
            'very_minimal': ['1,3,6', '1,3', '1,6'],  # 2-3 options = IoT
            'minimal': ['1,3,6,15', '1,3,6,12', '1,3,6,15,28'],  # 4-5 options = Smart Home
            'mobile_optimized': ['1,3,6,15,26,28,51,58,59'],  # Battery optimized
            'comprehensive': []  # 10+ options = Computer
        }
        
        logger.info("DHCP Fingerprint Classifier initialized")
    
    def classify_by_fingerprint(self, dhcp_fingerprint: str, vendor: str = None, 
                              vendor_class: str = None, hostname: str = None) -> tuple[Optional[str], str]:
        """
        Classify device type by DHCP fingerprint with context integration.
        
        Returns:
            (device_type, confidence_level)
        """
        # Priority 1: Check vendor class + hostname for specific device identification
        specific_device = self._identify_specific_device(vendor_class, hostname)
        if specific_device:
            return specific_device, "very_high"
        
        if not dhcp_fingerprint:
            return None, "none"
        
        # Normalize fingerprint
        fp = dhcp_fingerprint.replace(' ', '').strip()
        
        # Direct fingerprint match (high confidence)
        if fp in self.fingerprint_database:
            device_type = self.fingerprint_database[fp]
            logger.debug(f"Direct fingerprint match: {fp} -> {device_type}")
            return device_type, "high"
        
        # Analyze fingerprint characteristics with context
        return self._analyze_fingerprint_pattern(fp, vendor, vendor_class, hostname)
    
    def _identify_specific_device(self, vendor_class: str = None, hostname: str = None) -> Optional[str]:
        """Identify specific devices from vendor class and hostname context."""
        if not vendor_class and not hostname:
            return None
        
        # Combine vendor class and hostname for analysis
        context_text = ' '.join(filter(None, [vendor_class or '', hostname or ''])).lower()
        
        # High-confidence specific device patterns
        specific_device_patterns = {
            # Gaming Consoles (very specific identifiers)
            'Gaming Console': [
                'ps5', 'playstation', 'xbox', 'nintendo', 'nintendo-switch', 
                'ps4', 'xbox one', 'xbox series'
            ],
            
            # Smart Speakers (specific product names)
            'Smart Speaker': [
                'echo', 'alexa', 'echo-studio', 'echo-dot', 'echo-show',
                'google-home', 'nest-mini', 'nest-audio', 'homepod'
            ],
            
            # Smart Cameras (security devices)
            'Smart Camera': [
                'ring', 'doorbell', 'ring-doorbell', 'nest-cam', 'arlo',
                'wyze-cam', 'blink', 'security-camera'
            ],
            
            # Smart Lighting
            'Smart Lighting': [
                'hue', 'philips-hue', 'hue-bridge', 'lifx', 'smart-bulb',
                'kasa-bulb', 'tp-link-bulb'
            ],
            
            # Smart Thermostats
            'Smart Thermostat': [
                'nest-thermostat', 'ecobee', 'honeywell-thermostat',
                'thermostat'
            ],
            
            # Streaming Devices
            'Streaming Device': [
                'fire-tv', 'roku', 'apple-tv', 'chromecast', 'nvidia-shield'
            ],
            
            # Smart Home Hubs
            'Smart Hub': [
                'smartthings', 'hubitat', 'wink-hub', 'vera'
            ]
        }
        
        # Check for specific device matches
        for device_type, patterns in specific_device_patterns.items():
            for pattern in patterns:
                if pattern in context_text:
                    logger.debug(f"Specific device identified: {device_type} (pattern: '{pattern}' in '{context_text}')")
                    return device_type
        
        return None
    
    def _get_os_from_context(self, vendor_class: str = None, hostname: str = None, device_type: str = None) -> Optional[str]:
        """Extract operating system from vendor class and context."""
        if not vendor_class and not hostname:
            return None
            
        context_text = ' '.join(filter(None, [vendor_class or '', hostname or ''])).lower()
        
        # OS detection patterns from vendor class and hostname
        os_patterns = {
            'PlayStation OS': ['ps5', 'ps4', 'playstation'],
            'Xbox OS': ['xbox'],
            'Nintendo OS': ['nintendo'],
            'Fire OS': ['fire-tv', 'amazon fire', 'fire tv'],
            'Android': ['android', 'galaxy'],
            'iOS': ['iphone', 'ipad'],
            'tvOS': ['apple-tv'],
            'Roku OS': ['roku'],
            'Linux': ['nest-thermostat', 'ring', 'hue', 'dhcpcd', 'raspberrypi'],
            'Embedded OS': ['thermostat', 'doorbell', 'camera'],
        }
        
        for os_name, patterns in os_patterns.items():
            for pattern in patterns:
                if pattern in context_text:
                    logger.debug(f"OS identified from context: {os_name} (pattern: '{pattern}')")
                    return os_name
        
        # Device type based OS inference
        if device_type:
            device_type_os_map = {
                'Gaming Console': 'Game Console OS',
                'Smart Speaker': 'Embedded OS',
                'Smart Camera': 'Linux',
                'Smart Lighting': 'Embedded OS',
                'Smart Thermostat': 'Embedded OS',
                'Streaming Device': 'Streaming OS',
                'IoT Device': 'Embedded OS'
            }
            return device_type_os_map.get(device_type)
        
        return None
    
    def _analyze_fingerprint_pattern(self, fingerprint: str, vendor: str = None, 
                                   vendor_class: str = None, hostname: str = None) -> tuple[Optional[str], str]:
        """Analyze fingerprint pattern to infer device type."""
        if not fingerprint:
            return None, "none"
        
        options = fingerprint.split(',')
        option_count = len(options)
        
        logger.debug(f"Analyzing fingerprint: {fingerprint} ({option_count} options)")
        
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
        # Check vendor class for specific device types
        if vendor_class:
            vc_lower = vendor_class.lower()
            if any(gaming in vc_lower for gaming in ['ps5', 'nintendo', 'xbox']):
                return 'Gaming Console', 'high'
            elif any(streaming in vc_lower for streaming in ['roku', 'fire tv', 'chromecast']):
                return 'Streaming Device', 'high'
            elif any(smart in vc_lower for smart in ['ring', 'nest', 'hue']):
                return 'Smart Home Device', 'high'
        
        # Check vendor for device category
        if vendor:
            vendor_lower = vendor.lower()
            if 'amazon' in vendor_lower:
                return 'Smart Speaker', 'medium'  # Echo devices
            elif 'philips' in vendor_lower:
                return 'Smart Lighting', 'medium'  # Hue devices
            elif 'nintendo' in vendor_lower:
                return 'Gaming Console', 'high'
        
        # Default for smart devices
        return 'Smart Home Device', 'low'
    
    def _classify_mobile_device(self, options: list, vendor: str = None) -> tuple[str, str]:
        """Classify mobile devices (7-9 options, battery optimized)."""
        # Check for mobile-specific options
        mobile_options = ['26', '28', '51', '58', '59']  # Mobile/battery related
        mobile_option_count = sum(1 for opt in mobile_options if opt in options)
        
        if mobile_option_count >= 3:
            if vendor and 'apple' in vendor.lower():
                return 'iOS Device', 'medium'
            else:
                return 'Android Phone', 'medium'
        
        return 'Mobile Device', 'low'
    
    def _classify_complex_device(self, options: list, vendor_class: str = None) -> tuple[str, str]:
        """Classify devices with many DHCP options (computers)."""
        # Check for Windows-specific options
        windows_options = ['44', '46', '47', '31', '33', '121', '249', '252']
        windows_option_count = sum(1 for opt in windows_options if opt in options)
        
        if windows_option_count >= 4:
            return 'Windows Computer', 'high'
        
        # Check vendor class
        if vendor_class:
            vc_lower = vendor_class.lower()
            if 'dhcpcd' in vc_lower or 'linux' in vc_lower:
                return 'Linux Computer', 'medium'
            elif 'msft' in vc_lower or 'microsoft' in vc_lower:
                return 'Windows Computer', 'high'
        
        return 'Computer', 'medium'

class OptimizedDHCPDeviceAnalyzer:
    """
    Main integration class combining all classification methods.
    Provides comprehensive device identification from DHCP logs.
    """
    
    def __init__(self, fingerbank_api_key: str = None):
        """Initialize the DHCP device analyzer."""
        logger.info("Initializing DHCP Device Analyzer")
        
        # Initialize core components
        self.dhcp_parser = DHCPLogParser()
        self.vendor_lookup = MACVendorLookup()
        self.fallback_classifier = EnhancedFallbackClassifier()
        self.dhcp_fingerprint_classifier = DHCPFingerprintClassifier()
        
        # Initialize Fingerbank client if API key provided
        self.fingerbank_client = None
        if fingerbank_api_key:
            try:
                self.fingerbank_client = FingerbankAPIClient(fingerbank_api_key)
                logger.info("Fingerbank API client initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize Fingerbank client: {e}")
        else:
            logger.info("No Fingerbank API key provided, using fallback classification only")
        
        # Statistics
        self.total_devices_processed = 0
        self.classification_stats = {
            'fingerbank_success': 0,
            'dhcp_fingerprint_success': 0,
            'fallback_success': 0,
            'vendor_lookup_success': 0
        }
        
        logger.info("DHCP Device Analyzer initialization complete")
    
    def analyze_dhcp_log(self, log_file_path: str) -> List[DeviceClassificationResult]:
        """
        Analyze DHCP log file and classify all devices.
        
        Args:
            log_file_path: Path to DHCP log file
            
        Returns:
            List of device classification results
        """
        logger.info(f"Analyzing DHCP log: {log_file_path}")
        
        try:
            # Parse DHCP log
            dhcp_entries = self.dhcp_parser.parse_log_file(log_file_path)
            if not dhcp_entries:
                logger.warning("No DHCP entries found in log file")
                return []
            
            logger.info(f"Found {len(dhcp_entries)} DHCP entries")
            
            # Group entries by device (MAC address)
            device_entries = self._group_entries_by_device(dhcp_entries)
            logger.info(f"Identified {len(device_entries)} unique devices")
            
            # Classify each device
            results = []
            for mac_address, entries in device_entries.items():
                try:
                    result = self._classify_device(mac_address, entries)
                    results.append(result)
                    self.total_devices_processed += 1
                except Exception as e:
                    logger.error(f"Error classifying device {mac_address}: {e}")
                    # Create error result
                    error_result = DeviceClassificationResult(
                        mac_address=mac_address,
                        classification=f"Classification failed: {e}",
                        overall_confidence="error",
                        timestamp=datetime.now()
                    )
                    results.append(error_result)
            
            logger.info(f"Successfully classified {len(results)} devices")
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing DHCP log: {e}")
            raise
    
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
        # Prefer entries with more information
        scored_entries = []
        
        for entry in entries:
            score = 0
            if entry.hostname:
                score += 3
            if entry.vendor_class:
                score += 2
            if entry.dhcp_fingerprint:
                score += 2
            if entry.message_type == 'ACK':  # Successful assignments
                score += 1
            
            scored_entries.append((score, entry))
        
        # Return highest scoring entry
        scored_entries.sort(key=lambda x: x[0], reverse=True)
        return scored_entries[0][1]
    
    def _classify_device(self, mac_address: str, entries: List[DHCPLogEntry]) -> DeviceClassificationResult:
        """
        Classify a single device using all available methods.
        
        Args:
            mac_address: Device MAC address
            entries: List of DHCP entries for this device
            
        Returns:
            Complete device classification result
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
        
        # Step 2: DHCP Fingerprint Classification
        dhcp_device_type = None
        dhcp_confidence = "none"
        
        if best_entry.dhcp_fingerprint:
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
                logger.debug(f"DHCP fingerprint classified {mac_address} as {dhcp_device_type}")
                
                # Get OS from context if not already set
                if not result.operating_system:
                    context_os = self.dhcp_fingerprint_classifier._get_os_from_context(
                        best_entry.vendor_class, best_entry.hostname, dhcp_device_type
                    )
                    if context_os:
                        result.operating_system = context_os
        
        # Step 3: Fingerbank API (if available and no very high-confidence result yet)
        fingerbank_result = None
        if self.fingerbank_client and dhcp_confidence not in ['very_high']:
            try:
                # Create device fingerprint for Fingerbank
                device_fingerprint = DeviceFingerprint(
                    mac_address=mac_address,
                    dhcp_fingerprint=best_entry.dhcp_fingerprint,
                    dhcp_vendor_class=best_entry.vendor_class,
                    hostname=best_entry.hostname
                )
                
                fingerbank_result = self.fingerbank_client.classify_device(device_fingerprint)
                
                if fingerbank_result and not fingerbank_result.error_message:
                    result.fingerbank_confidence = fingerbank_result.confidence_score
                    result.device_name = fingerbank_result.device_name
                    
                    # Use Fingerbank OS if we don't have one
                    if fingerbank_result.operating_system:
                        result.operating_system = fingerbank_result.operating_system
                    
                    # Use Fingerbank device type if we don't have high confidence from DHCP
                    if fingerbank_result.device_type and dhcp_confidence not in ['high']:
                        result.device_type = fingerbank_result.device_type
                        result.classification_method = "fingerbank"
                    
                    self.classification_stats['fingerbank_success'] += 1
                    logger.debug(f"Fingerbank classified {mac_address}: {fingerbank_result.device_name}")
                else:
                    result.fingerbank_error = fingerbank_result.error_message if fingerbank_result else "No response"
                    
            except Exception as e:
                logger.warning(f"Fingerbank classification failed for {mac_address}: {e}")
                result.fingerbank_error = str(e)
        
        # Step 4: Enhanced fallback classification
        if not result.device_type or not result.operating_system:
            fallback_result = self.fallback_classifier.enhanced_classification(
                best_entry.hostname,
                best_entry.vendor_class,
                best_entry.dhcp_fingerprint,
                result.vendor
            )
            
            if not result.operating_system and fallback_result.get('operating_system'):
                result.operating_system = fallback_result['operating_system']
            
            if not result.device_type and fallback_result.get('device_type'):
                result.device_type = fallback_result['device_type']
                result.classification_method = "fallback"
                self.classification_stats['fallback_success'] += 1
        
        # Step 5: Calculate overall confidence and create classification
        result.overall_confidence = self._calculate_overall_confidence(
            result, dhcp_confidence, fingerbank_result
        )
        
        result.classification = self._create_combined_classification(result)
        
        return result
    
    def _calculate_overall_confidence(self, result: DeviceClassificationResult, 
                                    dhcp_confidence: str, 
                                    fingerbank_result: Optional[DeviceClassification]) -> str:
        """Calculate overall confidence level for classification."""
        confidence_scores = []
        
        # Vendor confidence (always available)
        if result.vendor_confidence == 'high':
            confidence_scores.append(3)
        elif result.vendor_confidence in ['medium', 'moderate']:
            confidence_scores.append(2)
        else:
            confidence_scores.append(1)
        
        # DHCP fingerprint confidence
        if dhcp_confidence == 'very_high':
            confidence_scores.append(4)
        elif dhcp_confidence == 'high':
            confidence_scores.append(3)
        elif dhcp_confidence == 'medium':
            confidence_scores.append(2)
        elif dhcp_confidence == 'low':
            confidence_scores.append(1)
        
        # Fingerbank confidence
        if fingerbank_result and result.fingerbank_confidence:
            if result.fingerbank_confidence >= 75:
                confidence_scores.append(3)
            elif result.fingerbank_confidence >= 50:
                confidence_scores.append(2)
            else:
                confidence_scores.append(1)
        
        # Calculate average confidence
        if confidence_scores:
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            if avg_confidence >= 3.0:
                return "high"
            elif avg_confidence >= 2.0:
                return "medium"
            else:
                return "low"
        
        return "unknown"
    
    def _create_combined_classification(self, result: DeviceClassificationResult) -> str:
        """Create human-readable combined classification."""
        parts = []
        
        if result.vendor:
            parts.append(result.vendor)
        
        if result.device_type:
            parts.append(result.device_type)
        
        if result.operating_system:
            parts.append(result.operating_system)
        
        if result.device_name and result.device_name not in str(parts):
            parts.append(result.device_name)
        
        return " ".join(parts) if parts else "Unknown Device"
    
    def export_results(self, results: List[DeviceClassificationResult], output_file: str):
        """Export classification results to JSON file."""
        logger.info(f"Exporting {len(results)} results to {output_file}")
        
        # Convert results to JSON-serializable format
        export_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_devices': len(results),
                'analyzer_version': '3.0',
                'statistics': self.get_classification_statistics()
            },
            'devices': []
        }
        
        for result in results:
            device_data = {
                'mac_address': result.mac_address,
                'ip_address': result.ip_address,
                'hostname': result.hostname,
                'vendor': result.vendor,
                'vendor_confidence': result.vendor_confidence,
                'operating_system': result.operating_system,
                'device_type': result.device_type,
                'device_name': result.device_name,
                'classification': result.classification,
                'classification_method': result.classification_method,
                'overall_confidence': result.overall_confidence,
                'fingerbank_confidence': result.fingerbank_confidence,
                'dhcp_fingerprint': result.dhcp_fingerprint,
                'vendor_class': result.vendor_class,
                'fingerbank_error': result.fingerbank_error,
                'timestamp': result.timestamp.isoformat() if result.timestamp else None
            }
            export_data['devices'].append(device_data)
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results exported successfully to {output_file}")
    
    def get_classification_statistics(self) -> Dict[str, Any]:
        """Get classification statistics."""
        stats = {
            'total_devices_processed': self.total_devices_processed,
            'classification_methods': self.classification_stats.copy()
        }
        
        # Calculate success rates
        if self.total_devices_processed > 0:
            for method, count in self.classification_stats.items():
                rate = (count / self.total_devices_processed) * 100
                stats[f'{method}_rate'] = f"{rate:.1f}%"
        
        # Add component statistics
        if hasattr(self.dhcp_parser, 'get_statistics'):
            stats['dhcp_parser'] = self.dhcp_parser.get_statistics()
        
        if hasattr(self.vendor_lookup, 'get_vendor_statistics'):
            stats['vendor_lookup'] = self.vendor_lookup.get_vendor_statistics()
        
        if self.fingerbank_client and hasattr(self.fingerbank_client, 'get_api_statistics'):
            stats['fingerbank_api'] = self.fingerbank_client.get_api_statistics()
        
        return stats

def main():
    """Test the DHCP device analyzer."""
    print("DHCP Device Analyzer v3.0 Test")
    print("=" * 40)
    
    # Get API key from environment
    api_key = os.getenv('FINGERBANK_API_KEY')
    if api_key:
        print("✓ Fingerbank API key found")
    else:
        print("⚠ No Fingerbank API key - using fallback classification only")
    
    try:
        # Initialize analyzer
        analyzer = OptimizedDHCPDeviceAnalyzer(fingerbank_api_key=api_key)
        
        # Test with sample log
        test_file = "test_logs/realistic_home_network.log"
        if not os.path.exists(test_file):
            print(f"❌ Test file not found: {test_file}")
            return
        
        print(f"📊 Analyzing: {test_file}")
        results = analyzer.analyze_dhcp_log(test_file)
        
        # Display results
        print(f"\n🎯 Classification Results ({len(results)} devices):")
        print("-" * 60)
        
        for result in results:
            print(f"MAC: {result.mac_address}")
            print(f"  Vendor: {result.vendor} ({result.vendor_confidence})")
            print(f"  Device Type: {result.device_type}")
            print(f"  OS: {result.operating_system}")
            print(f"  Method: {result.classification_method}")
            print(f"  Confidence: {result.overall_confidence}")
            print(f"  Classification: {result.classification}")
            if result.fingerbank_error:
                print(f"  FB Error: {result.fingerbank_error}")
            print()
        
        # Export results
        output_file = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        analyzer.export_results(results, output_file)
        
        # Show statistics
        stats = analyzer.get_classification_statistics()
        print("📈 Classification Statistics:")
        print(f"  Total devices: {stats['total_devices_processed']}")
        print(f"  DHCP fingerprint success: {stats.get('dhcp_fingerprint_success_rate', '0%')}")
        if 'fingerbank_success_rate' in stats:
            print(f"  Fingerbank success: {stats['fingerbank_success_rate']}")
        print(f"  Fallback used: {stats.get('fallback_success_rate', '0%')}")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()