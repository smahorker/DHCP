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
                    logger.debug(f"Fingerbank classified {mac_address}: {fingerbank_result.device_name}")
                else:
                    result.fingerbank_error = fingerbank_result.error_message if fingerbank_result else "No response"
                    
            except Exception as e:
                logger.warning(f"Fingerbank classification failed for {mac_address}: {e}")
                result.fingerbank_error = str(e)
        
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