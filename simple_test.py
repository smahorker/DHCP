#!/usr/bin/env python3
"""
Simple Test Script for DHCP Device Analyzer
Tests core functionality and outputs results to JSON
"""

import sys
import os
import json
import logging
from datetime import datetime

# Suppress logging output for cleaner test results
logging.basicConfig(level=logging.CRITICAL)
logging.getLogger().setLevel(logging.CRITICAL)

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from dhcp_device_analyzer import OptimizedDHCPDeviceAnalyzer
except ImportError:
    print("Error: Could not import DHCP Device Analyzer")
    sys.exit(1)

def export_json_results(devices, filename="test_results.json"):
    """Export results to JSON file"""
    if not devices:
        return None
    
    # Format devices for JSON export
    json_devices = []
    for device in devices:
        device_data = {
            'mac_address': getattr(device, 'mac_address', 'Unknown'),
            'vendor': getattr(device, 'vendor', 'Unknown'),
            'device_type': getattr(device, 'device_type', 'Unknown'),
            'operating_system': getattr(device, 'operating_system', 'Unknown'),
            'overall_confidence': getattr(device, 'overall_confidence', 'Unknown'),
            'classification_method': getattr(device, 'classification_method', 'Unknown'),
            'classification': getattr(device, 'classification', 'Unknown'),
            'vendor_confidence': getattr(device, 'vendor_confidence', 'Unknown'),
            'dhcp_fingerprint': getattr(device, 'dhcp_fingerprint', None),
            'vendor_class': getattr(device, 'vendor_class', None),
            'hostname': getattr(device, 'hostname', None),
            'ip_address': getattr(device, 'ip_address', None)
        }
        json_devices.append(device_data)
    
    # Create export data structure
    export_data = {
        'test_metadata': {
            'timestamp': datetime.now().isoformat(),
            'dataset_file': 'test_logs/dataset.log',
            'total_devices': len(json_devices),
            'analyzer_version': '3.0'
        },
        'statistics': {
            'confidence_distribution': {},
            'method_distribution': {},
            'vendor_distribution': {}
        },
        'devices': json_devices
    }
    
    # Calculate statistics
    for device in json_devices:
        conf = device['overall_confidence']
        method = device['classification_method']
        vendor = device['vendor']
        
        export_data['statistics']['confidence_distribution'][conf] = \
            export_data['statistics']['confidence_distribution'].get(conf, 0) + 1
        export_data['statistics']['method_distribution'][method] = \
            export_data['statistics']['method_distribution'].get(method, 0) + 1
        export_data['statistics']['vendor_distribution'][vendor] = \
            export_data['statistics']['vendor_distribution'].get(vendor, 0) + 1
    
    # Write to file
    with open(filename, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    return filename

def run_test():
    """Run the core functionality test"""
    dataset_path = "test_logs/dataset.log"
    
    if not os.path.exists(dataset_path):
        print("Error: Dataset file not found")
        return False
    
    try:
        # Initialize and run analyzer
        analyzer = OptimizedDHCPDeviceAnalyzer()
        results = analyzer.analyze_dhcp_log(dataset_path)
        
        if not results:
            print("Error: No results returned")
            return False
        
        # Export to JSON
        json_file = export_json_results(results)
        if json_file:
            print(f"Results exported to: {json_file}")
            return True
        else:
            print("Error: Failed to export results")
            return False
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    """Main entry point"""
    success = run_test()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()