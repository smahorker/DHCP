#!/usr/bin/env python3
"""
Test script for the optimized DHCP device analyzer.
Tests OUI vendor lookup + Fingerbank API integration.
"""

import os
import sys
import json
from dhcp_device_analyzer import OptimizedDHCPDeviceAnalyzer

def test_vendor_lookup():
    """Test OUI vendor lookup accuracy."""
    print("Testing OUI Vendor Lookup")
    print("=" * 30)
    
    # Test MAC addresses with known vendors
    test_macs = {
        "28:39:5e:f1:65:c1": "Samsung",  # Samsung Galaxy
        "a8:5e:45:48:18:2d": "Apple",    # MacBook Pro
        "00:d8:61:45:89:7a": "ASUSTek",  # ASUS
        "14:7d:da:5e:b9:23": "Apple",    # iPhone
        "f8:16:54:ab:cd:ef": "ASUSTek"   # ASUS router
    }
    
    analyzer = OptimizedDHCPDeviceAnalyzer()
    
    for mac, expected_vendor in test_macs.items():
        vendor_info = analyzer.vendor_lookup.lookup_vendor(mac)
        actual_vendor = vendor_info.get('vendor') if vendor_info else None
        
        status = "✓" if expected_vendor.lower() in (actual_vendor or "").lower() else "✗"
        print(f"{status} {mac} -> Expected: {expected_vendor}, Got: {actual_vendor}")
    
    print()

def test_dhcp_log_parsing():
    """Test DHCP log parsing with sample data."""
    print("Testing DHCP Log Parsing")
    print("=" * 30)
    
    analyzer = OptimizedDHCPDeviceAnalyzer()
    
    # Test with our sample log
    test_file = "test_logs/mixed_network_dhcp.log"
    
    if not os.path.exists(test_file):
        print(f"Test file not found: {test_file}")
        return
    
    try:
        results = analyzer.analyze_dhcp_log(test_file)
        
        print(f"Parsed {len(results)} devices:")
        for result in results:
            print(f"  MAC: {result.mac_address}")
            print(f"    Vendor: {result.vendor} ({result.vendor_confidence})")
            print(f"    Hostname: {result.hostname}")
            print(f"    DHCP FP: {result.dhcp_fingerprint}")
            print(f"    Vendor Class: {result.vendor_class}")
            print(f"    Classification: {result.classification}")
            print()
    
    except Exception as e:
        print(f"Error parsing log: {e}")
        import traceback
        traceback.print_exc()

def test_fingerbank_integration():
    """Test Fingerbank API integration (if API key available)."""
    print("Testing Fingerbank API Integration")
    print("=" * 35)
    
    # Check if API key is available
    api_key = os.getenv('FINGERBANK_API_KEY')
    if not api_key:
        print("No Fingerbank API key found. Set FINGERBANK_API_KEY environment variable.")
        print("Skipping Fingerbank tests.")
        return
    
    try:
        analyzer = OptimizedDHCPDeviceAnalyzer(fingerbank_api_key=api_key)
        
        # Test with sample log that includes Fingerbank calls
        test_file = "test_logs/mixed_network_dhcp.log"
        
        if not os.path.exists(test_file):
            print(f"Test file not found: {test_file}")
            return
        
        print("Analyzing with Fingerbank API...")
        results = analyzer.analyze_dhcp_log(test_file)
        
        print(f"Results with Fingerbank classification:")
        for result in results:
            print(f"  MAC: {result.mac_address}")
            print(f"    Vendor (OUI): {result.vendor}")
            print(f"    OS (Fingerbank): {result.operating_system}")
            print(f"    Device Type: {result.device_type}")
            print(f"    Device Name: {result.device_name}")
            print(f"    FB Confidence: {result.fingerbank_confidence}")
            print(f"    Combined: {result.classification}")
            print(f"    Overall Confidence: {result.overall_confidence}")
            if result.fingerbank_error:
                print(f"    Error: {result.fingerbank_error}")
            print()
        
        # Show API statistics
        if hasattr(analyzer, 'fingerbank_client') and analyzer.fingerbank_client:
            stats = analyzer.fingerbank_client.get_api_statistics()
            print("Fingerbank API Statistics:")
            print(f"  Total requests: {stats['total_requests']}")
            print(f"  Success rate: {stats['success_rate']:.1f}%")
            print(f"  Rate limit used: {stats['rate_limit_status']['hourly_used']}/{stats['rate_limit_status']['hourly_limit']}")
    
    except Exception as e:
        print(f"Fingerbank test failed: {e}")
        import traceback
        traceback.print_exc()

def test_accuracy_comparison():
    """Test accuracy comparison between methods."""
    print("Testing Accuracy Comparison")
    print("=" * 30)
    
    # Expected results for our test data
    expected_results = {
        "28:39:5e:f1:65:c1": {  # Samsung Galaxy
            "vendor": "Samsung",
            "os_keywords": ["android", "galaxy"],
            "device_type": "phone"
        },
        "a8:5e:45:48:18:2d": {  # MacBook Pro
            "vendor": "Apple",
            "os_keywords": ["mac", "macbook"],
            "device_type": "computer"
        },
        "00:d8:61:45:89:7a": {  # Windows PC
            "vendor": "ASUSTek",
            "os_keywords": ["windows"],
            "device_type": "computer"
        },
        "14:7d:da:5e:b9:23": {  # iPhone
            "vendor": "Apple",
            "os_keywords": ["ios", "iphone"],
            "device_type": "phone"
        }
    }
    
    analyzer = OptimizedDHCPDeviceAnalyzer()
    
    try:
        results = analyzer.analyze_dhcp_log("test_logs/mixed_network_dhcp.log")
        
        vendor_correct = 0
        os_detected = 0
        device_type_detected = 0
        
        for result in results:
            mac = result.mac_address
            if mac in expected_results:
                expected = expected_results[mac]
                
                # Check vendor accuracy
                if result.vendor and expected["vendor"].lower() in result.vendor.lower():
                    vendor_correct += 1
                    print(f"✓ Vendor correct for {mac}: {result.vendor}")
                else:
                    print(f"✗ Vendor incorrect for {mac}: got {result.vendor}, expected {expected['vendor']}")
                
                # Check OS detection
                if result.operating_system:
                    os_detected += 1
                    print(f"✓ OS detected for {mac}: {result.operating_system}")
                
                # Check device type
                if result.device_type:
                    device_type_detected += 1
                    print(f"✓ Device type detected for {mac}: {result.device_type}")
        
        total_devices = len(expected_results)
        print(f"\nAccuracy Summary:")
        print(f"  Vendor accuracy: {vendor_correct}/{total_devices} ({vendor_correct/total_devices*100:.1f}%)")
        print(f"  OS detection: {os_detected}/{total_devices} ({os_detected/total_devices*100:.1f}%)")
        print(f"  Device type detection: {device_type_detected}/{total_devices} ({device_type_detected/total_devices*100:.1f}%)")
    
    except Exception as e:
        print(f"Accuracy test failed: {e}")

def main():
    """Run all tests."""
    print("DHCP Device Analyzer Test Suite")
    print("=" * 40)
    print()
    
    # Test 1: OUI vendor lookup
    test_vendor_lookup()
    
    # Test 2: DHCP log parsing
    test_dhcp_log_parsing()
    
    # Test 3: Fingerbank integration (if API key available)
    test_fingerbank_integration()
    
    # Test 4: Accuracy comparison
    test_accuracy_comparison()
    
    print("Test suite completed!")

if __name__ == "__main__":
    main()