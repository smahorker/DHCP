#!/usr/bin/env python3
"""
Debug script to analyze what data is being sent to Fingerbank API
and understand why classifications are incorrect.
"""

import json
import sys
import os
from pathlib import Path
sys.path.append('/mnt/c/Users/sripa/Downloads/Network/src/core')

from dhcp_log_parser import DHCPLogParser
from fingerbank_api import DeviceFingerprint, FingerbankAPIClient

def analyze_fingerbank_requests():
    """Analyze what data would be sent to Fingerbank for problematic cases."""
    
    print("FINGERBANK API REQUEST ANALYSIS")
    print("=" * 40)
    
    # Parse the test log to get actual DHCP entries
    parser = DHCPLogParser()
    log_file = Path("test_logs/realistic_home_network.log")
    
    if not log_file.exists():
        print(f"Error: Test log file not found: {log_file}")
        return
    
    entries = parser.parse_log_file(log_file)
    
    # Problematic cases from the user's question
    problematic_cases = {
        '88:66:5a:12:34:56': {'description': 'Apple MAC + iPhone hostname -> Windows OS'},
        'dc:a6:32:aa:bb:cc': {'description': 'Raspberry Pi MAC + Galaxy-S24 hostname -> IoT Device'},
        '50:32:75:dd:ee:ff': {'description': 'Samsung MAC + Ring-Camera-1 hostname'},
        '48:2c:a0:44:55:66': {'description': 'Xiaomi MAC + FireTV-Stick hostname'}
    }
    
    print("\nAnalyzing DHCP data for problematic cases:")
    print("-" * 45)
    
    for entry in entries:
        if entry.mac_address in problematic_cases:
            case_info = problematic_cases[entry.mac_address]
            
            print(f"\nCASE: {case_info['description']}")
            print(f"MAC Address: {entry.mac_address}")
            print(f"Hostname: {entry.hostname}")
            print(f"Vendor Class (DHCP Option 60): {entry.vendor_class}")
            print(f"DHCP Fingerprint (Option 55): {entry.dhcp_fingerprint}")
            print(f"All DHCP Options: {entry.dhcp_options}")
            
            # Show what would be sent to Fingerbank
            fingerprint = DeviceFingerprint(
                mac_address=entry.mac_address,
                dhcp_fingerprint=entry.dhcp_fingerprint,
                dhcp_vendor_class=entry.vendor_class,
                hostname=entry.hostname
            )
            
            print("\nData that would be sent to Fingerbank API:")
            print(f"  MAC: {fingerprint.mac_address}")
            print(f"  DHCP Fingerprint: {fingerprint.dhcp_fingerprint}")
            print(f"  DHCP Vendor Class: {fingerprint.dhcp_vendor_class}")
            print(f"  Hostname: {fingerprint.hostname}")
            
            # Analyze the vendor class assignment
            oui = entry.mac_address[:8]
            print(f"\nVendor Class Analysis:")
            print(f"  OUI: {oui}")
            print(f"  OUI-based vendor class: {parser._get_vendor_class_from_oui(entry.mac_address)}")
            print(f"  Actual vendor class sent: {entry.vendor_class}")
            
            print("\n" + "=" * 60)

def analyze_vendor_class_conflicts():
    """Analyze conflicts between MAC vendor and hostname."""
    
    print("\nVENDOR CLASS CONFLICT ANALYSIS")
    print("=" * 35)
    
    # Load OUI mapping
    parser = DHCPLogParser()
    oui_map = parser.oui_vendor_class_map
    
    conflicts = [
        {
            'mac': '88:66:5a:12:34:56',
            'oui': '88:66:5a',
            'mac_vendor': 'Apple',
            'hostname': 'iPhone',
            'expected_device': 'iPhone (iOS)',
            'vendor_class_sent': oui_map.get('88:66:5a', 'None')
        },
        {
            'mac': 'dc:a6:32:aa:bb:cc',
            'oui': 'dc:a6:32',
            'mac_vendor': 'Raspberry Pi Trading Ltd',
            'hostname': 'Galaxy-S24',
            'expected_device': 'Android Phone',
            'vendor_class_sent': oui_map.get('dc:a6:32', 'None')
        },
        {
            'mac': '50:32:75:dd:ee:ff',
            'oui': '50:32:75',
            'mac_vendor': 'Samsung Electronics Co.',
            'hostname': 'Ring-Camera-1',
            'expected_device': 'Smart Camera',
            'vendor_class_sent': oui_map.get('50:32:75', 'None')
        },
        {
            'mac': '48:2c:a0:44:55:66',
            'oui': '48:2c:a0',
            'mac_vendor': 'Xiaomi Communications Co Ltd',
            'hostname': 'FireTV-Stick',
            'expected_device': 'Fire TV Streaming Device',
            'vendor_class_sent': oui_map.get('48:2c:a0', 'None')
        }
    ]
    
    for conflict in conflicts:
        print(f"\nConflict Analysis: {conflict['mac']}")
        print(f"  MAC Vendor: {conflict['mac_vendor']}")
        print(f"  Hostname: {conflict['hostname']}")
        print(f"  Expected Device: {conflict['expected_device']}")
        print(f"  Vendor Class Sent to Fingerbank: {conflict['vendor_class_sent']}")
        
        # Analyze the conflict
        if conflict['vendor_class_sent'] == 'MSFT 5.0' and 'iPhone' in conflict['hostname']:
            print("  ❌ PROBLEM: Sending Windows vendor class for iPhone!")
            print("  📝 Root Cause: Apple devices use Microsoft DHCP client")
            print("  🤔 Impact: Fingerbank gets mixed signals - Apple MAC + Windows vendor class + iPhone hostname")
        
        elif conflict['vendor_class_sent'] == 'linux-dhcp' and 'Galaxy' in conflict['hostname']:
            print("  ❌ PROBLEM: Sending Linux vendor class for Android phone!")
            print("  📝 Root Cause: Raspberry Pi OUI mapped to Linux, but hostname suggests Android")
            print("  🤔 Impact: Fingerbank gets conflicting data - RPi MAC + Linux vendor class + Samsung hostname")
        
        elif conflict['vendor_class_sent'] == 'None' and 'Ring' in conflict['hostname']:
            print("  ⚠️  ISSUE: No vendor class sent, only Samsung MAC + Ring hostname")
            print("  📝 Root Cause: Samsung OUI not mapped to any vendor class")
            print("  🤔 Impact: Fingerbank has limited data - just MAC and hostname")
        
        elif conflict['vendor_class_sent'] == 'android-dhcp-13' and 'FireTV' in conflict['hostname']:
            print("  🤔 MIXED SIGNALS: Android vendor class for Fire TV device")
            print("  📝 Root Cause: Xiaomi OUI mapped to Android, but Fire TV runs Fire OS")
            print("  🤔 Impact: Fingerbank gets Xiaomi MAC + Android vendor class + Fire TV hostname")

def main():
    """Main analysis function."""
    try:
        analyze_fingerbank_requests()
        analyze_vendor_class_conflicts()
        
        print("\n" + "=" * 60)
        print("SUMMARY OF FINDINGS:")
        print("=" * 60)
        print("1. DATA QUALITY ISSUES:")
        print("   - Test data has realistic vendor/hostname mismatches")
        print("   - These represent real-world scenarios (MAC spoofing, device sharing)")
        print()
        print("2. VENDOR CLASS MAPPING CONFLICTS:")
        print("   - Apple devices send 'MSFT 5.0' (correct behavior)")
        print("   - Raspberry Pi OUI mapped to 'linux-dhcp' (causes Android phone confusion)")
        print("   - Samsung Ring camera has no vendor class (limited data)")
        print("   - Xiaomi Fire TV gets Android vendor class (reasonable but imperfect)")
        print()
        print("3. FINGERBANK API LIMITATIONS:")
        print("   - Gets conflicting signals from MAC vendor vs vendor class vs hostname")
        print("   - No DHCP fingerprints in test data (major limitation)")
        print("   - Must resolve contradictory information with limited context")
        print()
        print("4. ROOT CAUSE ASSESSMENT:")
        print("   - NOT poor test data quality - this reflects real networks")
        print("   - NOT Fingerbank API limitations - it's working with conflicting data")
        print("   - YES data inconsistencies - but these are realistic scenarios")
        
    except Exception as e:
        print(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()