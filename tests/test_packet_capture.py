#!/usr/bin/env python3
"""
Packet capture test script for network monitoring system.
Tests Scapy functionality and DHCP packet capture capabilities.
"""

import os
import sys
import time
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

def test_scapy_import():
    """Test if Scapy is properly imported and functional."""
    
    print("Testing Scapy import and basic functionality...")
    
    try:
        # Test basic packet creation
        packet = Ether()/IP(dst="8.8.8.8")/UDP(dport=53)
        print("✓ Scapy packet creation successful")
        
        # Test packet field access
        if packet[IP].dst == "8.8.8.8":
            print("✓ Scapy packet field access working")
        
        return True
        
    except Exception as e:
        print(f"✗ Scapy test failed: {e}")
        return False

def get_network_interfaces():
    """Get available network interfaces."""
    
    print("Available network interfaces:")
    try:
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            addr = get_if_addr(iface) if get_if_addr(iface) != "0.0.0.0" else "No IP"
            print(f"  {i+1}. {iface} - {addr}")
        
        return interfaces
        
    except Exception as e:
        print(f"✗ Failed to get network interfaces: {e}")
        return []

def test_dhcp_packet_structure():
    """Test DHCP packet creation and parsing."""
    
    print("Testing DHCP packet structure...")
    
    try:
        # Create a sample DHCP Discover packet
        dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=b'\x00\x01\x02\x03\x04\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        
        print("✓ DHCP packet creation successful")
        
        # Test packet parsing
        if dhcp_discover.haslayer(DHCP):
            print("✓ DHCP layer detection working")
        
        if dhcp_discover.haslayer(BOOTP):
            chaddr = dhcp_discover[BOOTP].chaddr
            print(f"✓ MAC address extraction: {':'.join(['%02x' % b for b in chaddr[:6]])}")
        
        return True
        
    except Exception as e:
        print(f"✗ DHCP packet test failed: {e}")
        return False

def test_packet_capture_permissions():
    """Test if we have permissions for packet capture."""
    
    print("Testing packet capture permissions...")
    
    interfaces = get_network_interfaces()
    if not interfaces:
        return False
    
    # Try to capture on the first available interface
    test_iface = interfaces[0]
    
    try:
        print(f"Attempting packet capture on {test_iface} (5 second timeout)...")
        
        # Set a short timeout for testing
        packets = sniff(iface=test_iface, timeout=2, count=1)
        
        if packets:
            print(f"✓ Captured {len(packets)} packet(s)")
            print("✓ Packet capture permissions working")
            return True
        else:
            print("No packets captured in timeout period")
            print("✓ Packet capture setup working (no traffic detected)")
            return True
            
    except PermissionError:
        print("✗ Permission denied for packet capture")
        print("Note: Packet capture may require running as administrator/root")
        return False
    except Exception as e:
        print(f"✗ Packet capture test failed: {e}")
        return False

def main():
    print("Network Monitoring System - Packet Capture Test")
    print("=" * 52)
    
    success = True
    
    # Test Scapy functionality
    if not test_scapy_import():
        success = False
    
    print()
    
    # Show network interfaces
    interfaces = get_network_interfaces()
    if not interfaces:
        success = False
    
    print()
    
    # Test DHCP packet handling
    if not test_dhcp_packet_structure():
        success = False
    
    print()
    
    # Test packet capture permissions
    if not test_packet_capture_permissions():
        print("\nWarning: Packet capture permissions may be limited.")
        print("For full functionality, you may need to:")
        print("- Run the script as administrator/root")
        print("- Install WinPcap/Npcap on Windows")
        print("- Check firewall settings")
    
    print()
    
    if success:
        print("✓ Packet capture setup is ready!")
        return 0
    else:
        print("✗ Some packet capture tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())