#!/usr/bin/env python3
"""
DHCP Packet Capture Engine for Network Device Monitoring System.
Phase 3: Capture DHCP packets from network interface in real-time.
Uses packet filtering to capture ONLY DHCP traffic - no other network traffic.
"""

import os
import sys
import time
import threading
import logging
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from .database import get_dhcp_store, get_database_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class DHCPPacketInfo:
    """Structured DHCP packet information."""
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vendor_class: Optional[str] = None
    dhcp_options: Dict = None
    message_type: Optional[str] = None
    packet_timestamp: datetime = None

class DHCPPacketCaptureEngine:
    """
    DHCP packet capture engine that runs in a separate thread.
    ONLY captures DHCP packets (UDP ports 67/68) - filters out all other traffic.
    """
    
    def __init__(self, interface: str = None, store_packets: bool = True):
        """
        Initialize DHCP packet capture engine.
        
        Args:
            interface: Network interface to capture on (auto-detect if None)
            store_packets: Whether to store packets in database
        """
        self.interface = interface or self._get_default_interface()
        self.store_packets = store_packets
        self.is_running = False
        self.capture_thread = None
        self.packet_count = 0
        self.error_count = 0
        self.start_time = None
        
        # DHCP packet filter - ONLY captures DHCP traffic
        self.packet_filter = "udp and (port 67 or port 68)"
        
        # Packet processing callback
        self.packet_callback: Optional[Callable] = None
        
        # Database store
        self.dhcp_store = get_dhcp_store() if store_packets else None
        
        logger.info(f"DHCP Packet Capture Engine initialized on interface: {self.interface}")
        logger.info(f"Packet filter: {self.packet_filter}")
    
    def _get_default_interface(self) -> str:
        """Get the default network interface for packet capture."""
        try:
            # Get the interface with default route
            interfaces = get_if_list()
            
            # Prefer eth0 if available, otherwise use first non-loopback interface
            for iface in interfaces:
                if iface.startswith('eth') or iface.startswith('wlan'):
                    return iface
            
            # Fall back to first non-loopback interface
            for iface in interfaces:
                if iface != 'lo' and not iface.startswith('docker'):
                    return iface
            
            return interfaces[0] if interfaces else 'eth0'
            
        except Exception as e:
            logger.warning(f"Could not auto-detect interface: {e}")
            return 'eth0'
    
    def set_packet_callback(self, callback: Callable[[DHCPPacketInfo], None]):
        """Set a callback function to process captured packets."""
        self.packet_callback = callback
    
    def _extract_dhcp_info(self, packet) -> Optional[DHCPPacketInfo]:
        """
        Extract DHCP information from a captured packet.
        Only processes DHCP REQUEST and DHCP ACK packets as specified in Phase 3.
        """
        try:
            if not packet.haslayer(DHCP):
                return None
            
            dhcp_layer = packet[DHCP]
            bootp_layer = packet[BOOTP]
            
            # Extract DHCP message type
            message_type = None
            dhcp_options = {}
            
            for option in dhcp_layer.options:
                if isinstance(option, tuple) and len(option) == 2:
                    option_code, option_value = option
                    
                    if option_code == "message-type":
                        message_type = option_value
                    elif option_code == "hostname":
                        dhcp_options["option_12"] = option_value.decode('utf-8', errors='ignore')
                    elif option_code == "vendor_class_id":
                        dhcp_options["option_60"] = option_value.decode('utf-8', errors='ignore')
                    elif option_code == "param_req_list":
                        # Option 55: Parameter Request List - key for OS fingerprinting
                        dhcp_options["option_55"] = ','.join(str(x) for x in option_value)
                    elif option_code == "client_FQDN":
                        dhcp_options["option_81"] = option_value.decode('utf-8', errors='ignore')
                    else:
                        # Store other options for potential future use
                        dhcp_options[f"option_{option_code}"] = str(option_value)
            
            # Focus on DHCP REQUEST and DHCP ACK packets as specified
            if message_type not in [3, 5]:  # 3=REQUEST, 5=ACK
                return None
            
            # Extract MAC address from Ethernet header (client hardware address)
            mac_address = None
            if packet.haslayer(Ether):
                mac_address = packet[Ether].src
            elif bootp_layer.chaddr:
                # Extract MAC from BOOTP client hardware address
                mac_bytes = bootp_layer.chaddr[:6]
                mac_address = ':'.join(['%02x' % b for b in mac_bytes])
            
            if not mac_address or mac_address == "00:00:00:00:00:00":
                return None
            
            # Extract IP address assignment
            ip_address = None
            if packet.haslayer(IP):
                if message_type == 3:  # REQUEST
                    ip_address = packet[IP].src if packet[IP].src != "0.0.0.0" else None
                elif message_type == 5:  # ACK
                    ip_address = bootp_layer.yiaddr
            
            # Extract hostname and vendor class from options
            hostname = dhcp_options.get("option_12")
            vendor_class = dhcp_options.get("option_60")
            
            return DHCPPacketInfo(
                mac_address=mac_address,
                ip_address=ip_address,
                hostname=hostname,
                vendor_class=vendor_class,
                dhcp_options=dhcp_options,
                message_type="REQUEST" if message_type == 3 else "ACK",
                packet_timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Error extracting DHCP info: {e}")
            self.error_count += 1
            return None
    
    def _process_packet(self, packet):
        """Process a captured DHCP packet."""
        try:
            dhcp_info = self._extract_dhcp_info(packet)
            
            if dhcp_info:
                self.packet_count += 1
                
                logger.info(f"DHCP {dhcp_info.message_type}: {dhcp_info.mac_address} -> {dhcp_info.ip_address}")
                
                # Store in database if enabled
                if self.store_packets and self.dhcp_store:
                    try:
                        self.dhcp_store.insert_raw_packet(
                            mac_address=dhcp_info.mac_address,
                            ip_address=dhcp_info.ip_address,
                            hostname=dhcp_info.hostname,
                            vendor_class=dhcp_info.vendor_class,
                            dhcp_options=dhcp_info.dhcp_options
                        )
                    except Exception as e:
                        logger.error(f"Failed to store packet in database: {e}")
                
                # Call user callback if set
                if self.packet_callback:
                    try:
                        self.packet_callback(dhcp_info)
                    except Exception as e:
                        logger.error(f"Packet callback error: {e}")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            self.error_count += 1
    
    def _capture_loop(self):
        """Main packet capture loop that runs in separate thread."""
        logger.info(f"Starting DHCP packet capture on {self.interface}")
        logger.info(f"Filter: {self.packet_filter} (DHCP ONLY - no other network traffic)")
        
        try:
            # Start packet capture with DHCP filter
            sniff(
                iface=self.interface,
                filter=self.packet_filter,  # ONLY DHCP packets
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_running,
                timeout=1  # Check stop condition every second
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
        finally:
            logger.info("DHCP packet capture stopped")
    
    def start(self):
        """Start the DHCP packet capture engine."""
        if self.is_running:
            logger.warning("Packet capture is already running")
            return
        
        self.is_running = True
        self.start_time = datetime.now()
        self.packet_count = 0
        self.error_count = 0
        
        # Start capture in separate thread to avoid blocking main application
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        
        logger.info("DHCP packet capture engine started")
    
    def stop(self):
        """Stop the DHCP packet capture engine."""
        if not self.is_running:
            logger.warning("Packet capture is not running")
            return
        
        self.is_running = False
        
        # Wait for capture thread to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        logger.info("DHCP packet capture engine stopped")
    
    def get_statistics(self) -> Dict:
        """Get packet capture statistics."""
        runtime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            "is_running": self.is_running,
            "interface": self.interface,
            "packet_filter": self.packet_filter,
            "packets_captured": self.packet_count,
            "errors_encountered": self.error_count,
            "runtime_seconds": runtime,
            "packets_per_minute": (self.packet_count / runtime * 60) if runtime > 0 else 0,
            "start_time": self.start_time.isoformat() if self.start_time else None
        }
    
    def is_capture_running(self) -> bool:
        """Check if packet capture is currently running."""
        return self.is_running

def main():
    """Test the DHCP packet capture engine."""
    print("DHCP Packet Capture Engine Test")
    print("=" * 40)
    print("This will capture ONLY DHCP packets (UDP ports 67/68)")
    print("Your network traffic and other activity will NOT be captured")
    print()
    
    # Initialize capture engine
    capture_engine = DHCPPacketCaptureEngine(store_packets=False)
    
    # Set up packet callback for testing
    def packet_callback(dhcp_info: DHCPPacketInfo):
        print(f"Captured DHCP {dhcp_info.message_type}:")
        print(f"  MAC: {dhcp_info.mac_address}")
        print(f"  IP: {dhcp_info.ip_address}")
        print(f"  Hostname: {dhcp_info.hostname}")
        print(f"  Vendor: {dhcp_info.vendor_class}")
        print(f"  Options: {len(dhcp_info.dhcp_options)} DHCP options")
        print()
    
    capture_engine.set_packet_callback(packet_callback)
    
    try:
        # Start capture
        capture_engine.start()
        
        print("DHCP packet capture started. Waiting for DHCP traffic...")
        print("Press Ctrl+C to stop")
        print()
        
        # Run for a while or until interrupted
        while True:
            time.sleep(10)
            stats = capture_engine.get_statistics()
            print(f"Stats: {stats['packets_captured']} packets, {stats['errors_encountered']} errors")
    
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        capture_engine.stop()
        stats = capture_engine.get_statistics()
        print(f"\nFinal statistics: {stats}")

if __name__ == "__main__":
    main()