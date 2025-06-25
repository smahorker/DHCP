#!/usr/bin/env python3
"""
DHCP Packet Parser for Network Device Monitoring System.
Phase 4: Process raw DHCP packets to extract device fingerprinting information.
"""

import json
import logging
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from .database import get_dhcp_store

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeviceFingerprint:
    """Structured device fingerprint data for Fingerbank API."""
    mac_address: str
    dhcp_fingerprint: Optional[str] = None  # Option 55: Parameter Request List
    dhcp_vendor_class: Optional[str] = None  # Option 60: Vendor Class Identifier
    hostname: Optional[str] = None  # Option 12: Hostname
    client_fqdn: Optional[str] = None  # Option 81: Client FQDN
    user_agent: Optional[str] = None
    vendor_specific_options: Dict = None

class DHCPPacketParser:
    """
    Parser for extracting device fingerprinting information from raw DHCP packets.
    Phase 4: DHCP Packet Parser implementation.
    """
    
    def __init__(self):
        """Initialize the DHCP packet parser."""
        self.dhcp_store = get_dhcp_store()
        self.processed_count = 0
        self.error_count = 0
        
        # DHCP option mappings for fingerprinting
        self.dhcp_option_names = {
            12: "hostname",
            55: "parameter_request_list", 
            60: "vendor_class_identifier",
            81: "client_fqdn",
            77: "user_class",
            125: "vendor_specific_info"
        }
    
    def _normalize_mac_address(self, mac_address: str) -> str:
        """
        Normalize MAC address to consistent format (aa:bb:cc:dd:ee:ff).
        Handles various MAC address formats.
        """
        if not mac_address:
            return None
        
        # Remove all non-hex characters
        clean_mac = re.sub(r'[^0-9a-fA-F]', '', mac_address.lower())
        
        # Ensure we have 12 hex characters
        if len(clean_mac) != 12:
            logger.warning(f"Invalid MAC address length: {mac_address}")
            return None
        
        # Format as aa:bb:cc:dd:ee:ff
        formatted_mac = ':'.join([clean_mac[i:i+2] for i in range(0, 12, 2)])
        return formatted_mac
    
    def _sanitize_hostname(self, hostname: str) -> str:
        """
        Sanitize hostname by removing special characters and normalizing.
        Handles encoding issues and malformed hostnames.
        """
        if not hostname:
            return None
        
        # Handle bytes objects
        if isinstance(hostname, bytes):
            try:
                hostname = hostname.decode('utf-8', errors='ignore')
            except:
                return None
        
        # Remove null bytes and control characters
        hostname = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(hostname))
        
        # Limit length and remove dangerous characters
        hostname = re.sub(r'[<>"\'\\/;]', '', hostname)
        hostname = hostname.strip()[:255]
        
        return hostname if hostname else None
    
    def _validate_ip_address(self, ip_address: str) -> Optional[str]:
        """Validate IP address format."""
        if not ip_address:
            return None
        
        # Basic IPv4 validation
        parts = str(ip_address).split('.')
        if len(parts) != 4:
            return None
        
        try:
            for part in parts:
                num = int(part)
                if not 0 <= num <= 255:
                    return None
            return ip_address
        except ValueError:
            return None
    
    def _extract_dhcp_options(self, dhcp_options_json: str) -> Dict:
        """
        Extract and parse DHCP options from JSON string.
        Phase 4: Extract key DHCP options for device fingerprinting.
        """
        if not dhcp_options_json:
            return {}
        
        try:
            if isinstance(dhcp_options_json, str):
                options = json.loads(dhcp_options_json)
            else:
                options = dhcp_options_json
            
            return options if isinstance(options, dict) else {}
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Failed to parse DHCP options JSON: {e}")
            return {}
    
    def _extract_fingerprint_data(self, packet_data: Dict) -> DeviceFingerprint:
        """
        Extract fingerprinting data from a raw DHCP packet.
        Phase 4: Extract key DHCP options for device classification.
        """
        mac_address = self._normalize_mac_address(packet_data.get('mac_address'))
        if not mac_address:
            return None
        
        # Parse DHCP options
        dhcp_options = self._extract_dhcp_options(packet_data.get('dhcp_options'))
        
        # Extract key fingerprinting options
        
        # Option 12: Hostname (device name set by user/manufacturer)
        hostname = dhcp_options.get('option_12') or packet_data.get('hostname')
        hostname = self._sanitize_hostname(hostname)
        
        # Option 60: Vendor Class Identifier (device manufacturer/model info)
        vendor_class = dhcp_options.get('option_60') or packet_data.get('vendor_class')
        if vendor_class and isinstance(vendor_class, bytes):
            vendor_class = vendor_class.decode('utf-8', errors='ignore')
        
        # Option 55: Parameter Request List (ordered list - key for OS fingerprinting)
        param_request_list = dhcp_options.get('option_55')
        dhcp_fingerprint = None
        if param_request_list:
            if isinstance(param_request_list, str):
                dhcp_fingerprint = param_request_list
            elif isinstance(param_request_list, list):
                dhcp_fingerprint = ','.join(str(x) for x in param_request_list)
        
        # Option 81: Client FQDN (fully qualified domain name)
        client_fqdn = dhcp_options.get('option_81')
        if client_fqdn and isinstance(client_fqdn, bytes):
            client_fqdn = client_fqdn.decode('utf-8', errors='ignore')
        
        # Extract vendor-specific options
        vendor_specific = {}
        for key, value in dhcp_options.items():
            if key.startswith('option_') and key not in ['option_12', 'option_55', 'option_60', 'option_81']:
                vendor_specific[key] = value
        
        return DeviceFingerprint(
            mac_address=mac_address,
            dhcp_fingerprint=dhcp_fingerprint,
            dhcp_vendor_class=vendor_class,
            hostname=hostname,
            client_fqdn=client_fqdn,
            vendor_specific_options=vendor_specific
        )
    
    def process_unprocessed_packets(self, batch_size: int = 100) -> List[DeviceFingerprint]:
        """
        Process unprocessed DHCP packets and extract fingerprint data.
        Phase 4: Query raw_dhcp_packets table for unprocessed packets.
        """
        logger.info(f"Processing up to {batch_size} unprocessed DHCP packets")
        
        try:
            # Get unprocessed packets from database
            unprocessed_packets = self.dhcp_store.get_unprocessed_packets(limit=batch_size)
            
            if not unprocessed_packets:
                logger.info("No unprocessed packets found")
                return []
            
            logger.info(f"Found {len(unprocessed_packets)} unprocessed packets")
            
            fingerprints = []
            processed_packet_ids = []
            
            for packet in unprocessed_packets:
                try:
                    # Extract fingerprint data
                    fingerprint = self._extract_fingerprint_data(packet)
                    
                    if fingerprint:
                        fingerprints.append(fingerprint)
                        processed_packet_ids.append(packet['packet_id'])
                        self.processed_count += 1
                        
                        logger.debug(f"Processed packet {packet['packet_id']} for device {fingerprint.mac_address}")
                    else:
                        # Still mark as processed even if extraction failed
                        processed_packet_ids.append(packet['packet_id'])
                        logger.warning(f"Failed to extract fingerprint from packet {packet['packet_id']}")
                
                except Exception as e:
                    logger.error(f"Error processing packet {packet.get('packet_id', 'unknown')}: {e}")
                    self.error_count += 1
                    # Still mark as processed to avoid reprocessing
                    if 'packet_id' in packet:
                        processed_packet_ids.append(packet['packet_id'])
            
            # Mark packets as processed in database
            if processed_packet_ids:
                self.dhcp_store.mark_packets_processed(processed_packet_ids)
                logger.info(f"Marked {len(processed_packet_ids)} packets as processed")
            
            logger.info(f"Successfully extracted {len(fingerprints)} device fingerprints")
            return fingerprints
        
        except Exception as e:
            logger.error(f"Error processing unprocessed packets: {e}")
            self.error_count += 1
            return []
    
    def validate_fingerprint_data(self, fingerprint: DeviceFingerprint) -> bool:
        """
        Validate fingerprint data for API submission.
        Phase 4: Validate extracted data before Fingerbank API submission.
        """
        # MAC address is required
        if not fingerprint.mac_address:
            logger.warning("Fingerprint missing MAC address")
            return False
        
        # At least one identifying field should be present
        has_identifier = any([
            fingerprint.dhcp_fingerprint,
            fingerprint.dhcp_vendor_class,
            fingerprint.hostname
        ])
        
        if not has_identifier:
            logger.warning(f"Fingerprint for {fingerprint.mac_address} lacks identifying information")
            return False
        
        return True
    
    def get_processing_statistics(self) -> Dict:
        """Get packet processing statistics."""
        return {
            "processed_count": self.processed_count,
            "error_count": self.error_count,
            "success_rate": (self.processed_count / (self.processed_count + self.error_count)) * 100 
                           if (self.processed_count + self.error_count) > 0 else 0
        }
    
    def reset_statistics(self):
        """Reset processing statistics."""
        self.processed_count = 0
        self.error_count = 0

def main():
    """Test the DHCP packet parser."""
    print("DHCP Packet Parser Test")
    print("=" * 30)
    
    try:
        # Initialize parser
        parser = DHCPPacketParser()
        
        # Process unprocessed packets
        fingerprints = parser.process_unprocessed_packets(batch_size=50)
        
        print(f"Processed {len(fingerprints)} device fingerprints")
        
        # Display some fingerprints
        for i, fp in enumerate(fingerprints[:5]):  # Show first 5
            print(f"\nFingerprint {i+1}:")
            print(f"  MAC: {fp.mac_address}")
            print(f"  DHCP Fingerprint: {fp.dhcp_fingerprint}")
            print(f"  Vendor Class: {fp.dhcp_vendor_class}")
            print(f"  Hostname: {fp.hostname}")
            print(f"  FQDN: {fp.client_fqdn}")
            
            # Validate for API submission
            is_valid = parser.validate_fingerprint_data(fp)
            print(f"  Valid for API: {'Yes' if is_valid else 'No'}")
        
        # Show statistics
        stats = parser.get_processing_statistics()
        print(f"\nProcessing Statistics:")
        print(f"  Processed: {stats['processed_count']}")
        print(f"  Errors: {stats['error_count']}")
        print(f"  Success Rate: {stats['success_rate']:.1f}%")
    
    except Exception as e:
        print(f"Parser test failed: {e}")

if __name__ == "__main__":
    main()