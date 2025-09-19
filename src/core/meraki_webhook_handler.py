#!/usr/bin/env python3
"""
Meraki Webhook Handler for Real-time Device Classification
Processes DHCP events from SQS messages and integrates with existing system
"""

import json
import hmac
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional
import logging
from datetime import datetime

@dataclass
class MerakiDHCPEvent:
    """Meraki DHCP event data structure"""
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    network_id: str = ""
    device_serial: str = ""
    client_description: str = ""
    event_type: str = ""  # lease_assigned, lease_renewed, etc.
    timestamp: str = ""
    vlan_id: Optional[int] = None
    ssid: Optional[str] = None

class MerakiWebhookHandler:
    def __init__(self, shared_secret: str, device_analyzer):
        self.shared_secret = shared_secret
        self.device_analyzer = device_analyzer
        self.logger = logging.getLogger(__name__)
        self.processed_events = 0
        self.classification_results = []

    def verify_webhook_signature(self, payload: str, signature: str) -> bool:
        """Verify Meraki webhook signature"""
        if not signature:
            return False
            
        expected_signature = hmac.new(
            self.shared_secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)

    def parse_meraki_webhook(self, webhook_data: Dict) -> List[MerakiDHCPEvent]:
        """Parse Meraki webhook payload into DHCP events"""
        events = []

        # Handle different alert types
        alert_type = webhook_data.get('alertType', '')
        
        if 'DHCP' in alert_type or 'lease' in alert_type.lower():
            event = MerakiDHCPEvent(
                mac_address=webhook_data.get('deviceMac', ''),
                ip_address=webhook_data.get('clientIp', ''),
                hostname=webhook_data.get('clientName') or webhook_data.get('hostname'),
                network_id=webhook_data.get('networkId', ''),
                device_serial=webhook_data.get('deviceSerial', ''),
                client_description=webhook_data.get('clientDescription', ''),
                event_type=alert_type.lower().replace(' ', '_'),
                timestamp=webhook_data.get('occurredAt', datetime.now().isoformat()),
                vlan_id=webhook_data.get('vlanId'),
                ssid=webhook_data.get('ssid')
            )
            events.append(event)

        # Handle client connection events
        elif 'client' in alert_type.lower() and ('connected' in alert_type.lower() or 'associated' in alert_type.lower()):
            event = MerakiDHCPEvent(
                mac_address=webhook_data.get('clientMac', ''),
                ip_address=webhook_data.get('clientIp', ''),
                hostname=webhook_data.get('clientName'),
                network_id=webhook_data.get('networkId', ''),
                device_serial=webhook_data.get('deviceSerial', ''),
                event_type='client_connected',
                timestamp=webhook_data.get('occurredAt', datetime.now().isoformat()),
                vlan_id=webhook_data.get('vlanId'),
                ssid=webhook_data.get('ssid')
            )
            events.append(event)

        return events

    def process_dhcp_event(self, event: MerakiDHCPEvent):
        """Process DHCP event through existing classification system"""
        try:
            # Convert to DHCPLogEntry format for existing system
            from .dhcp_log_parser import DHCPLogEntry

            dhcp_entry = DHCPLogEntry(
                mac_address=event.mac_address,
                ip_address=event.ip_address,
                hostname=event.hostname,
                message_type='ACK',  # Assume ACK for webhook events
                timestamp=datetime.now(),
                vendor_class=None,
                user_class=None,
                dhcp_options={}
            )

            # Run through existing classification pipeline
            result = self.device_analyzer._classify_device(
                event.mac_address,
                [dhcp_entry]
            )

            # Enhance with Meraki context
            result.meraki_context = {
                'network_id': event.network_id,
                'device_serial': event.device_serial,
                'ssid': event.ssid,
                'vlan_id': event.vlan_id,
                'event_type': event.event_type,
                'timestamp': event.timestamp
            }

            # Store classification result
            self.store_classification_result(result, event)

        except Exception as e:
            self.logger.error(f"Error processing DHCP event: {str(e)}")

    def store_classification_result(self, result, event: MerakiDHCPEvent):
        """Store classification result and optionally send back to Meraki"""
        # Create result summary
        result_summary = {
            'mac_address': event.mac_address,
            'device_type': result.device_type,
            'confidence': result.overall_confidence,
            'classification_method': result.classification_method,
            'network_id': event.network_id,
            'timestamp': event.timestamp,
            'meraki_event_type': event.event_type
        }

        # Add to recent results (keep last 100)
        self.classification_results.append(result_summary)
        if len(self.classification_results) > 100:
            self.classification_results = self.classification_results[-100:]

        # Log classification
        self.logger.info(f"Classified Meraki device: {result.device_type} "
                        f"({result.overall_confidence}) - {event.mac_address} "
                        f"via {result.classification_method}")

        # TODO: Optional integration with Meraki API for device tagging
        # This would be implemented in the enhanced classifier module