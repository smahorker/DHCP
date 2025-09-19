#!/usr/bin/env python3
"""
Cisco Meraki Dashboard API Client
Integrates device classification results back into Meraki cloud
"""

import requests
import json
from typing import Dict, List, Optional, Union
import logging
import time
from datetime import datetime, timedelta

class MerakiAPIClient:
    def __init__(self, api_key: str, base_url: str = "https://api.meraki.com/api/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'X-Cisco-Meraki-API-Key': api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'DHCP-Device-Classifier/1.0'
        })
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting (Meraki allows 5 requests per second per org)
        self.last_request_time = 0
        self.min_request_interval = 0.2  # 200ms between requests

    def _rate_limit(self):
        """Implement rate limiting for Meraki API"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)
        self.last_request_time = time.time()

    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Union[Dict, List]:
        """Make rate-limited API request with error handling"""
        self._rate_limit()
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            
            # Handle empty responses
            if response.status_code == 204:
                return {}
                
            return response.json()

        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:  # Rate limit exceeded
                self.logger.warning("Rate limit exceeded, waiting 60 seconds")
                time.sleep(60)
                return self._make_request(method, endpoint, data)  # Retry once
            else:
                self.logger.error(f"HTTP Error {response.status_code}: {e}")
                raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise

    def get_organizations(self) -> List[Dict]:
        """Get all organizations for the API key"""
        return self._make_request('GET', '/organizations')

    def get_networks(self, organization_id: str) -> List[Dict]:
        """Get all networks in an organization"""
        return self._make_request('GET', f'/organizations/{organization_id}/networks')

    def get_network_clients(self, network_id: str, timespan: int = 86400) -> List[Dict]:
        """Get all clients in a network (timespan in seconds, max 31 days)"""
        endpoint = f'/networks/{network_id}/clients?timespan={timespan}'
        return self._make_request('GET', endpoint)

    def get_client_details(self, network_id: str, client_id: str) -> Dict:
        """Get detailed information about a specific client"""
        return self._make_request('GET', f'/networks/{network_id}/clients/{client_id}')

    def get_network_devices(self, network_id: str) -> List[Dict]:
        """Get all devices in a network"""
        return self._make_request('GET', f'/networks/{network_id}/devices')

    def update_client_policy(self, network_id: str, client_mac: str, 
                           group_policy_id: str = None, device_policy: str = 'Normal') -> Dict:
        """Update client policy based on device classification"""
        endpoint = f'/networks/{network_id}/clients/{client_mac}/policy'
        
        policy_data = {
            'devicePolicy': device_policy
        }
        
        if group_policy_id:
            policy_data['groupPolicyId'] = group_policy_id

        return self._make_request('PUT', endpoint, policy_data)

    def tag_device(self, network_id: str, serial: str, tags: List[str]) -> Dict:
        """Add tags to Meraki device based on classification"""
        endpoint = f'/networks/{network_id}/devices/{serial}'
        
        device_data = {'tags': tags}
        return self._make_request('PUT', endpoint, device_data)

    def get_group_policies(self, network_id: str) -> List[Dict]:
        """Get all group policies for a network"""
        return self._make_request('GET', f'/networks/{network_id}/groupPolicies')

    def create_group_policy(self, network_id: str, policy_name: str,
                          bandwidth_limits: Dict = None, 
                          firewall_rules: List[Dict] = None) -> Dict:
        """Create group policy for device type"""
        endpoint = f'/networks/{network_id}/groupPolicies'

        policy_data = {
            'name': policy_name,
            'scheduling': {'enabled': False},
            'bandwidth': bandwidth_limits or {'limitUp': 0, 'limitDown': 0}
        }

        if firewall_rules:
            policy_data['firewallAndTrafficShaping'] = {
                'settings': 'custom',
                'trafficShapingRules': firewall_rules
            }

        return self._make_request('POST', endpoint, policy_data)

    def update_network_client_notes(self, network_id: str, client_mac: str, notes: str) -> Dict:
        """Update client notes with classification information"""
        endpoint = f'/networks/{network_id}/clients/{client_mac}'
        
        client_data = {'notes': notes}
        return self._make_request('PUT', endpoint, client_data)

    def get_network_events(self, network_id: str, starting_after: str = None, 
                         ending_before: str = None, per_page: int = 1000) -> List[Dict]:
        """Get network events for analysis"""
        params = []
        if starting_after:
            params.append(f'startingAfter={starting_after}')
        if ending_before:
            params.append(f'endingBefore={ending_before}')
        params.append(f'perPage={per_page}')
        
        query_string = '&'.join(params)
        endpoint = f'/networks/{network_id}/events?{query_string}'
        
        return self._make_request('GET', endpoint)

    def create_webhook_server(self, network_id: str, name: str, url: str, 
                            shared_secret: str) -> Dict:
        """Create webhook server for real-time events"""
        endpoint = f'/networks/{network_id}/webhooks/httpServers'
        
        webhook_data = {
            'name': name,
            'url': url,
            'sharedSecret': shared_secret
        }

        return self._make_request('POST', endpoint, webhook_data)

    def get_webhook_servers(self, network_id: str) -> List[Dict]:
        """Get all webhook servers for a network"""
        return self._make_request('GET', f'/networks/{network_id}/webhooks/httpServers')

    def update_webhook_alerts(self, network_id: str, enabled: bool = True,
                            default_destinations: Dict = None,
                            alerts: List[Dict] = None) -> Dict:
        """Configure webhook alerts for DHCP and client events"""
        endpoint = f'/networks/{network_id}/alerts/settings'
        
        # Default DHCP and client event alerts
        if not alerts:
            alerts = [
                {
                    'type': 'dhcp_lease_assigned',
                    'enabled': enabled,
                    'alertDestinations': default_destinations or {}
                },
                {
                    'type': 'client_connectivity',
                    'enabled': enabled,
                    'alertDestinations': default_destinations or {}
                }
            ]

        alert_data = {
            'defaultDestinations': default_destinations or {},
            'alerts': alerts
        }

        return self._make_request('PUT', endpoint, alert_data)

    def get_device_classification_policies(self, network_id: str) -> Dict:
        """Get existing device classification policies"""
        try:
            group_policies = self.get_group_policies(network_id)
            
            # Filter policies that might be device-type related
            device_policies = {}
            for policy in group_policies:
                policy_name = policy.get('name', '').lower()
                if any(device_type in policy_name for device_type in 
                      ['phone', 'tablet', 'laptop', 'desktop', 'iot', 'gaming', 'smart']):
                    device_policies[policy['name']] = policy
                    
            return device_policies
        except Exception as e:
            self.logger.error(f"Error getting device classification policies: {e}")
            return {}

    def apply_device_classification(self, network_id: str, client_mac: str, 
                                  device_type: str, confidence: str) -> bool:
        """Apply device classification to Meraki client"""
        try:
            # Update client notes with classification info
            classification_note = (
                f"Auto-classified as {device_type} "
                f"(confidence: {confidence}) on {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            
            self.update_network_client_notes(network_id, client_mac, classification_note)
            
            # Apply appropriate group policy if available
            device_policies = self.get_device_classification_policies(network_id)
            
            # Map device types to policies
            policy_mapping = {
                'Phone': 'Mobile Device Policy',
                'Tablet': 'Mobile Device Policy', 
                'Gaming Console': 'Gaming Device Policy',
                'Smart TV': 'Streaming Device Policy',
                'IoT Device': 'IoT Device Policy',
                'Printer': 'Printer Policy'
            }
            
            policy_name = policy_mapping.get(device_type)
            if policy_name and policy_name in device_policies:
                policy_id = device_policies[policy_name]['groupPolicyId']
                self.update_client_policy(network_id, client_mac, policy_id)
                self.logger.info(f"Applied policy {policy_name} to {client_mac}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error applying device classification: {e}")
            return False