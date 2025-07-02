#!/usr/bin/env python3
"""
Fingerbank API Integration for Network Device Monitoring System.
Phase 5: Send device fingerprint data to Fingerbank API and store classifications.
"""

import os
import time
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
# Database imports removed - system now operates without database dependency
# DeviceFingerprint moved to this file since dhcp_parser was removed

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DeviceFingerprint:
    """Enhanced device fingerprint data for Fingerbank API v2."""
    mac_address: str
    
    # DHCP Options
    dhcp_fingerprint: Optional[str] = None  # Option 55: Parameter Request List
    dhcp6_fingerprint: Optional[str] = None  # DHCPv6 fingerprint
    dhcp_vendor_class: Optional[str] = None  # Option 60: Vendor Class Identifier
    dhcp6_enterprise: Optional[str] = None  # DHCPv6 enterprise
    hostname: Optional[str] = None  # Option 12: Hostname
    client_fqdn: Optional[str] = None  # Option 81: Client FQDN
    
    # Network Traffic Patterns
    user_agents: Optional[List[str]] = None  # HTTP User-Agent headers
    destination_hosts: Optional[List[str]] = None  # Domains contacted
    
    # Advanced Fingerprinting
    tcp_syn_signatures: Optional[List[str]] = None  # TCP SYN fingerprints
    ja3_fingerprints: Optional[List[str]] = None  # JA3 TLS fingerprints
    ja3_data: Optional[Dict] = None  # JA3+JA3s with host:port
    
    # UPnP and mDNS
    upnp_user_agents: Optional[List[str]] = None  # UPnP USER-AGENT headers
    upnp_server_strings: Optional[List[str]] = None  # UPnP SERVER headers
    mdns_services: Optional[List[str]] = None  # mDNS service advertisements
    
    # HTTP Client Hints
    client_hints: Optional[Dict] = None  # sec-ch-ua headers
    
    # Additional data for internal use
    vendor_specific_options: Dict = None

class APIRateLimit:
    """Rate limiting for Fingerbank Community API."""
    
    def __init__(self, requests_per_hour: int = 100, requests_per_day: int = 1000):
        """
        Initialize rate limiter for Fingerbank Community API.
        Community API limits: typically 100/hour, 1000/day
        """
        self.requests_per_hour = requests_per_hour
        self.requests_per_day = requests_per_day
        self.hourly_requests = []
        self.daily_requests = []
        self.last_request_time = None
    
    def can_make_request(self) -> bool:
        """Check if we can make a request within rate limits."""
        now = datetime.now()
        
        # Clean old requests from tracking
        self._cleanup_old_requests(now)
        
        # Check hourly limit
        if len(self.hourly_requests) >= self.requests_per_hour:
            return False
        
        # Check daily limit
        if len(self.daily_requests) >= self.requests_per_day:
            return False
        
        return True
    
    def record_request(self):
        """Record a request for rate limiting."""
        now = datetime.now()
        self.hourly_requests.append(now)
        self.daily_requests.append(now)
        self.last_request_time = now
    
    def _cleanup_old_requests(self, now: datetime):
        """Remove old requests from tracking."""
        # Remove requests older than 1 hour
        hour_ago = now - timedelta(hours=1)
        self.hourly_requests = [req for req in self.hourly_requests if req > hour_ago]
        
        # Remove requests older than 1 day
        day_ago = now - timedelta(days=1)
        self.daily_requests = [req for req in self.daily_requests if req > day_ago]
    
    def get_wait_time(self) -> float:
        """Get recommended wait time before next request."""
        if not self.hourly_requests:
            return 0
        
        # Calculate time until oldest request expires
        oldest_request = min(self.hourly_requests)
        hour_from_oldest = oldest_request + timedelta(hours=1)
        wait_time = (hour_from_oldest - datetime.now()).total_seconds()
        
        return max(0, wait_time)
    
    def get_status(self) -> Dict:
        """Get current rate limit status."""
        now = datetime.now()
        self._cleanup_old_requests(now)
        
        return {
            "hourly_used": len(self.hourly_requests),
            "hourly_limit": self.requests_per_hour,
            "daily_used": len(self.daily_requests),
            "daily_limit": self.requests_per_day,
            "can_request": self.can_make_request(),
            "wait_time_seconds": self.get_wait_time()
        }

@dataclass
class DeviceClassification:
    """Enhanced device classification result from Fingerbank API v2."""
    # Core device information
    fingerbank_device_id: Optional[int] = None
    device_name: Optional[str] = None  # Full hierarchy path
    device_type: Optional[str] = None
    
    # Operating system details
    operating_system: Optional[str] = None
    operating_system_id: Optional[int] = None
    version: Optional[str] = None  # Specific version (e.g., "11.0.1" for iOS)
    
    # Manufacturer information
    manufacturer: Optional[str] = None
    manufacturer_id: Optional[int] = None
    
    # Device hierarchy and relationships
    device_hierarchy: Optional[List[str]] = None  # Parent device chain
    parent_device_id: Optional[int] = None
    
    # Confidence and scoring
    confidence_score: Optional[int] = None
    confidence_level: Optional[str] = None  # very_low, moderate, high, very_high
    can_be_more_precise: Optional[bool] = None
    
    # Additional metadata
    request_id: Optional[str] = None
    vulnerabilities: Optional[Dict] = None  # CVE information if available
    
    # Response tracking
    raw_response: Dict = None
    error_message: Optional[str] = None

class FingerbankAPIClient:
    """
    Fingerbank API client with rate limiting and error handling.
    Phase 5: Fingerbank Integration implementation.
    """
    
    def __init__(self, api_key: str = None):
        """Initialize Fingerbank API client."""
        self.api_key = api_key or os.getenv('FINGERBANK_API_KEY')
        if not self.api_key:
            raise ValueError("Fingerbank API key is required. Set FINGERBANK_API_KEY environment variable.")
        
        self.base_url = "https://api.fingerbank.org/api/v2"
        self.rate_limiter = APIRateLimit()
        
        # Configure requests session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # API statistics
        self.successful_requests = 0
        self.failed_requests = 0
        self.rate_limited_requests = 0
        
        logger.info("Fingerbank API client initialized")
    
    def _exponential_backoff_retry(self, func, max_retries: int = 3, base_delay: float = 1.0):
        """Implement exponential backoff retry logic for failed requests."""
        for attempt in range(max_retries):
            try:
                return func()
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:  # Last attempt
                    raise e
                
                delay = base_delay * (2 ** attempt)
                logger.warning(f"Request failed (attempt {attempt + 1}/{max_retries}), retrying in {delay}s: {e}")
                time.sleep(delay)
    
    def _make_api_request(self, fingerprint: DeviceFingerprint) -> Dict:
        """Make API request to Fingerbank with rate limiting."""
        
        # Check rate limits
        if not self.rate_limiter.can_make_request():
            wait_time = self.rate_limiter.get_wait_time()
            raise Exception(f"Rate limit exceeded. Wait {wait_time:.0f} seconds.")
        
        # Prepare API request parameters
        params = {
            'key': self.api_key
        }
        
        # Add MAC address (critical for maximum accuracy)
        if fingerprint.mac_address:
            params['mac'] = fingerprint.mac_address
        
        # Add fingerprint data to request
        if fingerprint.dhcp_fingerprint:
            params['dhcp_fingerprint'] = fingerprint.dhcp_fingerprint
        
        if fingerprint.dhcp_vendor_class:
            params['dhcp_vendor'] = fingerprint.dhcp_vendor_class  # Correct parameter name
        
        if fingerprint.hostname:
            params['hostname'] = fingerprint.hostname
        
        if fingerprint.client_fqdn:
            params['fqdn'] = fingerprint.client_fqdn
        
        # Make the API request
        def make_request():
            response = self.session.get(
                f"{self.base_url}/combinations/interrogate",
                params=params,
                timeout=30
            )
            response.raise_for_status()
            return response
        
        # Execute request with retry logic
        response = self._exponential_backoff_retry(make_request)
        
        # Record request for rate limiting
        self.rate_limiter.record_request()
        
        return response.json()
    
    def classify_device(self, fingerprint: DeviceFingerprint) -> DeviceClassification:
        """
        Classify device using Fingerbank API.
        Phase 5: Send MAC address and DHCP fingerprint data to API.
        """
        try:
            logger.debug(f"Classifying device: {fingerprint.mac_address}")
            
            # Make API request
            response_data = self._make_api_request(fingerprint)
            
            # Parse API response
            classification = self._parse_api_response(response_data)
            
            if classification.error_message:
                logger.warning(f"API classification warning for {fingerprint.mac_address}: {classification.error_message}")
                self.failed_requests += 1
            else:
                logger.info(f"Successfully classified {fingerprint.mac_address}: {classification.device_name}")
                self.successful_requests += 1
            
            return classification
        
        except Exception as e:
            error_msg = str(e)
            logger.error(f"API request failed for {fingerprint.mac_address}: {error_msg}")
            
            if "Rate limit" in error_msg:
                self.rate_limited_requests += 1
            else:
                self.failed_requests += 1
            
            return DeviceClassification(
                raw_response={},
                error_message=error_msg
            )
    
    def _parse_api_response(self, response_data: Dict) -> DeviceClassification:
        """
        Enhanced parsing of Fingerbank API v2 response with complete field extraction.
        """
        classification = DeviceClassification(raw_response=response_data)
        
        try:
            # Extract core response metadata
            classification.confidence_score = response_data.get('score', 0)
            classification.request_id = response_data.get('request_id')
            classification.version = response_data.get('version', '')
            
            # Interpret confidence score according to Fingerbank documentation
            score = classification.confidence_score
            if score < 30:
                classification.confidence_level = 'very_low'
            elif score <= 50:
                classification.confidence_level = 'moderate' 
            elif score <= 75:
                classification.confidence_level = 'high'
            else:
                classification.confidence_level = 'very_high'
            
            # Extract device information with full hierarchy
            if 'device' in response_data and response_data['device']:
                device_info = response_data['device']
                classification.fingerbank_device_id = device_info.get('id')
                classification.device_name = device_info.get('name')
                classification.parent_device_id = device_info.get('parent_id')
                classification.can_be_more_precise = device_info.get('can_be_more_precise')
                
                # Extract device hierarchy from parents
                if 'parents' in device_info and device_info['parents']:
                    classification.device_hierarchy = []
                    for parent in device_info['parents']:
                        classification.device_hierarchy.append(parent.get('name', ''))
                
                # Use full device_name from response root (complete hierarchy path)
                if 'device_name' in response_data:
                    classification.device_name = response_data['device_name']
            
            # Extract operating system information (separate from device)
            if 'operating_system' in response_data and response_data['operating_system']:
                os_info = response_data['operating_system']
                classification.operating_system = os_info.get('name')
                classification.operating_system_id = os_info.get('id')
                
                # Combine with version if available
                if classification.version and classification.operating_system:
                    classification.operating_system = f"{classification.operating_system} {classification.version}".strip()
                
                logger.debug(f"Extracted OS: {classification.operating_system} (ID: {classification.operating_system_id})")
            
            # Extract manufacturer information (distinct from device vendor)
            if 'manufacturer' in response_data and response_data['manufacturer']:
                manufacturer_info = response_data['manufacturer']
                classification.manufacturer = manufacturer_info.get('name')
                classification.manufacturer_id = manufacturer_info.get('id')
                logger.debug(f"Extracted manufacturer: {classification.manufacturer}")
            
            # Determine device type from hierarchy analysis
            classification.device_type = self._determine_device_type(
                response_data.get('device_name', ''),
                classification.device_hierarchy or [],
                classification.manufacturer
            )
            
            # Extract vulnerability information if available
            if 'device' in response_data and 'vulnerabilities' in response_data['device']:
                classification.vulnerabilities = response_data['device']['vulnerabilities']
            
            # Handle error responses
            if 'errors' in response_data:
                classification.error_message = response_data['errors'].get('details', 'Unknown error')
            elif not classification.device_name and not classification.operating_system and not classification.manufacturer:
                classification.error_message = "No device information found in response"
            
            logger.debug(f"Enhanced parsing - Device: {classification.device_name}, "
                        f"OS: {classification.operating_system}, Manufacturer: {classification.manufacturer}, "
                        f"Type: {classification.device_type}, Score: {classification.confidence_score} ({classification.confidence_level})")
            
            return classification
        
        except Exception as e:
            logger.error(f"Error parsing enhanced API response: {e}")
            logger.error(f"Response data: {response_data}")
            classification.error_message = f"Failed to parse API response: {e}"
            return classification
    
    def _determine_device_type(self, device_name: str, device_hierarchy: List[str], manufacturer: str) -> Optional[str]:
        """Enhanced device type determination using full Fingerbank hierarchy analysis."""
        
        # Combine all available text for comprehensive analysis
        full_text = ' '.join(filter(None, [device_name, manufacturer] + (device_hierarchy or []))).lower()
        
        logger.debug(f"Analyzing device hierarchy: {device_name}, parents: {device_hierarchy}, manufacturer: {manufacturer}")
        
        # Enhanced device type patterns with confidence weighting
        device_patterns = {
            'Phone': {
                'high': ['smartphone', 'mobile phone', 'cellular phone', 'iphone', 'android phone'],
                'medium': ['phone', 'galaxy', 'pixel', 'oneplus', 'huawei phone'],
                'low': ['mobile']
            },
            'Tablet': {
                'high': ['tablet', 'ipad', 'android tablet'],
                'medium': ['slate', 'surface tablet'],
                'low': ['tab']
            },
            'Computer': {
                'high': ['laptop', 'desktop', 'workstation', 'macbook', 'imac', 'thinkpad'],
                'medium': ['computer', 'pc', 'notebook', 'ultrabook'],
                'low': ['mac', 'windows']
            },
            'Server': {
                'high': ['server', 'rack server', 'blade server', 'database server'],
                'medium': ['datacenter', 'enterprise server'],
                'low': ['srv']
            },
            'Gaming Console': {
                'high': ['playstation', 'xbox', 'nintendo switch', 'ps4', 'ps5', 'xbox one', 'xbox series'],
                'medium': ['console', 'gaming console', 'nintendo'],
                'low': ['gaming']
            },
            'Smart TV': {
                'high': ['smart tv', 'android tv', 'roku tv', 'apple tv', 'fire tv'],
                'medium': ['television', 'tv', 'media player', 'streaming device'],
                'low': ['roku', 'chromecast']
            },
            'Network Device': {
                'high': ['router', 'switch', 'access point', 'firewall', 'gateway'],
                'medium': ['network device', 'networking', 'modem', 'bridge'],
                'low': ['wireless', 'ethernet']
            },
            'Printer': {
                'high': ['printer', 'multifunction printer', 'laser printer', 'inkjet printer'],
                'medium': ['print server', 'scanner', 'copier'],
                'low': ['print']
            },
            'Smart Speaker': {
                'high': ['smart speaker', 'voice assistant', 'echo', 'google home', 'homepod'],
                'medium': ['speaker', 'alexa device', 'google assistant'],
                'low': ['audio']
            },
            'Smart Camera': {
                'high': ['security camera', 'ip camera', 'webcam', 'doorbell camera', 'ring'],
                'medium': ['camera', 'surveillance', 'nest cam'],
                'low': ['cam']
            },
            'Smart Lighting': {
                'high': ['smart light', 'smart bulb', 'hue', 'philips lighting'],
                'medium': ['lighting', 'bulb', 'dimmer'],
                'low': ['light']
            },
            'IoT Device': {
                'high': ['iot device', 'smart sensor', 'smart plug', 'smart switch'],
                'medium': ['sensor', 'thermostat', 'smart home', 'automation'],
                'low': ['iot']
            },
            'Storage Device': {
                'high': ['nas', 'network storage', 'storage server'],
                'medium': ['storage', 'drive', 'disk'],
                'low': ['hdd', 'ssd']
            }
        }
        
        # Find best match with confidence scoring
        best_match = None
        best_confidence = 0
        best_device_type = None
        
        for device_type, confidence_levels in device_patterns.items():
            for confidence, patterns in confidence_levels.items():
                confidence_score = {'high': 3, 'medium': 2, 'low': 1}[confidence]
                
                for pattern in patterns:
                    if pattern in full_text:
                        if confidence_score > best_confidence:
                            best_match = pattern
                            best_confidence = confidence_score
                            best_device_type = device_type
                        # Break on first high-confidence match for this device type
                        if confidence == 'high':
                            break
                
                # Break on high-confidence match
                if best_confidence == 3:
                    break
            
            if best_confidence == 3:
                break
        
        if best_device_type:
            confidence_level = {3: 'high', 2: 'medium', 1: 'low'}[best_confidence]
            logger.debug(f"Device type determined: {best_device_type} (confidence: {confidence_level}, pattern: '{best_match}')")
            return best_device_type
        
        # Fallback: analyze hierarchy structure for device category hints
        if device_hierarchy:
            return self._analyze_hierarchy_structure(device_hierarchy, manufacturer)
        
        logger.debug("No device type pattern matched")
        return None
    
    def _analyze_hierarchy_structure(self, device_hierarchy: List[str], manufacturer: str) -> Optional[str]:
        """Analyze Fingerbank device hierarchy structure for classification hints."""
        if not device_hierarchy:
            return None
        
        # Join hierarchy for analysis
        hierarchy_text = ' '.join(device_hierarchy).lower()
        
        # Hierarchy-based classification patterns
        hierarchy_patterns = {
            'Phone': ['mobile', 'cellular', 'smartphone'],
            'Computer': ['operating system', 'os', 'desktop', 'laptop'],
            'Gaming Console': ['gaming', 'console', 'entertainment'],
            'Network Device': ['networking', 'infrastructure', 'wireless'],
            'IoT Device': ['internet of things', 'embedded', 'sensor'],
            'Smart TV': ['media', 'entertainment', 'streaming'],
        }
        
        for device_type, keywords in hierarchy_patterns.items():
            if any(keyword in hierarchy_text for keyword in keywords):
                logger.debug(f"Device type from hierarchy: {device_type} (hierarchy: {hierarchy_text})")
                return device_type
        
        # Manufacturer-based inference as last resort
        if manufacturer:
            manufacturer_lower = manufacturer.lower()
            if any(mobile_mfg in manufacturer_lower for mobile_mfg in ['apple', 'samsung', 'google', 'huawei']):
                # Could be phone, tablet, or computer - can't determine without more info
                return None
            elif any(gaming_mfg in manufacturer_lower for gaming_mfg in ['sony', 'microsoft', 'nintendo']):
                return 'Gaming Console'
            elif any(network_mfg in manufacturer_lower for network_mfg in ['cisco', 'netgear', 'linksys']):
                return 'Network Device'
        
        return None
    
    def get_api_statistics(self) -> Dict:
        """Get API usage statistics."""
        rate_status = self.rate_limiter.get_status()
        
        total_requests = self.successful_requests + self.failed_requests + self.rate_limited_requests
        success_rate = (self.successful_requests / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "total_requests": total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "rate_limited_requests": self.rate_limited_requests,
            "success_rate": success_rate,
            "rate_limit_status": rate_status
        }

class DeviceClassificationManager:
    """
    Manages device classification workflow.
    Simplified version without database dependencies.
    """
    
    def __init__(self, api_client: FingerbankAPIClient):
        """Initialize classification manager."""
        self.api_client = api_client
        
        self.classifications_processed = 0
        self.classifications_stored = 0
    
    def classify_and_store_fingerprints(self, fingerprints: List[DeviceFingerprint], 
                                      batch_delay: float = 1.0) -> List[DeviceClassification]:
        """
        Classify multiple device fingerprints and store results.
        Phase 5: Process fingerprints with rate limiting and store classifications.
        """
        logger.info(f"Processing {len(fingerprints)} device fingerprints")
        
        classifications = []
        
        for i, fingerprint in enumerate(fingerprints):
            try:
                # Check rate limits before processing
                if not self.api_client.rate_limiter.can_make_request():
                    wait_time = self.api_client.rate_limiter.get_wait_time()
                    logger.info(f"Rate limit reached, waiting {wait_time:.0f} seconds...")
                    time.sleep(wait_time + 1)  # Add 1 second buffer
                
                # Classify device
                classification = self.api_client.classify_device(fingerprint)
                classifications.append(classification)
                self.classifications_processed += 1
                
                # Count successful classifications
                if not classification.error_message:
                    self.classifications_stored += 1
                
                # Add delay between requests to be respectful to API
                if i < len(fingerprints) - 1:  # Don't delay after last request
                    time.sleep(batch_delay)
                
                logger.debug(f"Processed {i + 1}/{len(fingerprints)} fingerprints")
            
            except Exception as e:
                logger.error(f"Error processing fingerprint {fingerprint.mac_address}: {e}")
                classifications.append(DeviceClassification(
                    raw_response={},
                    error_message=str(e)
                ))
        
        logger.info(f"Completed processing: {self.classifications_stored} stored, {self.classifications_processed} total")
        return classifications
    
    
    def get_processing_statistics(self) -> Dict:
        """Get classification processing statistics."""
        return {
            "classifications_processed": self.classifications_processed,
            "classifications_stored": self.classifications_stored,
            "api_statistics": self.api_client.get_api_statistics()
        }

def main():
    """Test Fingerbank API integration."""
    print("Fingerbank API Integration Test")
    print("=" * 35)
    
    try:
        # Initialize API client
        api_client = FingerbankAPIClient()
        classification_manager = DeviceClassificationManager(api_client)
        
        # Test with sample fingerprint
        test_fingerprint = DeviceFingerprint(
            mac_address="00:11:22:33:44:55",
            dhcp_fingerprint="1,3,6,15,119,95,252,44,46,47",
            dhcp_vendor_class="MSFT 5.0",
            hostname="test-windows-pc"
        )
        
        print("Testing device classification...")
        classification = api_client.classify_device(test_fingerprint)
        
        print(f"Classification Result:")
        print(f"  Device Name: {classification.device_name}")
        print(f"  Device Type: {classification.device_type}")
        print(f"  Operating System: {classification.operating_system}")
        print(f"  Confidence Score: {classification.confidence_score}")
        print(f"  Error: {classification.error_message}")
        
        # Show API statistics
        stats = api_client.get_api_statistics()
        print(f"\nAPI Statistics:")
        print(f"  Total Requests: {stats['total_requests']}")
        print(f"  Success Rate: {stats['success_rate']:.1f}%")
        print(f"  Rate Limit Used: {stats['rate_limit_status']['hourly_used']}/{stats['rate_limit_status']['hourly_limit']}")
    
    except Exception as e:
        print(f"API test failed: {e}")

if __name__ == "__main__":
    main()