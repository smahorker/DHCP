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
from .database import get_classification_store, get_device_store
from .dhcp_parser import DeviceFingerprint

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    """Device classification result from Fingerbank API."""
    fingerbank_device_id: Optional[int] = None
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    operating_system: Optional[str] = None
    confidence_score: Optional[int] = None
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
        
        # Add fingerprint data to request
        if fingerprint.dhcp_fingerprint:
            params['dhcp_fingerprint'] = fingerprint.dhcp_fingerprint
        
        if fingerprint.dhcp_vendor_class:
            params['dhcp_vendor_class'] = fingerprint.dhcp_vendor_class
        
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
        Parse Fingerbank API response and extract device classification.
        Phase 5: Extract device name, type, OS, and confidence score.
        """
        classification = DeviceClassification(raw_response=response_data)
        
        try:
            # Handle different response formats
            if 'device' in response_data:
                device_info = response_data['device']
                
                # Extract device information
                classification.fingerbank_device_id = device_info.get('id')
                classification.device_name = device_info.get('name')
                classification.device_type = device_info.get('category')
                classification.operating_system = device_info.get('os')
                
                # Extract confidence score
                classification.confidence_score = response_data.get('score', 0)
                
            elif 'error' in response_data:
                classification.error_message = response_data['error']
                
            else:
                # Handle unknown device responses
                classification.error_message = "Unknown device - no classification available"
                classification.confidence_score = 0
            
            return classification
        
        except Exception as e:
            logger.error(f"Error parsing API response: {e}")
            classification.error_message = f"Failed to parse API response: {e}"
            return classification
    
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
    Phase 5: Handle classification storage and device inventory updates.
    """
    
    def __init__(self, api_client: FingerbankAPIClient):
        """Initialize classification manager."""
        self.api_client = api_client
        self.classification_store = get_classification_store()
        self.device_store = get_device_store()
        
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
                
                # Store classification in database
                if not classification.error_message:
                    self._store_classification(fingerprint.mac_address, classification)
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
    
    def _store_classification(self, mac_address: str, classification: DeviceClassification):
        """Store device classification in database."""
        try:
            self.classification_store.insert_classification(
                mac_address=mac_address,
                fingerbank_device_id=classification.fingerbank_device_id,
                device_name=classification.device_name,
                device_type=classification.device_type,
                operating_system=classification.operating_system,
                confidence_score=classification.confidence_score,
                fingerbank_raw_response=classification.raw_response
            )
            
            # Update active device inventory
            self.device_store.upsert_active_device(
                mac_address=mac_address,
                device_name=classification.device_name,
                device_type=classification.device_type,
                operating_system=classification.operating_system
            )
            
            logger.debug(f"Stored classification for {mac_address}")
        
        except Exception as e:
            logger.error(f"Failed to store classification for {mac_address}: {e}")
    
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