#!/usr/bin/env python3
"""
Fingerbank API connectivity test script for network monitoring system.
Tests API authentication and basic device classification.
"""

import os
import sys
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class FingerbankAPITest:
    def __init__(self):
        self.api_key = os.getenv('FINGERBANK_API_KEY')
        self.base_url = "https://api.fingerbank.org/api/v2"
        
    def test_api_connection(self):
        """Test basic API connectivity and authentication."""
        
        if not self.api_key:
            print("✗ FINGERBANK_API_KEY not found in environment variables")
            print("Please add FINGERBANK_API_KEY=your_api_key to your .env file")
            return False
            
        print(f"Testing Fingerbank API connection...")
        print(f"API Key: {self.api_key[:8]}...")
        print()
        
        try:
            # Test authentication endpoint with sample data
            response = requests.get(
                f"{self.base_url}/combinations/interrogate",
                params={
                    'key': self.api_key,
                    'dhcp_fingerprint': '1,3,6,15,119,95,252,44,46,47'
                }
            )
            
            if response.status_code == 200:
                print("✓ API authentication successful!")
                return True
            elif response.status_code == 401:
                print("✗ API authentication failed - Invalid API key")
                return False
            else:
                print(f"✗ API connection failed - Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"✗ API connection failed: {e}")
            return False
    
    def test_device_classification(self):
        """Test device classification with sample data."""
        
        print("Testing device classification...")
        
        # Sample DHCP fingerprint data for testing
        test_data = {
            'dhcp_fingerprint': '1,3,6,15,119,95,252,44,46,47',
            'dhcp_vendor_class': 'MSFT 5.0',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.get(
                f"{self.base_url}/combinations/interrogate",
                params={
                    'key': self.api_key,
                    **test_data
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print("✓ Device classification successful!")
                
                if 'device' in result:
                    device = result['device']
                    print(f"Device: {device.get('name', 'Unknown')}")
                    print(f"Category: {device.get('category', 'Unknown')}")
                    print(f"OS: {device.get('os', 'Unknown')}")
                else:
                    print("No device classification returned")
                
                return True
            else:
                print(f"✗ Device classification failed - Status code: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"✗ Device classification failed: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error during classification: {e}")
            return False

def main():
    print("Network Monitoring System - Fingerbank API Test")
    print("=" * 50)
    
    api_test = FingerbankAPITest()
    
    # Test API connection
    if not api_test.test_api_connection():
        print("\n✗ API connection test failed.")
        print("\nNext steps:")
        print("1. Register for Fingerbank Community API at: https://fingerbank.org/users/register")
        print("2. Get your API key from: https://fingerbank.org/api_keys")
        print("3. Add FINGERBANK_API_KEY=your_api_key to your .env file")
        sys.exit(1)
    
    print()
    
    # Test device classification
    if api_test.test_device_classification():
        print("\n✓ All Fingerbank API tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Device classification test failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()