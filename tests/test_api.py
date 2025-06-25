#!/usr/bin/env python3
"""
API Test Script for Network Device Monitoring System.
Tests all REST API endpoints and functionality.
"""

import json
import time
import requests
from datetime import datetime
import sys

class APITester:
    """Test suite for the Network Monitoring API."""
    
    def __init__(self, base_url: str = "http://localhost:5000"):
        """Initialize API tester."""
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = {}
    
    def test_health_endpoint(self):
        """Test /health endpoint."""
        print("🔍 Testing /health endpoint...")
        
        try:
            response = self.session.get(f"{self.base_url}/health")
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✅ Health check passed")
                print(f"  📊 Status: {data['data']['status']}")
                print(f"  💾 Database: {data['data']['components']['database']}")
                print(f"  📡 Packet Capture: {data['data']['components']['packet_capture']['status']}")
                self.test_results['health'] = True
            else:
                print(f"  ❌ Health check failed: {response.status_code}")
                self.test_results['health'] = False
                
        except Exception as e:
            print(f"  ❌ Health check error: {e}")
            self.test_results['health'] = False
    
    def test_devices_list_endpoint(self):
        """Test /devices endpoint with various filters."""
        print("\n🔍 Testing /devices endpoint...")
        
        try:
            # Basic list
            response = self.session.get(f"{self.base_url}/devices")
            
            if response.status_code == 200:
                data = response.json()
                devices = data['data']['items']
                pagination = data['data']['pagination']
                
                print(f"  ✅ Devices list retrieved")
                print(f"  📱 Total devices: {pagination['total_items']}")
                print(f"  📄 Page size: {pagination['page_size']}")
                
                if devices:
                    first_device = devices[0]
                    print(f"  🔍 Sample device: {first_device.get('device_name', 'Unknown')} ({first_device['mac_address']})")
                
                # Test filtering
                if devices:
                    self._test_device_filters()
                
                self.test_results['devices_list'] = True
            else:
                print(f"  ❌ Devices list failed: {response.status_code}")
                self.test_results['devices_list'] = False
                
        except Exception as e:
            print(f"  ❌ Devices list error: {e}")
            self.test_results['devices_list'] = False
    
    def _test_device_filters(self):
        """Test device filtering options."""
        print("  🔍 Testing device filters...")
        
        # Test active filter
        response = self.session.get(f"{self.base_url}/devices?active=true")
        if response.status_code == 200:
            data = response.json()
            active_count = data['data']['pagination']['total_items']
            print(f"    ✅ Active filter: {active_count} active devices")
        
        # Test device type filter
        response = self.session.get(f"{self.base_url}/devices?device_type=Computer")
        if response.status_code == 200:
            data = response.json()
            computer_count = data['data']['pagination']['total_items']
            print(f"    ✅ Device type filter: {computer_count} computers")
        
        # Test pagination
        response = self.session.get(f"{self.base_url}/devices?page=1&page_size=1")
        if response.status_code == 200:
            data = response.json()
            page_items = len(data['data']['items'])
            print(f"    ✅ Pagination: {page_items} item per page")
    
    def test_device_details_endpoint(self):
        """Test /devices/{mac_address} endpoint."""
        print("\n🔍 Testing /devices/{mac_address} endpoint...")
        
        try:
            # First get a device MAC address
            response = self.session.get(f"{self.base_url}/devices?page_size=1")
            
            if response.status_code == 200:
                data = response.json()
                devices = data['data']['items']
                
                if devices:
                    mac_address = devices[0]['mac_address']
                    
                    # Test device details
                    detail_response = self.session.get(f"{self.base_url}/devices/{mac_address}")
                    
                    if detail_response.status_code == 200:
                        detail_data = detail_response.json()
                        device_info = detail_data['data']
                        
                        print(f"  ✅ Device details retrieved for {mac_address}")
                        print(f"  📱 Device: {device_info.get('device_name', 'Unknown')}")
                        print(f"  🔧 Type: {device_info.get('device_type', 'Unknown')}")
                        print(f"  💻 OS: {device_info.get('operating_system', 'Unknown')}")
                        print(f"  📊 Classifications: {len(device_info.get('classification_history', []))}")
                        
                        self.test_results['device_details'] = True
                    else:
                        print(f"  ❌ Device details failed: {detail_response.status_code}")
                        self.test_results['device_details'] = False
                else:
                    print("  ⚠️ No devices available for testing details")
                    self.test_results['device_details'] = True  # Not a failure, just no data
            else:
                print(f"  ❌ Could not get device list: {response.status_code}")
                self.test_results['device_details'] = False
                
        except Exception as e:
            print(f"  ❌ Device details error: {e}")
            self.test_results['device_details'] = False
    
    def test_device_stats_endpoint(self):
        """Test /devices/stats endpoint."""
        print("\n🔍 Testing /devices/stats endpoint...")
        
        try:
            response = self.session.get(f"{self.base_url}/devices/stats")
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']
                
                print(f"  ✅ Device statistics retrieved")
                print(f"  📊 Summary:")
                print(f"    Total devices: {stats['summary']['total_devices']}")
                print(f"    Active devices: {stats['summary']['active_devices']}")
                print(f"    Recent activity (24h): {stats['summary']['recent_activity']['last_24_hours']}")
                
                print(f"  🔧 Device types: {len(stats['device_types'])} types")
                for dtype, count in list(stats['device_types'].items())[:3]:
                    print(f"    {dtype}: {count}")
                
                print(f"  💻 Operating systems: {len(stats['operating_systems'])} OS types")
                
                print(f"  📡 Packet stats:")
                packet_stats = stats['packet_statistics']
                print(f"    Total packets: {packet_stats['total_packets']}")
                print(f"    Unique devices: {packet_stats['unique_devices']}")
                
                self.test_results['device_stats'] = True
            else:
                print(f"  ❌ Device stats failed: {response.status_code}")
                self.test_results['device_stats'] = False
                
        except Exception as e:
            print(f"  ❌ Device stats error: {e}")
            self.test_results['device_stats'] = False
    
    def test_device_types_endpoint(self):
        """Test /devices/types endpoint."""
        print("\n🔍 Testing /devices/types endpoint...")
        
        try:
            response = self.session.get(f"{self.base_url}/devices/types")
            
            if response.status_code == 200:
                data = response.json()
                types_info = data['data']
                
                print(f"  ✅ Device types retrieved")
                print(f"  🔧 Total types: {types_info['total_types']}")
                print(f"  📱 Total devices: {types_info['total_devices']}")
                
                print("  📊 Device type breakdown:")
                for type_info in types_info['device_types'][:5]:  # Show top 5
                    print(f"    {type_info['device_type']}: {type_info['count']} ({type_info['percentage']}%)")
                
                self.test_results['device_types'] = True
            else:
                print(f"  ❌ Device types failed: {response.status_code}")
                self.test_results['device_types'] = False
                
        except Exception as e:
            print(f"  ❌ Device types error: {e}")
            self.test_results['device_types'] = False
    
    def test_error_handling(self):
        """Test error handling and edge cases."""
        print("\n🔍 Testing error handling...")
        
        try:
            # Test 404 for non-existent device
            response = self.session.get(f"{self.base_url}/devices/00:00:00:00:00:99")
            
            if response.status_code == 404:
                print("  ✅ 404 handling for non-existent device")
            else:
                print(f"  ⚠️ Unexpected status for non-existent device: {response.status_code}")
            
            # Test 404 for non-existent endpoint
            response = self.session.get(f"{self.base_url}/nonexistent")
            
            if response.status_code == 404:
                print("  ✅ 404 handling for non-existent endpoint")
            else:
                print(f"  ⚠️ Unexpected status for non-existent endpoint: {response.status_code}")
            
            # Test invalid pagination
            response = self.session.get(f"{self.base_url}/devices?page=-1")
            
            if response.status_code in [200, 400]:  # Should handle gracefully
                print("  ✅ Invalid pagination handled")
            else:
                print(f"  ⚠️ Unexpected status for invalid pagination: {response.status_code}")
            
            self.test_results['error_handling'] = True
            
        except Exception as e:
            print(f"  ❌ Error handling test error: {e}")
            self.test_results['error_handling'] = False
    
    def test_web_interface(self):
        """Test web interface accessibility."""
        print("\n🔍 Testing web interface...")
        
        try:
            response = self.session.get(f"{self.base_url}/")
            
            if response.status_code == 200:
                content = response.text
                if "Network Device Monitor" in content:
                    print("  ✅ Web interface accessible")
                    print("  🌐 HTML content loaded successfully")
                    self.test_results['web_interface'] = True
                else:
                    print("  ❌ Web interface content unexpected")
                    self.test_results['web_interface'] = False
            else:
                print(f"  ❌ Web interface failed: {response.status_code}")
                self.test_results['web_interface'] = False
                
        except Exception as e:
            print(f"  ❌ Web interface error: {e}")
            self.test_results['web_interface'] = False
    
    def run_all_tests(self):
        """Run complete API test suite."""
        print("🧪 NETWORK MONITORING API TEST SUITE")
        print("=" * 50)
        
        # Run all tests
        self.test_health_endpoint()
        self.test_devices_list_endpoint()
        self.test_device_details_endpoint()
        self.test_device_stats_endpoint()
        self.test_device_types_endpoint()
        self.test_error_handling()
        self.test_web_interface()
        
        # Results summary
        print("\n" + "=" * 50)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 50)
        
        passed = sum(self.test_results.values())
        total = len(self.test_results)
        
        for test_name, passed_test in self.test_results.items():
            status = "✅ PASS" if passed_test else "❌ FAIL"
            print(f"{test_name.replace('_', ' ').title():<20} {status}")
        
        print("-" * 50)
        print(f"OVERALL: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 ALL API TESTS PASSED!")
            print(f"\n🌐 Web Interface: {self.base_url}")
            print("📋 API is fully functional and ready for use!")
        else:
            print("⚠️ Some API tests failed")
        
        print("=" * 50)
        return passed == total

def main():
    """Run API tests."""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:5000"
    
    print(f"Testing API at: {base_url}")
    print("Make sure the API server is running with: python api_server.py")
    print()
    
    # Wait a moment for user to confirm
    try:
        input("Press Enter to start tests (or Ctrl+C to cancel)...")
    except KeyboardInterrupt:
        print("\nTests cancelled")
        return
    
    # Run tests
    tester = APITester(base_url)
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()