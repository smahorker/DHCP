#!/usr/bin/env python3
"""
Complete System Test for Network Device Monitoring System.
Run this script to verify all components are working correctly.
"""

import os
import sys
import time
from datetime import datetime

def test_environment():
    """Test environment and dependencies."""
    print("1. TESTING ENVIRONMENT & DEPENDENCIES")
    print("-" * 40)
    
    try:
        # Test imports
        import scapy
        import psycopg2
        import requests
        from dotenv import load_dotenv
        
        load_dotenv()
        
        print("✓ All required packages imported successfully")
        
        # Check API key
        api_key = os.getenv('FINGERBANK_API_KEY')
        if api_key:
            print(f"✓ Fingerbank API key configured: {api_key[:8]}...")
        else:
            print("⚠ No Fingerbank API key found")
        
        return True
        
    except ImportError as e:
        print(f"✗ Missing package: {e}")
        return False
    except Exception as e:
        print(f"✗ Environment error: {e}")
        return False

def test_database():
    """Test database connectivity and schema."""
    print("\n2. TESTING DATABASE")
    print("-" * 40)
    
    try:
        from src.core.database import initialize_database, get_dhcp_store, get_device_store
        
        # Test connection
        db_manager = initialize_database()
        print("✓ Database connection pool established")
        
        # Test stores
        dhcp_store = get_dhcp_store()
        device_store = get_device_store()
        
        # Test basic operations
        stats = dhcp_store.get_packet_statistics()
        devices = device_store.get_active_devices()
        
        print(f"✓ Database operations working")
        print(f"  - Total packets in DB: {stats['total_packets']}")
        print(f"  - Active devices: {len(devices)}")
        
        db_manager.close_all_connections()
        return True
        
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        if "Connection refused" in str(e):
            print("  → Start database with: docker-compose up -d")
        return False

def test_packet_capture():
    """Test packet capture capabilities."""
    print("\n3. TESTING PACKET CAPTURE")
    print("-" * 40)
    
    try:
        from src.core.packet_capture import DHCPPacketCaptureEngine
        
        # Test engine creation
        engine = DHCPPacketCaptureEngine(store_packets=False)
        print(f"✓ Packet capture engine created")
        print(f"  - Interface: {engine.interface}")
        print(f"  - Filter: {engine.packet_filter}")
        
        # Test permissions (short test)
        print("  - Testing capture permissions...")
        engine.start()
        time.sleep(2)  # Brief test
        engine.stop()
        
        stats = engine.get_statistics()
        print(f"✓ Packet capture test completed")
        print(f"  - Test captured {stats['packets_captured']} packets")
        
        return True
        
    except Exception as e:
        print(f"✗ Packet capture test failed: {e}")
        if "Permission denied" in str(e):
            print("  → Run with: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.12")
        return False

def test_fingerbank_api():
    """Test Fingerbank API connectivity."""
    print("\n4. TESTING FINGERBANK API")
    print("-" * 40)
    
    try:
        from src.core.fingerbank_api import FingerbankAPIClient
        from src.core.dhcp_parser import DeviceFingerprint
        
        # Test API client
        client = FingerbankAPIClient()
        print("✓ Fingerbank API client initialized")
        
        # Test classification with sample data
        test_fingerprint = DeviceFingerprint(
            mac_address="00:11:22:33:44:55",
            dhcp_fingerprint="1,3,6,15,119,95,252,44,46,47",
            dhcp_vendor_class="MSFT 5.0"
        )
        
        classification = client.classify_device(test_fingerprint)
        
        if classification.error_message:
            print(f"⚠ API returned: {classification.error_message}")
        else:
            print(f"✓ Device classified: {classification.device_name}")
            print(f"  - Type: {classification.device_type}")
            print(f"  - Confidence: {classification.confidence_score}")
        
        # Check rate limits
        stats = client.get_api_statistics()
        rate_status = stats['rate_limit_status']
        print(f"✓ Rate limiting working: {rate_status['hourly_used']}/{rate_status['hourly_limit']} used")
        
        return True
        
    except Exception as e:
        print(f"✗ Fingerbank API test failed: {e}")
        if "API key" in str(e):
            print("  → Set FINGERBANK_API_KEY in .env file")
        return False

def test_integration():
    """Test integrated system functionality."""
    print("\n5. TESTING SYSTEM INTEGRATION")
    print("-" * 40)
    
    try:
        from src.network_monitor import NetworkMonitoringSystem
        
        # Test system initialization
        system = NetworkMonitoringSystem()
        print("✓ Network monitoring system initialized")
        
        # Test status reporting
        status = system.get_system_status()
        print("✓ Status reporting working")
        
        # Test device listing
        devices = system.get_device_list()
        print(f"✓ Device listing working: {len(devices)} devices found")
        
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        return False

def main():
    """Run complete system test."""
    print("NETWORK DEVICE MONITORING SYSTEM - COMPLETE TEST")
    print("=" * 60)
    print(f"Test started at: {datetime.now()}")
    print("=" * 60)
    
    # Run all tests
    tests = [
        ("Environment", test_environment),
        ("Database", test_database),
        ("Packet Capture", test_packet_capture),
        ("Fingerbank API", test_fingerbank_api),
        ("Integration", test_integration)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"✗ {test_name} test crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, passed_test in results.items():
        status = "✓ PASS" if passed_test else "✗ FAIL"
        print(f"{test_name:<20} {status}")
    
    print("-" * 60)
    print(f"OVERALL: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED - System is ready!")
        print("\nTo start monitoring:")
        print("python network_monitor.py")
    else:
        print("⚠ Some tests failed - check output above")
        if not results.get("Database", False):
            print("\nMost likely fix: Start the database")
            print("docker-compose up -d")
    
    print("=" * 60)
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)