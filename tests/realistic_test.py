#!/usr/bin/env python3
"""
Realistic DHCP Log Test - Testing with minimal home router data
Evaluates system performance with real-world DHCP log limitations
"""

import json
import logging
from pathlib import Path
from datetime import datetime
import sys
sys.path.append('..')
from src.core.dhcp_device_analyzer import OptimizedDHCPDeviceAnalyzer, DeviceClassificationResult

# Configure logging to see detailed output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_realistic_dhcp_logs():
    """Test the system with realistic home router DHCP logs."""
    print("=" * 60)
    print("REALISTIC DHCP LOG ANALYSIS TEST")
    print("=" * 60)
    print()
    
    # Initialize the analyzer with API key
    import os
    api_key = os.getenv('FINGERBANK_API_KEY')
    analyzer = OptimizedDHCPDeviceAnalyzer(fingerbank_api_key=api_key)
    
    # Test with realistic home network log
    log_file = Path("test_logs/realistic_home_network.log")
    
    if not log_file.exists():
        print(f"Error: Test log file not found: {log_file}")
        return
    
    print(f"Testing with realistic home network log: {log_file}")
    print()
    
    try:
        # Analyze the log file
        results = analyzer.analyze_dhcp_log(str(log_file))
        
        print(f"Analysis Results:")
        print(f"  Total devices detected: {len(results)}")
        print(f"  Analysis timestamp: {datetime.now().isoformat()}")
        print()
        
        # Detailed analysis of each device
        classification_stats = {
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0,
            'unknown_confidence': 0,
            'vendor_only': 0,
            'fingerbank_used': 0,
            'fallback_used': 0,
            'hostname_available': 0,
            'vendor_class_available': 0
        }
        
        device_types = {}
        operating_systems = {}
        vendors = {}
        
        print("DEVICE CLASSIFICATION RESULTS:")
        print("-" * 40)
        
        for i, result in enumerate(results, 1):
            print(f"{i:2d}. MAC: {result.mac_address}")
            print(f"    Vendor: {result.vendor or 'Unknown'}")
            print(f"    Device Type: {result.device_type or 'Unknown'}")
            print(f"    OS: {result.operating_system or 'Unknown'}")
            print(f"    Classification: {result.classification or 'Unknown'}")
            print(f"    Hostname: {result.hostname or 'None'}")
            print(f"    Overall Confidence: {result.overall_confidence}")
            print(f"    Vendor Class: {'Yes' if result.vendor_class else 'No'}")
            print(f"    Fingerbank Score: {result.fingerbank_confidence or 'N/A'}")
            print()
            
            # Collect statistics
            confidence = result.overall_confidence.lower()
            if confidence == 'high':
                classification_stats['high_confidence'] += 1
            elif confidence == 'medium':
                classification_stats['medium_confidence'] += 1
            elif confidence == 'low':
                classification_stats['low_confidence'] += 1
            else:
                classification_stats['unknown_confidence'] += 1
            
            if result.hostname:
                classification_stats['hostname_available'] += 1
            if result.vendor_class:
                classification_stats['vendor_class_available'] += 1
            if result.fingerbank_confidence:
                classification_stats['fingerbank_used'] += 1
            if result.device_type == 'Unknown' and result.vendor:
                classification_stats['vendor_only'] += 1
            
            # Count device types and OSes
            device_type = result.device_type or 'Unknown'
            device_types[device_type] = device_types.get(device_type, 0) + 1
            
            os = result.operating_system or 'Unknown'
            operating_systems[os] = operating_systems.get(os, 0) + 1
            
            vendor = result.vendor or 'Unknown'
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        # Print detailed statistics
        print("CLASSIFICATION STATISTICS:")
        print("-" * 30)
        total_devices = len(results)
        
        print(f"Confidence Distribution:")
        print(f"  High:    {classification_stats['high_confidence']:2d} ({classification_stats['high_confidence']/total_devices*100:5.1f}%)")
        print(f"  Medium:  {classification_stats['medium_confidence']:2d} ({classification_stats['medium_confidence']/total_devices*100:5.1f}%)")
        print(f"  Low:     {classification_stats['low_confidence']:2d} ({classification_stats['low_confidence']/total_devices*100:5.1f}%)")
        print(f"  Unknown: {classification_stats['unknown_confidence']:2d} ({classification_stats['unknown_confidence']/total_devices*100:5.1f}%)")
        print()
        
        print(f"Data Availability:")
        print(f"  Hostname:         {classification_stats['hostname_available']:2d} ({classification_stats['hostname_available']/total_devices*100:5.1f}%)")
        print(f"  Vendor Class:     {classification_stats['vendor_class_available']:2d} ({classification_stats['vendor_class_available']/total_devices*100:5.1f}%)")
        print()
        
        print(f"Classification Methods:")
        print(f"  Fingerbank API:   {classification_stats['fingerbank_used']:2d} ({classification_stats['fingerbank_used']/total_devices*100:5.1f}%)")
        print(f"  Vendor Only:      {classification_stats['vendor_only']:2d} ({classification_stats['vendor_only']/total_devices*100:5.1f}%)")
        print()
        
        print("Device Type Distribution:")
        for device_type, count in sorted(device_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {device_type:<15}: {count:2d} ({count/total_devices*100:5.1f}%)")
        print()
        
        print("Operating System Distribution:")
        for os, count in sorted(operating_systems.items(), key=lambda x: x[1], reverse=True):
            print(f"  {os:<15}: {count:2d} ({count/total_devices*100:5.1f}%)")
        print()
        
        print("Top Vendors:")
        for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {vendor:<25}: {count:2d}")
        print()
        
        # Identify problematic cases
        print("PROBLEMATIC CLASSIFICATIONS:")
        print("-" * 35)
        
        problem_cases = []
        for result in results:
            if (not result.hostname or not result.vendor_class or 
                result.device_type == 'Unknown' or result.operating_system == 'Unknown' or
                result.overall_confidence in ['low', 'unknown']):
                problem_cases.append({
                    'mac': result.mac_address,
                    'vendor': result.vendor,
                    'hostname': result.hostname
                })
        
        for case in problem_cases:
            print(f"MAC: {case['mac']} ({case['vendor']})")
            print(f"  Hostname: {case['hostname'] or 'None'}")
            print()
        
        # Save results for further analysis
        results_data = {
            'timestamp': datetime.now().isoformat(),
            'total_devices': len(results),
            'statistics': classification_stats,
            'device_types': device_types,
            'operating_systems': operating_systems,
            'vendors': dict(list(vendors.items())[:20]),  # Top 20 vendors
            'devices': [
                {
                    'mac_address': r.mac_address,
                    'vendor': r.vendor,
                    'device_type': r.device_type,
                    'operating_system': r.operating_system,
                    'hostname': r.hostname,
                    'overall_confidence': r.overall_confidence,
                    'has_vendor_class': bool(r.vendor_class),
                    'fingerbank_score': r.fingerbank_confidence
                }
                for r in results
            ]
        }
        
        # Save to file
        output_file = "realistic_test_results.json"
        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        
        print(f"Detailed results saved to: {output_file}")
        print()
        
        # Final assessment
        print("REAL-WORLD PERFORMANCE ASSESSMENT:")
        print("-" * 40)
        
        success_rate = (classification_stats['high_confidence'] + classification_stats['medium_confidence']) / total_devices * 100
        data_richness = classification_stats['hostname_available'] / total_devices * 100
        
        print(f"Overall Success Rate: {success_rate:.1f}% (High+Medium confidence)")
        print(f"Data Richness: {data_richness:.1f}% (Devices with hostnames)")
        print(f"Unknown Device Types: {device_types.get('Unknown', 0)} devices")
        print(f"Vendor-Only Classifications: {classification_stats['vendor_only']} devices")
        
        if success_rate < 70:
            print("⚠️  WARNING: Success rate below 70% - System struggles with minimal DHCP data")
        elif success_rate < 85:
            print("⚠️  NOTICE: Moderate success rate - Room for improvement with sparse data")
        else:
            print("✅ GOOD: Success rate above 85%")
        
        if data_richness < 50:
            print("⚠️  WARNING: Very limited hostname data available (typical of cheap routers)")
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise

def main():
    """Run the realistic DHCP log analysis test."""
    analyze_realistic_dhcp_logs()

if __name__ == "__main__":
    main()