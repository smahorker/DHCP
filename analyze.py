#!/usr/bin/env python3
"""
Main entry point for DHCP Device Analysis
"""

import os
from pathlib import Path
from src.core.dhcp_device_analyzer import OptimizedDHCPDeviceAnalyzer

def main():
    """Main function for testing the analyzer."""
    print("DHCP Device Analyzer - Fingerbank-First Implementation")
    print("=" * 60)
    
    # Get API key from environment
    api_key = os.getenv('FINGERBANK_API_KEY')
    if not api_key:
        print("Warning: No FINGERBANK_API_KEY found in environment variables")
        print("Local classification methods will be used as fallback")
    
    # Initialize analyzer
    analyzer = OptimizedDHCPDeviceAnalyzer(fingerbank_api_key=api_key)
    
    # Test with sample log file
    test_log = Path("test_logs/realistic_home_network.log")
    if test_log.exists():
        print(f"Analyzing test log: {test_log}")
        results = analyzer.analyze_dhcp_log(str(test_log))
        
        print(f"\nAnalysis complete: {len(results)} devices classified")
        print("\nClassification Statistics:")
        for method, count in analyzer.classification_stats.items():
            print(f"  {method}: {count}")
        
        # Export results
        output_file = analyzer.export_results(results)
        print(f"\nResults exported to: {output_file}")
        
        return results
    else:
        print(f"Test log file not found: {test_log}")
        return None

if __name__ == "__main__":
    main()