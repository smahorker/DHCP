#!/usr/bin/env python3
"""
DHCP Device Classification System - Main Entry Point
Network Device Monitoring System with Fingerbank-First Implementation
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from examples.analyze_dhcp_log import main as analyze_main

def main():
    """Main entry point for the DHCP Device Classification System."""
    parser = argparse.ArgumentParser(
        description="DHCP Device Classification System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --log test_logs/realistic_home_network.log
  python main.py --log /var/log/dhcp.log --api-key YOUR_FINGERBANK_KEY
  python main.py --help

For more information, see README.md or docs/
        """
    )
    
    parser.add_argument(
        "--log", 
        type=str, 
        help="Path to DHCP log file to analyze"
    )
    
    parser.add_argument(
        "--api-key", 
        type=str, 
        help="Fingerbank API key (optional, will use local classification if not provided)"
    )
    
    parser.add_argument(
        "--output", 
        type=str, 
        help="Output file for results (default: auto-generated timestamp file)"
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version="DHCP Device Classification System v1.0"
    )
    
    args = parser.parse_args()
    
    # If no arguments provided, run the default example
    if not args.log:
        print("No log file specified. Running default example...")
        return analyze_main()
    
    # TODO: Implement command-line interface for custom log files
    print(f"Analyzing log file: {args.log}")
    print("Custom CLI interface not yet implemented. Please use examples/analyze_dhcp_log.py directly.")
    return None

if __name__ == "__main__":
    main()