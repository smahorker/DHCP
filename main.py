#!/usr/bin/env python3
"""
Network Device Monitoring System - Main Entry Point
Organized project structure with proper imports.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from network_monitor import main

if __name__ == "__main__":
    main()