#!/usr/bin/env python3
"""
Test Runner for Network Monitoring System
Runs all tests with proper imports.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the system test
sys.path.append(os.path.join(os.path.dirname(__file__), 'tests'))
from system_test import main

if __name__ == "__main__":
    main()