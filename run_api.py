#!/usr/bin/env python3
"""
API Server Entry Point
Starts the REST API server with proper imports.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from api.api_server import main

if __name__ == "__main__":
    main()