# Tests

This directory contains test scripts for the DHCP device classification system.

## Test Scripts

- **realistic_test.py** - Real-world performance testing with home network logs
- **simple_test.py** - Basic functionality testing

## Usage

```bash
# Run realistic scenario test
python3 tests/realistic_test.py

# Run basic functionality test  
python3 tests/simple_test.py
```

## Requirements

- FINGERBANK_API_KEY environment variable (optional but recommended)
- Test log files in test_logs/ directory