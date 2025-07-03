# Examples

This directory contains example scripts demonstrating how to use the DHCP Device Classification System.

## Files

- `analyze_dhcp_log.py` - Main analysis script that processes DHCP logs and generates classification results

## Usage

### Basic Analysis
```bash
cd examples/
python analyze_dhcp_log.py
```

This will analyze the test log file and output classification results.

### With Fingerbank API Key
```bash
export FINGERBANK_API_KEY="your_api_key_here"
python analyze_dhcp_log.py
```

## Output

The script will:
1. Parse DHCP log entries
2. Classify devices using Fingerbank API (if available) and enhanced fallback methods
3. Export results to a JSON file with timestamp
4. Display classification statistics

## Example Output
```
DHCP Device Analyzer - Fingerbank-First Implementation
============================================================
Analyzing test log: ../test_logs/realistic_home_network.log

Analysis complete: 23 devices classified

Classification Statistics:
  vendor_lookup_success: 23
  fingerbank_success: 23
  dhcp_fingerprint_success: 0
  fallback_success: 15
  total_devices: 23

Results exported to: results_20250703_123456.json
```