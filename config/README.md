# Configuration

This directory contains configuration files and templates for the DHCP Device Classification System.

## Files

*Currently empty - configuration files can be added here as needed*

## Future Configuration Options

- `fingerbank.conf` - Fingerbank API configuration
- `classification_rules.json` - Custom classification rules
- `vendor_mappings.json` - Custom vendor-to-device-type mappings
- `logging.conf` - Logging configuration

## Environment Variables

The system currently supports these environment variables:

- `FINGERBANK_API_KEY` - Your Fingerbank API key for enhanced device classification

## Example Configuration

```bash
# Set Fingerbank API key
export FINGERBANK_API_KEY="your_api_key_here"

# Run analysis
python main.py --log /path/to/dhcp.log
```