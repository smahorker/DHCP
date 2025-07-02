# Tools

This directory contains utility scripts and debugging tools for the DHCP Device Classification System.

## 🔧 Available Tools

### **debug_fingerbank.py**
**Purpose**: Fingerbank API debugging and analysis utility

**Features**:
- Tests API connectivity and authentication
- Analyzes individual device fingerprints
- Debugs problematic classifications
- Validates API response format
- Measures API response times

**Usage**:
```bash
cd tools
python3 debug_fingerbank.py
```

**What it does**:
1. Parses realistic test log for device data
2. Sends each device fingerprint to Fingerbank API
3. Analyzes API responses and confidence scores
4. Identifies patterns in classification failures
5. Reports detailed API interaction logs

**Output Example**:
```
FINGERBANK API DEBUG ANALYSIS
========================================

Testing API connectivity...
✅ API accessible and responding

Device Analysis:
MAC: 28:39:5e:f1:65:c1 (Samsung Electronics Co.)
  Fingerprint: 1,121,3,6,15,119,252
  Vendor Class: android-dhcp-13
  API Response: Phone, Tablet or Wearable/Generic Android/Samsung Android
  Confidence: 59
  Status: SUCCESS

MAC: 58:8b:f3:dd:ee:ff (Zyxel Communications Corporation)  
  Fingerprint: None
  Vendor Class: busybox-dhcp
  API Response: Hardware Manufacturer/Zyxel Communications Corporation
  Confidence: 29
  Device Type: None (LOW CONFIDENCE)
  Status: PROBLEMATIC
```

## 📊 Debug Analysis Features

### API Connectivity Testing
```python
def test_api_connectivity():
    # Tests basic API access
    # Validates authentication
    # Measures response times
    # Reports API status
```

### Device Fingerprint Analysis
```python
def analyze_device_fingerprints():
    # Extracts fingerprint data from logs
    # Sends individual API requests
    # Compares local vs API classifications
    # Identifies classification discrepancies
```

### Response Pattern Analysis
- **High Confidence Patterns**: Score ≥60 with device_type
- **Medium Confidence Patterns**: Score 30-59 with device_type  
- **Low Confidence Patterns**: Score ≤29 without device_type
- **Hardware Manufacturer Responses**: Vendor info only

### Rate Limiting Analysis
```python
def test_rate_limiting():
    # Measures API rate limits
    # Tests burst request handling
    # Validates queue management
    # Reports throttling behavior
```

## 🐛 Debugging Common Issues

### Issue 1: API Authentication
**Symptoms**:
- HTTP 401 Unauthorized responses
- "Invalid API key" errors
- All devices fall back to local classification

**Debug Steps**:
```bash
# Check API key
echo $FINGERBANK_API_KEY

# Test API manually
python3 debug_fingerbank.py

# Verify key validity
curl -H "Authorization: Bearer $FINGERBANK_API_KEY" https://fingerbank.org/api/v1/test
```

### Issue 2: Low Classification Rates
**Symptoms**:
- High number of "unknown" classifications
- Many devices with confidence scores ≤29
- Fallback system heavily utilized

**Debug Process**:
1. Run debug tool to identify problematic devices
2. Analyze API response patterns
3. Check data quality (hostname, vendor class availability)
4. Validate DHCP fingerprint extraction

### Issue 3: API Performance
**Symptoms**:
- Slow processing times
- Timeout errors
- Rate limiting messages

**Performance Analysis**:
```python
# Measure API response times
import time
start = time.time()
result = api_client.classify_device(fingerprint)
duration = time.time() - start
print(f"API call took {duration:.2f} seconds")
```

## 🔍 Advanced Debugging

### Custom Device Testing
```python
# Test specific device fingerprint
def debug_specific_device(mac_address):
    fingerprint = DeviceFingerprint(
        mac_address=mac_address,
        dhcp_fingerprint="1,3,6,15,119,252",
        dhcp_vendor_class="custom-device",
        hostname="test-device"
    )
    
    result = api_client.classify_device(fingerprint)
    print(f"Result: {result}")
```

### Batch Testing
```python
# Test multiple devices for patterns
def batch_debug_analysis():
    devices = load_test_devices()
    for device in devices:
        result = analyze_device(device)
        log_result(device, result)
    
    generate_pattern_report()
```

### Response Caching Analysis
```python
# Analyze API response caching
def test_response_caching():
    # Send identical requests
    # Measure response time differences
    # Validate cache behavior
    # Report caching effectiveness
```

## 📈 Performance Monitoring

### API Health Metrics
- **Response Time**: Average API call duration
- **Success Rate**: Percentage of successful API calls
- **Error Rate**: Frequency of API errors
- **Rate Limiting**: Frequency of rate limit hits

### Classification Quality Metrics
- **Confidence Distribution**: Breakdown of API confidence scores
- **Device Type Coverage**: Percentage of responses with device_type
- **Vendor vs Device Mapping**: Analysis of vendor classification patterns
- **Fallback Trigger Rate**: Frequency of local fallback usage

## 🔧 Tool Configuration

### Environment Setup
```bash
# Required environment variables
export FINGERBANK_API_KEY=your_api_key_here

# Optional debug settings
export DEBUG_MODE=true
export LOG_LEVEL=DEBUG
export API_TIMEOUT=30
```

### Debug Output Control
```python
# Enable verbose output
DEBUG_VERBOSE = True

# Log API requests/responses
LOG_API_CALLS = True

# Save debug data to files
SAVE_DEBUG_DATA = True
```

## 📝 Debug Report Generation

### Automated Reporting
```bash
# Generate comprehensive debug report
python3 debug_fingerbank.py --report > fingerbank_debug_report.txt

# Generate JSON output for analysis
python3 debug_fingerbank.py --json > debug_results.json
```

### Report Contents
- API connectivity status
- Device-by-device analysis
- Classification failure patterns  
- Performance metrics
- Recommendations for improvement

## 🚀 Integration with Testing

### Test Integration
```python
# Use debug tool in test pipeline
def test_api_performance():
    debug_results = run_fingerbank_debug()
    assert debug_results['success_rate'] > 0.8
    assert debug_results['avg_response_time'] < 2.0
```

### Continuous Monitoring
- Run debug tool periodically
- Monitor API performance trends
- Alert on classification degradation
- Track API quota usage

## 🔒 Security Considerations

### API Key Protection
- Never log API keys in debug output
- Use environment variables only
- Rotate keys regularly
- Monitor for unauthorized usage

### Data Privacy
- Debug tool respects same privacy rules
- Only MAC prefixes sent to API
- Local processing for sensitive data
- No credential storage

The debugging tools provide comprehensive analysis capabilities for maintaining and optimizing the Fingerbank-first classification system.