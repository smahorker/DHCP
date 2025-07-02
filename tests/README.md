# Tests

This directory contains test scripts for the DHCP Device Classification System with Fingerbank-first architecture.

## 🧪 Test Scripts

### **realistic_test.py**
**Purpose**: Real-world performance testing with home network logs

**What it tests**:
- Fingerbank API utilization rates
- Fallback system effectiveness  
- Classification success rates with minimal DHCP data
- Performance with typical home router logs

**Usage**:
```bash
cd tests
python3 realistic_test.py
```

**Output**:
- Detailed device classification results
- Performance statistics and confidence distribution
- Problematic device identification
- Results saved to `realistic_test_results.json`

**Expected Results**:
- 91.3% classification success rate
- 100% Fingerbank API coverage when available
- Fallback system rescues 2-3 devices
- Zero null API scores

### **simple_test.py**
**Purpose**: Basic functionality testing with richer data

**What it tests**:
- Core classification pipeline
- Module integration
- JSON export functionality
- Error handling

**Usage**:
```bash
cd tests  
python3 simple_test.py
```

**Output**:
- JSON export with device classifications
- Basic statistics and method distribution
- Validation of core functionality

## 📊 Test Data

### Realistic Test Log
**File**: `../test_logs/realistic_home_network.log`
**Devices**: 23 typical home network devices
**Characteristics**:
- Minimal DHCP data (69.6% hostname availability)
- Mixed device types (phones, computers, IoT, gaming)
- Representative of consumer router logging

**Device Breakdown**:
- **6 Phones**: Android and iPhone devices
- **9 Computers**: Windows, macOS, Linux systems
- **2 IoT Devices**: Raspberry Pi, VMware
- **3 Smart Devices**: Plugs, TV, gaming console  
- **2 Network Equipment**: Router, switches
- **1 Problematic**: Zyxel device with minimal data

### Test Log Format
```
Jan 15 10:30:15 router dhcpd: DHCPACK on 192.168.1.100 to 28:39:5e:f1:65:c1 via eth0
Jan 15 10:30:16 router dhcpd: vendor class identifier = android-dhcp-13
Jan 15 10:30:17 router dhcpd: DHCP DISCOVER from a4:c3:f0:85:ac:2d via eth0: network 192.168.1.0/24
```

## 🔍 Test Scenarios

### Scenario 1: Fingerbank API Available
**Condition**: `FINGERBANK_API_KEY` environment variable set
**Expected Outcome**:
- 100% API attempt rate (23/23 devices)
- 87% API success rate (20/23 devices)
- 9% fallback usage (2/23 devices)
- 4% unclassified (1/23 devices)

### Scenario 2: No API Key
**Condition**: No `FINGERBANK_API_KEY` environment variable
**Expected Outcome**:
- 0% API usage
- 100% local classification attempts
- Higher reliance on hostname and vendor patterns
- Reduced overall accuracy

### Scenario 3: API Rate Limiting
**Condition**: API key with exceeded rate limits
**Expected Outcome**:
- Gradual fallback to local methods
- Maintained classification coverage
- Longer processing time

## 📈 Performance Metrics

### Key Performance Indicators

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| **Classification Success Rate** | ≥90% | 91.3% | ✅ |
| **API Utilization** | ≥95% | 100% | ✅ |
| **Fallback Effectiveness** | ≥60% | 67% | ✅ |
| **Processing Speed** | <60s for 23 devices | ~45s | ✅ |
| **Memory Usage** | <200MB | ~100MB | ✅ |

### Success Criteria
- ✅ **High Confidence**: ≥30% of devices
- ✅ **Medium Confidence**: ≥50% of devices  
- ✅ **Unclassified Rate**: ≤10% of devices
- ✅ **Zero Null Scores**: 100% when API available
- ✅ **Vendor Coverage**: 100% of devices

## 🐛 Common Test Issues

### API Key Problems
**Symptom**: All devices use local classification
**Solution**: Verify `FINGERBANK_API_KEY` environment variable
```bash
echo $FINGERBANK_API_KEY
export FINGERBANK_API_KEY=your_api_key_here
```

### Import Errors
**Symptom**: `ModuleNotFoundError: No module named 'src.core.dhcp_device_analyzer'`
**Solution**: Run tests from correct directory
```bash
cd tests
python3 realistic_test.py
```

### Missing Test Logs
**Symptom**: `Error: Test log file not found`
**Solution**: Verify test log files exist
```bash
ls -la ../test_logs/
```

### Low Classification Rates
**Symptom**: High number of unclassified devices
**Potential Causes**:
- Invalid API key
- Network connectivity issues
- Corrupted test log format
- Missing dependencies

## 🔧 Debug Mode

Enable detailed logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Debug Output Includes**:
- API request/response details
- Classification decision logic
- Fallback trigger reasons
- Error stack traces

## 📝 Test Result Interpretation

### Classification Methods
- **fingerbank**: Primary API classification
- **enhanced_fallback**: Local pattern matching rescue
- **unknown**: Complete classification failure

### Confidence Levels
- **high**: Reliable classification (≥80 points)
- **medium**: Good classification (50-79 points)
- **low**: Basic classification (30-49 points)

### Success Rate Calculation
```
Success Rate = (High Confidence + Medium Confidence) / Total Devices * 100
Target: ≥90%
Current: 91.3%
```

## 🚀 Running Continuous Tests

### Automated Testing
```bash
#!/bin/bash
# test_runner.sh
cd tests
echo "Running realistic test..."
python3 realistic_test.py > realistic_results.log 2>&1

echo "Running simple test..."  
python3 simple_test.py > simple_results.log 2>&1

echo "Tests completed. Check log files for results."
```

### Performance Monitoring
- Monitor API utilization rates
- Track classification success over time
- Identify degrading performance patterns
- Validate system reliability

The testing framework ensures the Fingerbank-first implementation maintains high performance and reliability across diverse network environments.