# API Reference Guide

## Core Classes and Methods

### OptimizedDHCPDeviceAnalyzer

Main orchestration class for device classification.

#### Constructor

```python
OptimizedDHCPDeviceAnalyzer(fingerbank_api_key: Optional[str] = None)
```

**Parameters:**
- `fingerbank_api_key`: Optional Fingerbank API key for enhanced classification

**Example:**
```python
# Basic usage (vendor lookup + fallback only)
analyzer = OptimizedDHCPDeviceAnalyzer()

# Enhanced usage (with Fingerbank API)
analyzer = OptimizedDHCPDeviceAnalyzer(fingerbank_api_key="your_api_key")
```

#### Methods

##### `analyze_dhcp_log(log_file_path: str) -> List[DeviceClassificationResult]`

Analyze DHCP log file and return device classifications.

**Parameters:**
- `log_file_path`: Path to DHCP log file

**Returns:**
- List of `DeviceClassificationResult` objects

**Example:**
```python
results = analyzer.analyze_dhcp_log("/var/log/dhcp.log")
for device in results:
    print(f"{device.mac_address}: {device.device_type}")
```

##### `get_statistics() -> Dict[str, Any]`

Get analysis statistics and performance metrics.

**Returns:**
- Dictionary with classification statistics

**Example:**
```python
stats = analyzer.get_statistics()
print(f"Success rate: {stats['classification_success_rate']:.1f}%")
```

---

### DHCPLogParser

DHCP log parsing engine supporting multiple formats.

#### Constructor

```python
DHCPLogParser()
```

#### Methods

##### `parse_log_file(file_path: Union[str, Path]) -> List[DHCPLogEntry]`

Parse DHCP log file and extract device entries.

**Parameters:**
- `file_path`: Path to log file

**Returns:**
- List of `DHCPLogEntry` objects

**Example:**
```python
parser = DHCPLogParser()
entries = parser.parse_log_file("/var/log/dhcp.log")
```

##### `parse_log_content(log_content: str) -> List[DHCPLogEntry]`

Parse DHCP log content from string.

**Parameters:**
- `log_content`: Raw log content as string

**Returns:**
- List of `DHCPLogEntry` objects

**Example:**
```python
with open("dhcp.log", "r") as f:
    content = f.read()
entries = parser.parse_log_content(content)
```

##### `detect_log_format(sample_lines: List[str]) -> Optional[str]`

Detect log format from sample lines.

**Parameters:**
- `sample_lines`: List of sample log lines

**Returns:**
- Detected format name or None

**Example:**
```python
sample = ["DHCPACK on 192.168.1.100 to aa:bb:cc:dd:ee:ff"]
format_name = parser.detect_log_format(sample)
print(f"Detected format: {format_name}")
```

##### `get_statistics() -> Dict[str, int]`

Get parsing statistics.

**Returns:**
- Dictionary with parsing metrics

---

### MACVendorLookup

IEEE OUI database interface for vendor identification.

#### Constructor

```python
MACVendorLookup(oui_file_path: Optional[str] = None)
```

**Parameters:**
- `oui_file_path`: Optional custom OUI database path

#### Methods

##### `lookup_vendor(mac_address: str) -> Dict[str, Optional[str]]`

Look up vendor information for MAC address.

**Parameters:**
- `mac_address`: MAC address in any standard format

**Returns:**
- Dictionary with vendor information

**Example:**
```python
lookup = MACVendorLookup()
result = lookup.lookup_vendor("aa:bb:cc:dd:ee:ff")
print(f"Vendor: {result['vendor']}")
```

**Return Format:**
```python
{
    'mac_address': 'aa:bb:cc:dd:ee:ff',
    'oui': 'aa:bb:cc', 
    'vendor': 'Apple, Inc.',
    'vendor_full': 'Apple, Inc.',
    'country': 'US',
    'confidence': 'high',
    'source': 'oui_database'
}
```

##### `download_oui_database() -> bool`

Download latest OUI database from IEEE.

**Returns:**
- True if successful, False otherwise

**Example:**
```python
success = lookup.download_oui_database()
if success:
    print("OUI database updated successfully")
```

---

### FingerbankAPIClient

Fingerbank API integration for advanced device classification.

#### Constructor

```python
FingerbankAPIClient(api_key: str)
```

**Parameters:**
- `api_key`: Fingerbank API key

#### Methods

##### `classify_device(fingerprint: DeviceFingerprint) -> DeviceClassification`

Classify device using Fingerbank API.

**Parameters:**
- `fingerprint`: Device fingerprint data

**Returns:**
- `DeviceClassification` object

**Example:**
```python
client = FingerbankAPIClient("your_api_key")
fingerprint = DeviceFingerprint(
    mac_address="aa:bb:cc:dd:ee:ff",
    hostname="iPhone-John"
)
result = client.classify_device(fingerprint)
```

##### `get_api_statistics() -> Dict[str, int]`

Get API usage statistics.

**Returns:**
- Dictionary with API metrics

---

### EnhancedFallbackClassifier

Fallback classification for 100% device detection.

#### Constructor

```python
EnhancedFallbackClassifier()
```

#### Methods

##### `classify_device(device_data: Dict[str, Any]) -> Dict[str, str]`

Classify device using fallback methods.

**Parameters:**
- `device_data`: Dictionary with device information

**Returns:**
- Dictionary with classification results

**Example:**
```python
classifier = EnhancedFallbackClassifier()
result = classifier.classify_device({
    'vendor': 'Apple, Inc.',
    'hostname': 'iPhone-John',
    'mac_address': 'aa:bb:cc:dd:ee:ff'
})
```

---

## Data Structures

### DeviceClassificationResult

Complete device classification output.

```python
@dataclass
class DeviceClassificationResult:
    # Core identification
    mac_address: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    
    # Vendor information
    vendor: Optional[str] = None
    vendor_confidence: str = "unknown"
    
    # Device classification  
    operating_system: Optional[str] = None
    device_type: Optional[str] = None
    device_name: Optional[str] = None
    classification: Optional[str] = None
    
    # Confidence scores
    fingerbank_confidence: Optional[int] = None
    dhcp_fingerprint_confidence: Optional[str] = None
    overall_confidence: str = "unknown"
    
    # Raw data
    dhcp_fingerprint: Optional[str] = None
    vendor_class: Optional[str] = None
    
    # Metadata
    classification_method: Optional[str] = None
    timestamp: datetime = None
```

**Example:**
```python
result = DeviceClassificationResult(
    mac_address="aa:bb:cc:dd:ee:ff",
    vendor="Apple, Inc.",
    device_type="Phone",
    operating_system="iOS",
    overall_confidence="high"
)
```

### DHCPLogEntry

Parsed DHCP log entry with extracted options.

```python
@dataclass  
class DHCPLogEntry:
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    
    # DHCP options
    vendor_class: Optional[str] = None          # Option 60
    dhcp_fingerprint: Optional[str] = None      # Option 55
    client_fqdn: Optional[str] = None           # Option 81
    user_class: Optional[str] = None            # Option 77
    client_arch: Optional[str] = None           # Option 93
    vendor_specific: Optional[str] = None       # Option 43
    domain_name: Optional[str] = None           # Option 15
    
    # All options
    dhcp_options: Dict = None
    
    # Metadata
    message_type: Optional[str] = None
    timestamp: datetime = None
    raw_log_line: str = None
```

### DeviceFingerprint

Input data for Fingerbank API classification.

```python
@dataclass
class DeviceFingerprint:
    mac_address: str
    
    # DHCP data
    dhcp_fingerprint: Optional[str] = None
    dhcp6_fingerprint: Optional[str] = None  
    dhcp_vendor_class: Optional[str] = None
    dhcp6_enterprise: Optional[str] = None
    hostname: Optional[str] = None
    client_fqdn: Optional[str] = None
    
    # Network traffic patterns
    user_agents: Optional[List[str]] = None
    destination_hosts: Optional[List[str]] = None
    
    # Advanced fingerprinting
    tcp_syn_signatures: Optional[List[str]] = None
    ja3_fingerprints: Optional[List[str]] = None
    ja3_data: Optional[Dict] = None
    
    # UPnP and mDNS
    upnp_user_agents: Optional[List[str]] = None
    upnp_server_strings: Optional[List[str]] = None
    mdns_services: Optional[List[str]] = None
    
    # HTTP client hints
    client_hints: Optional[Dict] = None
```

### DeviceClassification

Fingerbank API response data.

```python
@dataclass
class DeviceClassification:
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    operating_system: Optional[str] = None
    manufacturer: Optional[str] = None
    version: Optional[str] = None
    confidence_score: Optional[int] = None
    device_hierarchy: Optional[List[str]] = None
    
    # Response metadata
    raw_response: Dict = None
    error_message: Optional[str] = None
    api_version: Optional[str] = None
    request_id: Optional[str] = None
```

---

## Configuration Options

### Environment Variables

```python
# Required for enhanced classification
FINGERBANK_API_KEY=your_api_key_here

# Optional customizations  
OUI_DATABASE_PATH=/custom/path/oui.csv
LOG_LEVEL=INFO
FINGERBANK_BASE_URL=https://api.fingerbank.org
FINGERBANK_REQUESTS_PER_HOUR=100
FINGERBANK_REQUESTS_PER_DAY=1000

# Performance tuning
MAX_ENTRIES_PER_DEVICE=10
CONFIDENCE_THRESHOLD=50
ENABLE_DEBUG_LOGGING=false
```

### Runtime Configuration

```python
# Analyzer configuration
config = {
    'fingerbank_api_key': 'your_key',
    'enable_dhcp_fingerprinting': True,
    'enable_enhanced_fallback': True,
    'confidence_threshold': 50,
    'max_api_requests_per_batch': 100
}

analyzer = OptimizedDHCPDeviceAnalyzer(**config)
```

---

## Error Handling

### Exception Types

#### `DHCPParsingError`
Raised when log parsing fails.

```python
try:
    entries = parser.parse_log_file("invalid.log")
except DHCPParsingError as e:
    print(f"Parsing failed: {e}")
```

#### `FingerbankAPIError`  
Raised for Fingerbank API issues.

```python
try:
    result = client.classify_device(fingerprint)
except FingerbankAPIError as e:
    print(f"API error: {e}")
```

#### `RateLimitExceededError`
Raised when API rate limits are exceeded.

```python
try:
    result = client.classify_device(fingerprint)
except RateLimitExceededError as e:
    print(f"Rate limited. Wait {e.retry_after} seconds")
```

### Error Recovery

```python
def robust_classification(analyzer, log_file):
    """Example of robust error handling"""
    try:
        return analyzer.analyze_dhcp_log(log_file)
    except DHCPParsingError:
        # Try alternative parser
        return analyzer.analyze_with_fallback_parser(log_file)
    except FingerbankAPIError:
        # Disable API and use local classification
        analyzer.disable_fingerbank()
        return analyzer.analyze_dhcp_log(log_file)
    except Exception as e:
        # Log error and return empty results
        logger.error(f"Classification failed: {e}")
        return []
```

---

## Performance Guidelines

### Best Practices

1. **Batch Processing**: Process multiple log files together
2. **Rate Limiting**: Respect Fingerbank API limits
3. **Caching**: Cache vendor lookups for repeated MAC addresses  
4. **Memory Management**: Process large logs in chunks

### Optimization Examples

```python
# Efficient batch processing
def process_multiple_logs(log_files):
    analyzer = OptimizedDHCPDeviceAnalyzer()
    all_results = []
    
    for log_file in log_files:
        results = analyzer.analyze_dhcp_log(log_file)
        all_results.extend(results)
        
        # Respect rate limits
        time.sleep(1)
    
    return all_results

# Memory-efficient large file processing  
def process_large_log(log_file, chunk_size=1000):
    parser = DHCPLogParser()
    analyzer = OptimizedDHCPDeviceAnalyzer()
    
    with open(log_file, 'r') as f:
        while True:
            lines = f.readlines(chunk_size)
            if not lines:
                break
                
            chunk_content = ''.join(lines)
            entries = parser.parse_log_content(chunk_content)
            # Process chunk...
```

---

## Integration Examples

### Web API Integration

```python
from flask import Flask, request, jsonify

app = Flask(__name__)
analyzer = OptimizedDHCPDeviceAnalyzer(api_key="your_key")

@app.route('/analyze', methods=['POST'])
def analyze_dhcp_log():
    """REST API endpoint for DHCP analysis"""
    log_content = request.data.decode('utf-8')
    
    try:
        parser = DHCPLogParser()
        entries = parser.parse_log_content(log_content)
        results = analyzer.classify_devices(entries)
        
        return jsonify({
            'status': 'success',
            'device_count': len(results),
            'devices': [asdict(device) for device in results]
        })
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'message': str(e)
        }), 500
```

### Database Integration

```python
import sqlite3
from dataclasses import asdict

def store_results_in_database(results, db_path):
    """Store classification results in SQLite database"""
    conn = sqlite3.connect(db_path)
    
    # Create table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            mac_address TEXT PRIMARY KEY,
            vendor TEXT,
            device_type TEXT,
            operating_system TEXT,
            hostname TEXT,
            confidence TEXT,
            timestamp DATETIME
        )
    ''')
    
    # Insert results
    for result in results:
        conn.execute('''
            INSERT OR REPLACE INTO devices 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.mac_address,
            result.vendor,
            result.device_type, 
            result.operating_system,
            result.hostname,
            result.overall_confidence,
            result.timestamp
        ))
    
    conn.commit()
    conn.close()
```

### Monitoring Integration

```python
import logging
from prometheus_client import Counter, Histogram

# Metrics
classification_counter = Counter('devices_classified_total', 'Total devices classified')
classification_duration = Histogram('classification_duration_seconds', 'Time spent classifying')

class MonitoredAnalyzer(OptimizedDHCPDeviceAnalyzer):
    """Analyzer with monitoring integration"""
    
    def analyze_dhcp_log(self, log_file_path):
        with classification_duration.time():
            results = super().analyze_dhcp_log(log_file_path)
            classification_counter.inc(len(results))
            return results
```

---

**Document Version:** 1.0  
**Last Updated:** July 2025