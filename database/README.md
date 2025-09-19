# Network Device Database

A PostgreSQL database solution for storing and analyzing network device data from DHCP log analysis.

## Overview

This database system provides:
- **Structured storage** for device classification results
- **Normalized schema** with proper relationships and constraints
- **Docker deployment** for easy setup and management
- **Python utilities** for data import and querying
- **Web interface** via pgAdmin for database administration

## Database Schema

### Core Tables

- **analysis_sessions**: Tracks different analysis runs with timestamps
- **devices**: Main device data (MAC, vendor, device type, OS, confidence, etc.)
- **analysis_statistics**: Aggregated statistics per session
- **device_type_counts**: Device type distribution data
- **operating_system_counts**: OS distribution data
- **vendor_counts**: Vendor distribution data

### Views and Utilities

- **device_summary**: Convenient view combining device and session data
- **latest_devices**: Shows devices from the most recent analysis
- **confidence_distribution**: Aggregated confidence statistics

## Quick Start

### 1. Start the Database

```bash
cd database
docker compose up -d
```

This starts:
- PostgreSQL on port 5432
- pgAdmin on port 8080 (admin@networkdevices.local / admin123)

### 2. Import Your Data

```bash
python3 import_data.py ../realistic_test_results.json
```

### 3. Query Your Data

```bash
# List all devices
python3 query_data.py list

# Show statistics
python3 query_data.py stats

# Search for devices
python3 query_data.py search Apple

# Generate complete report
python3 query_data.py report --output report.json
```

## Database Connection

- **Host**: localhost
- **Port**: 5432
- **Database**: network_devices
- **Username**: network_admin
- **Password**: secure_password_123

## Scripts

### import_data.py
Imports JSON device analysis results into the database.

```bash
python3 import_data.py [JSON_FILE] [--host HOST] [--port PORT] [--database DB] [--user USER] [--password PASS]
```

### query_data.py
Queries and displays device data in various formats.

```bash
# Commands:
python3 query_data.py list [--limit N] [--session-id ID]
python3 query_data.py search TERM [--field FIELD]
python3 query_data.py stats [--session-id ID]
python3 query_data.py report [--session-id ID] [--output FILE]
```

## Data Structure

The JSON data structure expected for import:

```json
{
  "timestamp": "2025-07-14T10:42:54.356313",
  "total_devices": 23,
  "statistics": {
    "high_confidence": 16,
    "medium_confidence": 7,
    "fingerbank_used": 23,
    "hostname_available": 16
  },
  "devices": [
    {
      "mac_address": "28:39:5e:f1:65:c1",
      "vendor": "Samsung Electronics Co.",
      "device_type": "Phone",
      "operating_system": "Android OS 14",
      "hostname": null,
      "overall_confidence": "medium",
      "has_vendor_class": true,
      "fingerbank_score": 59
    }
  ]
}
```

## Example Queries

### Get High-Confidence Devices
```sql
SELECT mac_address, vendor, device_type, hostname 
FROM devices 
WHERE overall_confidence = 'high'
ORDER BY device_type;
```

### Device Type Distribution
```sql
SELECT device_type, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM devices), 2) as percentage
FROM devices 
GROUP BY device_type 
ORDER BY count DESC;
```

### Vendor Analysis
```sql
SELECT vendor, COUNT(*) as device_count,
       COUNT(DISTINCT device_type) as device_types
FROM devices 
WHERE vendor IS NOT NULL
GROUP BY vendor 
ORDER BY device_count DESC;
```

## Web Interface

Access pgAdmin at http://localhost:8080:
- Email: admin@networkdevices.local
- Password: admin123

Add the PostgreSQL server:
- Host: network_devices_db (Docker network name)
- Port: 5432
- Database: network_devices
- Username: network_admin
- Password: secure_password_123

## Backup and Restore

### Backup
```bash
docker exec network_devices_db pg_dump -U network_admin network_devices > backup.sql
```

### Restore
```bash
docker exec -i network_devices_db psql -U network_admin network_devices < backup.sql
```

## Performance Considerations

The database includes optimized indexes for:
- Device lookups by MAC address
- Vendor and device type filtering
- Confidence level filtering
- Session-based queries
- Fingerbank score ranges

For large datasets, consider:
- Partitioning by analysis date
- Archiving old analysis sessions
- Adding custom indexes for specific query patterns

## Maintenance

### Stop Database
```bash
docker compose down
```

### Remove All Data
```bash
docker compose down -v
```

### View Logs
```bash
docker logs network_devices_db
docker logs network_devices_pgadmin
```