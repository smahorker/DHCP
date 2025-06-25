# Network Device Monitoring API - Complete Guide

## 🚀 Phase 7: REST API Implementation Complete

The REST API provides programmatic access to your network device inventory and monitoring data.

## 📡 API Server

### Starting the API Server
```bash
cd /mnt/c/Users/sripa/Downloads/Network
source network_monitoring_env/bin/activate
python api_server.py
```

The server runs on **http://localhost:5000**

## 🌐 Web Interface

### Quick Access
- **URL**: http://localhost:5000
- **Features**: Live device inventory, statistics, filtering
- **Auto-refresh**: Updates every 30 seconds
- **Mobile-friendly**: Responsive design

## 📋 API Endpoints

### 1. Health Check
```http
GET /health
```

**Response Example:**
```json
{
  "status": "success",
  "data": {
    "status": "healthy",
    "components": {
      "database": "healthy",
      "packet_capture": {
        "status": "running",
        "interface": "eth0",
        "packets_captured": 150
      }
    },
    "system_stats": {
      "total_devices": 8,
      "active_devices": 6,
      "recent_activity_24h": 4
    }
  }
}
```

### 2. List Devices
```http
GET /devices
```

**Query Parameters:**
- `device_type` - Filter by device type (e.g., "Computer", "Smartphone")
- `active` - Filter by status (`true`/`false`)
- `last_seen_after` - Filter by date (ISO format: `2024-01-01T00:00:00`)
- `os` - Filter by operating system
- `ip` - Filter by IP address
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 50, max: 500)

**Examples:**
```http
GET /devices?active=true&page_size=10
GET /devices?device_type=Computer&last_seen_after=2024-06-01
GET /devices?os=Windows&active=true
```

**Response Example:**
```json
{
  "status": "success",
  "data": {
    "items": [
      {
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "hostname": "MyLaptop",
        "device_name": "Windows Computer",
        "device_type": "Computer", 
        "operating_system": "Windows 10",
        "current_ip": "192.168.1.100",
        "last_seen": "2024-06-21T09:30:00",
        "first_seen": "2024-06-15T14:20:00",
        "is_active": true,
        "confidence_score": 95,
        "total_packets": 45
      }
    ],
    "pagination": {
      "page": 1,
      "page_size": 50,
      "total_items": 8,
      "total_pages": 1,
      "has_next": false,
      "has_previous": false
    }
  }
}
```

### 3. Device Details
```http
GET /devices/{mac_address}
```

**Example:**
```http
GET /devices/aa:bb:cc:dd:ee:ff
```

**Response Example:**
```json
{
  "status": "success", 
  "data": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "hostname": "MyLaptop",
    "device_name": "Windows Computer",
    "device_type": "Computer",
    "operating_system": "Windows 10",
    "current_ip": "192.168.1.100",
    "last_seen": "2024-06-21T09:30:00",
    "first_seen": "2024-06-15T14:20:00", 
    "is_active": true,
    "total_packets": 45,
    "classification_history": [
      {
        "fingerbank_device_id": 12345,
        "device_name": "Windows Computer",
        "device_type": "Computer",
        "operating_system": "Windows 10",
        "confidence_score": 95,
        "classified_at": "2024-06-15T14:25:00"
      }
    ]
  }
}
```

### 4. Network Statistics
```http
GET /devices/stats
```

**Response Example:**
```json
{
  "status": "success",
  "data": {
    "summary": {
      "total_devices": 8,
      "active_devices": 6,
      "inactive_devices": 2,
      "recent_activity": {
        "last_24_hours": 4,
        "last_7_days": 6,
        "last_30_days": 8
      }
    },
    "device_types": {
      "Computer": 4,
      "Smartphone": 2,
      "Tablet": 1,
      "Unknown": 1
    },
    "operating_systems": {
      "Windows 10": 3,
      "Android": 2,
      "iOS": 1,
      "Linux": 1,
      "Unknown": 1
    },
    "packet_statistics": {
      "total_packets": 342,
      "processed_packets": 342,
      "unprocessed_packets": 0,
      "unique_devices": 8,
      "first_packet": "2024-06-15T14:20:00",
      "last_packet": "2024-06-21T09:30:00"
    }
  }
}
```

### 5. Device Types
```http
GET /devices/types
```

**Response Example:**
```json
{
  "status": "success",
  "data": {
    "device_types": [
      {
        "device_type": "Computer",
        "count": 4,
        "percentage": 50.0
      },
      {
        "device_type": "Smartphone", 
        "count": 2,
        "percentage": 25.0
      },
      {
        "device_type": "Tablet",
        "count": 1,
        "percentage": 12.5
      }
    ],
    "total_types": 3,
    "total_devices": 8
  }
}
```

## 🔧 API Features

### Standard Response Format
All endpoints return JSON with consistent structure:
```json
{
  "status": "success|error",
  "message": "Description",
  "data": {...},
  "metadata": {
    "timestamp": "2024-06-21T09:30:00",
    "api_version": "1.0.0"
  }
}
```

### Error Handling
- **404**: Resource not found
- **500**: Internal server error
- **400**: Bad request (invalid parameters)

### Pagination
- Default page size: 50 items
- Maximum page size: 500 items
- Includes pagination metadata in response

### CORS Support
- Cross-origin requests enabled
- Works with web applications

## 💻 Usage Examples

### Python Example
```python
import requests

# Get all active devices
response = requests.get('http://localhost:5000/devices?active=true')
devices = response.json()['data']['items']

for device in devices:
    print(f"{device['device_name']} - {device['mac_address']}")
```

### JavaScript Example
```javascript
// Get network statistics
fetch('http://localhost:5000/devices/stats')
  .then(response => response.json())
  .then(data => {
    const stats = data.data;
    console.log(`Total devices: ${stats.summary.total_devices}`);
    console.log(`Active devices: ${stats.summary.active_devices}`);
  });
```

### curl Example
```bash
# Get device details
curl -X GET "http://localhost:5000/devices/aa:bb:cc:dd:ee:ff" \
     -H "Accept: application/json"

# Get computers only
curl -X GET "http://localhost:5000/devices?device_type=Computer" \
     -H "Accept: application/json"
```

## 🚀 Integration Ideas

### Monitoring Dashboards
- Create custom dashboards using the stats endpoint
- Real-time device monitoring with health checks
- Network activity visualization

### Security Applications
- Alert on new unknown devices
- Track device connection patterns
- Monitor for unusual device behavior

### Network Management
- Automated device inventory
- DHCP lease tracking
- Device type reporting

## ⚡ Performance Notes

- **Caching**: Results are generated fresh for real-time accuracy
- **Database**: Optimized with indexes for fast queries
- **Pagination**: Use pagination for large device lists
- **Filtering**: Server-side filtering for better performance

## 🔒 Security Considerations

- **Local Access**: API runs on localhost by default
- **No Authentication**: Designed for local/trusted network use
- **CORS Enabled**: For web interface integration
- **Input Validation**: Query parameters are validated

## 🎯 Production Deployment

For production use:
1. **Use a WSGI server** (gunicorn, uwsgi) instead of Flask dev server
2. **Add authentication** if exposing beyond localhost
3. **Configure HTTPS** for secure access
4. **Set up rate limiting** for API protection
5. **Monitor logs** for API usage patterns

---

**🎉 Phase 7 Complete!** Your network monitoring system now has a full REST API for programmatic access to device data.