# 🖥️ Network Device Monitoring System

## 🎉 Complete Implementation - All 7 Phases

A comprehensive network device monitoring system that discovers and classifies devices on your network using DHCP packet analysis and the Fingerbank API.

## ✅ **Network-Safe**: Only monitors DHCP packets for device discovery - your network traffic is completely ignored!

## 🚀 Quick Start

### 1. Start Database
```bash
# Start PostgreSQL in Docker
docker-compose up -d
```

### 2. Start Network Monitoring
```bash
# Complete monitoring system
source network_monitoring_env/bin/activate
python main.py
```

### 3. Start API Server (Optional)
```bash
# REST API and web interface
python run_api.py
# Visit: http://localhost:5000
```

### 4. Run Tests
```bash
# Verify everything works
python run_tests.py
```

## 🏗️ Project Structure

```
Network/
├── main.py              # Main monitoring application
├── run_api.py           # REST API server
├── run_tests.py         # Test runner
├── src/
│   ├── core/            # Core system modules
│   │   ├── database.py          # Database operations
│   │   ├── packet_capture.py    # DHCP packet capture
│   │   ├── dhcp_parser.py       # Packet parsing
│   │   ├── fingerbank_api.py    # Device classification
│   │   └── device_inventory.py  # Device tracking
│   ├── api/
│   │   └── api_server.py        # REST API & web interface
│   └── database/
│       └── init_new_schema.sql  # Database schema
├── tests/               # Comprehensive test suite
└── docker-compose.yml   # PostgreSQL container
```

## 🔧 System Features

### 📡 Packet Capture (Phase 3)
- **DHCP-only filtering** (`udp and port 67 or 68`)
- **Threaded operation** for non-blocking capture
- **Network-safe**: No interference with other applications

### 🧠 Device Classification (Phase 5)
- **Fingerbank API integration** with rate limiting
- **Device type detection** (Computer, Phone, Tablet, etc.)
- **Operating system identification** (Windows, Android, iOS, Linux)
- **Confidence scoring** for accuracy

### 📊 Device Inventory (Phase 6)
- **Real-time device tracking** with timestamps
- **Automatic device updates** from classifications
- **Anomaly detection** for unusual behavior
- **Active/inactive device management**

### 🌐 REST API & Web Interface (Phase 7)
- **5 REST endpoints** with filtering and pagination
- **Real-time web dashboard** at http://localhost:5000
- **Device filtering** by type, status, and date
- **Network statistics** and analytics

## 📋 API Endpoints

- `GET /health` - System health check
- `GET /devices` - List devices (with filtering)
- `GET /devices/{mac}` - Device details
- `GET /devices/stats` - Network statistics
- `GET /devices/types` - Device type breakdown

## 🗄️ Database Design (Phase 2)

### Tables
- **raw_dhcp_packets**: Every captured DHCP packet
- **device_classifications**: Fingerbank API responses
- **active_devices**: Current device inventory
- **capture_statistics**: System performance metrics

### Features
- **Connection pooling** for performance
- **Optimized indexes** for fast queries
- **JSON storage** for DHCP options
- **Foreign key relationships** for data integrity

## 🧪 Testing

### Comprehensive Test Suite
```bash
# Run all tests
python run_tests.py

# Individual test modules
cd tests/
python system_test.py          # End-to-end system test
python test_api.py             # API endpoint tests
python test_db_connection.py   # Database connectivity
python test_packet_capture.py  # Packet capture verification
```

## ⚙️ Configuration

### Environment Variables (`.env`)
```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=network_monitoring
DB_USER=postgres
DB_PASSWORD=postgres

# Fingerbank API (get free key from fingerbank.org)
FINGERBANK_API_KEY=your_api_key_here
```

## 📈 What You'll See

### Device Discovery
- **New devices** connecting to your network
- **Device types**: Windows PCs, iPhones, Android tablets, etc.
- **Operating systems**: Detailed OS identification
- **Connection history**: First seen, last seen timestamps

### Real-Time Monitoring
- **Live packet capture** statistics
- **API classification** success rates
- **Device inventory** updates
- **Network activity** summaries

### Web Dashboard
- **Device list** with filtering options
- **Network statistics** and breakdowns
- **Device type** distribution
- **Recent activity** monitoring

## 🔒 Privacy & Security

### What It Monitors
- ✅ **DHCP packets only** (device discovery)
- ✅ **Device connection events**
- ✅ **Network device inventory**

### What It DOESN'T Monitor
- ❌ Web browsing
- ❌ Streaming data
- ❌ File transfers
- ❌ Any application data

## 📚 Documentation

All comprehensive documentation is available locally in the `docs/` directory when you clone the repository.

## 🎯 Use Cases

### Network Administration
- **Device inventory** management
- **Network activity** monitoring
- **Device type** reporting

### Security Monitoring
- **New device detection**
- **Unknown device alerts**
- **Connection pattern analysis**

### Home Network Management
- **Family device tracking**
- **Guest device monitoring**
- **Network usage insights**

## 🏆 Implementation Status

**✅ All 7 Phases Complete:**
1. ✅ Database Design & Setup
2. ✅ DHCP Packet Capture Engine
3. ✅ Packet Parser & Fingerprinting
4. ✅ Fingerbank API Integration
5. ✅ Device Inventory Management
6. ✅ REST API & Web Interface
7. ✅ Professional Project Organization

**🎉 Your network monitoring system is complete and ready for use!**

## 🤝 Contributing

The project is organized for easy development:
- **Core modules**: Add functionality to `src/core/`
- **API features**: Extend `src/api/api_server.py`
- **Tests**: Add test coverage in `tests/`
- **Documentation**: Update guides in `docs/`

## 📞 Support

- **System Testing**: Run `python run_tests.py`
- **Setup Issues**: Check local documentation in `docs/` directory
- **API Questions**: See local API guide in `docs/` directory
