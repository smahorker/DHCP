#!/usr/bin/env python3
"""
REST API Server for Network Device Monitoring System.
Phase 7: Application Interface - REST API for device inventory queries.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from core.database import get_device_store, get_classification_store, get_dhcp_store, initialize_database
from core.device_inventory import DeviceInventoryManager
from core.packet_capture import DHCPPacketCaptureEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for web interface

# API Configuration
API_VERSION = "1.0.0"
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500

# Global components
db_manager = None
device_store = None
classification_store = None
dhcp_store = None
inventory_manager = None
packet_capture_engine = None

def initialize_api_components():
    """Initialize all API components."""
    global db_manager, device_store, classification_store, dhcp_store, inventory_manager, packet_capture_engine
    
    try:
        # Initialize database components
        db_manager = initialize_database()
        device_store = get_device_store()
        classification_store = get_classification_store()
        dhcp_store = get_dhcp_store()
        inventory_manager = DeviceInventoryManager()
        
        # Initialize packet capture for status checks (without starting it)
        packet_capture_engine = DHCPPacketCaptureEngine(store_packets=False)
        
        logger.info("API components initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize API components: {e}")
        return False

def create_api_response(data: Any, status_code: int = 200, message: str = "success") -> tuple:
    """Create standardized API response."""
    response = {
        "status": "success" if status_code < 400 else "error",
        "message": message,
        "data": data,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "api_version": API_VERSION
        }
    }
    return jsonify(response), status_code

def parse_filters(args: dict) -> Dict[str, Any]:
    """Parse query parameters into filters."""
    filters = {}
    
    # Device type filter
    if 'device_type' in args:
        filters['device_type'] = args.get('device_type')
    
    # Active status filter
    if 'active' in args:
        active_val = args.get('active', '').lower()
        if active_val in ['true', '1', 'yes']:
            filters['active'] = True
        elif active_val in ['false', '0', 'no']:
            filters['active'] = False
    
    # Last seen after filter
    if 'last_seen_after' in args:
        try:
            filters['last_seen_after'] = datetime.fromisoformat(args.get('last_seen_after'))
        except ValueError:
            pass  # Invalid date format, ignore filter
    
    # Operating system filter
    if 'os' in args:
        filters['operating_system'] = args.get('os')
    
    # IP address filter
    if 'ip' in args:
        filters['current_ip'] = args.get('ip')
    
    return filters

def apply_device_filters(devices: List[Dict], filters: Dict[str, Any]) -> List[Dict]:
    """Apply filters to device list."""
    filtered_devices = devices
    
    # Filter by device type
    if 'device_type' in filters:
        device_type = filters['device_type'].lower()
        filtered_devices = [d for d in filtered_devices 
                          if d.get('device_type', '').lower() == device_type]
    
    # Filter by active status
    if 'active' in filters:
        active = filters['active']
        filtered_devices = [d for d in filtered_devices 
                          if d.get('is_active') == active]
    
    # Filter by last seen after date
    if 'last_seen_after' in filters:
        after_date = filters['last_seen_after']
        filtered_devices = [d for d in filtered_devices 
                          if d.get('last_seen') and 
                          datetime.fromisoformat(d['last_seen'].replace('Z', '+00:00')) > after_date]
    
    # Filter by operating system
    if 'operating_system' in filters:
        os_name = filters['operating_system'].lower()
        filtered_devices = [d for d in filtered_devices 
                          if d.get('operating_system', '').lower() == os_name]
    
    # Filter by IP address
    if 'current_ip' in filters:
        ip_addr = filters['current_ip']
        filtered_devices = [d for d in filtered_devices 
                          if d.get('current_ip') == ip_addr]
    
    return filtered_devices

def paginate_results(items: List[Any], page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> Dict:
    """Paginate results with metadata."""
    page_size = min(page_size, MAX_PAGE_SIZE)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    
    paginated_items = items[start_idx:end_idx]
    
    return {
        "items": paginated_items,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": len(items),
            "total_pages": (len(items) + page_size - 1) // page_size,
            "has_next": end_idx < len(items),
            "has_previous": page > 1
        }
    }

# API Endpoints

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint showing system status."""
    try:
        # Check database connectivity
        db_healthy = bool(device_store.get_active_devices())
        
        # Check packet capture status (if running)
        capture_status = packet_capture_engine.get_statistics() if packet_capture_engine else {}
        
        # Get system stats
        stats = inventory_manager.get_inventory_statistics()
        
        health_data = {
            "status": "healthy" if db_healthy else "degraded",
            "components": {
                "database": "healthy" if db_healthy else "unhealthy",
                "packet_capture": {
                    "status": "running" if capture_status.get('is_running', False) else "stopped",
                    "interface": capture_status.get('interface', 'unknown'),
                    "packets_captured": capture_status.get('packets_captured', 0)
                }
            },
            "system_stats": {
                "total_devices": stats.get('total_devices', 0),
                "active_devices": stats.get('active_devices', 0),
                "recent_activity_24h": stats.get('recent_activity_24h', 0)
            }
        }
        
        status_code = 200 if db_healthy else 503
        return create_api_response(health_data, status_code)
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return create_api_response({"error": str(e)}, 503, "Health check failed")

@app.route('/devices', methods=['GET'])
def get_devices():
    """
    GET /devices - Return all active devices with filtering and pagination.
    
    Query parameters:
    - device_type: Filter by device type
    - active: Filter by active status (true/false)
    - last_seen_after: Filter by last seen date (ISO format)
    - os: Filter by operating system
    - ip: Filter by current IP address
    - page: Page number (default: 1)
    - page_size: Items per page (default: 50, max: 500)
    """
    try:
        # Parse query parameters
        filters = parse_filters(request.args)
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', DEFAULT_PAGE_SIZE))
        
        # Get devices from inventory
        all_devices = inventory_manager.get_device_inventory(include_inactive=True)
        
        # Convert to API format
        device_list = []
        for device in all_devices:
            device_data = {
                "mac_address": device.mac_address,
                "hostname": device.hostname,
                "device_name": device.device_name,
                "device_type": device.device_type,
                "operating_system": device.operating_system,
                "current_ip": device.current_ip,
                "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                "first_seen": device.first_seen.isoformat() if device.first_seen else None,
                "is_active": device.is_active,
                "confidence_score": device.confidence_score,
                "total_packets": device.total_packets
            }
            device_list.append(device_data)
        
        # Apply filters
        filtered_devices = apply_device_filters(device_list, filters)
        
        # Paginate results
        paginated_data = paginate_results(filtered_devices, page, page_size)
        
        # Add filter info to metadata
        paginated_data["filters_applied"] = filters
        
        return create_api_response(paginated_data)
        
    except Exception as e:
        logger.error(f"Failed to get devices: {e}")
        return create_api_response({"error": str(e)}, 500, "Failed to retrieve devices")

@app.route('/devices/<mac_address>', methods=['GET'])
def get_device_details(mac_address: str):
    """
    GET /devices/{mac_address} - Return detailed information for specific device.
    
    Includes:
    - Basic device information
    - Classification history
    - Connection history
    - Confidence scores
    """
    try:
        # Normalize MAC address format
        mac_address = mac_address.lower().replace('-', ':')
        
        # Get device details
        device_details = inventory_manager.get_device_details(mac_address)
        
        if not device_details:
            return create_api_response(
                {"error": f"Device {mac_address} not found"}, 
                404, 
                "Device not found"
            )
        
        device_info = device_details['device_info']
        classification_history = device_details['classification_history']
        
        # Format response
        detailed_data = {
            "mac_address": device_info.mac_address,
            "hostname": device_info.hostname,
            "device_name": device_info.device_name,
            "device_type": device_info.device_type,
            "operating_system": device_info.operating_system,
            "current_ip": device_info.current_ip,
            "last_seen": device_info.last_seen.isoformat() if device_info.last_seen else None,
            "first_seen": device_info.first_seen.isoformat() if device_info.first_seen else None,
            "is_active": device_info.is_active,
            "total_packets": device_info.total_packets,
            "classification_history": [
                {
                    "fingerbank_device_id": cls.get('fingerbank_device_id'),
                    "device_name": cls.get('device_name'),
                    "device_type": cls.get('device_type'),
                    "operating_system": cls.get('operating_system'),
                    "confidence_score": cls.get('confidence_score'),
                    "classified_at": cls.get('classified_at').isoformat() if cls.get('classified_at') else None
                }
                for cls in classification_history if cls
            ]
        }
        
        return create_api_response(detailed_data)
        
    except Exception as e:
        logger.error(f"Failed to get device details for {mac_address}: {e}")
        return create_api_response({"error": str(e)}, 500, "Failed to retrieve device details")

@app.route('/devices/stats', methods=['GET'])
def get_device_stats():
    """
    GET /devices/stats - Return network statistics and device breakdowns.
    
    Includes:
    - Total device counts
    - Breakdown by device type
    - OS distribution
    - Active vs inactive counts
    - Recent activity summary
    """
    try:
        # Get comprehensive statistics
        stats = inventory_manager.get_inventory_statistics()
        
        # Get packet statistics
        packet_stats = dhcp_store.get_packet_statistics()
        
        # Calculate additional metrics
        devices = inventory_manager.get_device_inventory(include_inactive=True)
        
        # Recent activity (last 24 hours, 7 days, 30 days)
        from datetime import timezone
        now = datetime.now(timezone.utc)
        
        def safe_datetime_diff(dt):
            if not dt:
                return 999  # Large number to exclude from recent activity
            # Ensure datetime is timezone-aware
            if isinstance(dt, str):
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (now - dt).days
        
        recent_24h = len([d for d in devices if safe_datetime_diff(d.last_seen) < 1])
        recent_7d = len([d for d in devices if safe_datetime_diff(d.last_seen) < 7])
        recent_30d = len([d for d in devices if safe_datetime_diff(d.last_seen) < 30])
        
        stats_data = {
            "summary": {
                "total_devices": stats.get('total_devices', 0),
                "active_devices": stats.get('active_devices', 0),
                "inactive_devices": stats.get('inactive_devices', 0),
                "recent_activity": {
                    "last_24_hours": recent_24h,
                    "last_7_days": recent_7d,
                    "last_30_days": recent_30d
                }
            },
            "device_types": stats.get('device_types', {}),
            "operating_systems": stats.get('operating_systems', {}),
            "packet_statistics": {
                "total_packets": packet_stats.get('total_packets', 0),
                "processed_packets": packet_stats.get('processed_packets', 0),
                "unprocessed_packets": packet_stats.get('unprocessed_packets', 0),
                "unique_devices": packet_stats.get('unique_devices', 0),
                "first_packet": packet_stats.get('first_packet').isoformat() if packet_stats.get('first_packet') else None,
                "last_packet": packet_stats.get('last_packet').isoformat() if packet_stats.get('last_packet') else None
            }
        }
        
        return create_api_response(stats_data)
        
    except Exception as e:
        logger.error(f"Failed to get device stats: {e}")
        return create_api_response({"error": str(e)}, 500, "Failed to retrieve statistics")

@app.route('/devices/types', methods=['GET'])
def get_device_types():
    """
    GET /devices/types - Return list of all detected device types with counts.
    """
    try:
        # Get inventory statistics
        stats = inventory_manager.get_inventory_statistics()
        device_types = stats.get('device_types', {})
        
        # Format as list with counts
        types_list = [
            {
                "device_type": device_type,
                "count": count,
                "percentage": round((count / sum(device_types.values())) * 100, 1) if device_types else 0
            }
            for device_type, count in sorted(device_types.items(), key=lambda x: x[1], reverse=True)
        ]
        
        types_data = {
            "device_types": types_list,
            "total_types": len(types_list),
            "total_devices": sum(device_types.values())
        }
        
        return create_api_response(types_data)
        
    except Exception as e:
        logger.error(f"Failed to get device types: {e}")
        return create_api_response({"error": str(e)}, 500, "Failed to retrieve device types")

# Simple Web Interface

@app.route('/', methods=['GET'])
def web_interface():
    """Simple web interface for viewing device inventory."""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Device Monitor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .stat-label { color: #666; margin-top: 5px; }
        .devices-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .devices-table th, .devices-table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .devices-table th { background-color: #f8f9fa; font-weight: bold; }
        .status-active { color: #28a745; font-weight: bold; }
        .status-inactive { color: #dc3545; }
        .refresh-btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-bottom: 20px; }
        .refresh-btn:hover { background: #0056b3; }
        .filter-controls { margin-bottom: 20px; }
        .filter-controls select, .filter-controls input { margin: 5px; padding: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥️ Network Device Monitor</h1>
        
        <div class="stats" id="stats">
            <div class="stat-card">
                <div class="stat-number" id="total-devices">-</div>
                <div class="stat-label">Total Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="active-devices">-</div>
                <div class="stat-label">Active Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="recent-activity">-</div>
                <div class="stat-label">Recent Activity (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="total-packets">-</div>
                <div class="stat-label">DHCP Packets</div>
            </div>
        </div>
        
        <div class="filter-controls">
            <button class="refresh-btn" onclick="loadData()">🔄 Refresh</button>
            <select id="device-type-filter" onchange="filterDevices()">
                <option value="">All Device Types</option>
            </select>
            <select id="active-filter" onchange="filterDevices()">
                <option value="">All Devices</option>
                <option value="true">Active Only</option>
                <option value="false">Inactive Only</option>
            </select>
        </div>
        
        <table class="devices-table">
            <thead>
                <tr>
                    <th>Device Name</th>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Device Type</th>
                    <th>Operating System</th>
                    <th>Last Seen</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody id="devices-tbody">
                <tr><td colspan="7" style="text-align: center;">Loading...</td></tr>
            </tbody>
        </table>
    </div>

    <script>
        let allDevices = [];
        
        async function loadData() {
            try {
                // Load statistics
                const statsResponse = await fetch('/devices/stats');
                const statsData = await statsResponse.json();
                
                if (statsData.status === 'success') {
                    const stats = statsData.data;
                    document.getElementById('total-devices').textContent = stats.summary.total_devices;
                    document.getElementById('active-devices').textContent = stats.summary.active_devices;
                    document.getElementById('recent-activity').textContent = stats.summary.recent_activity.last_24_hours;
                    document.getElementById('total-packets').textContent = stats.packet_statistics.total_packets;
                    
                    // Populate device type filter
                    const typeFilter = document.getElementById('device-type-filter');
                    typeFilter.innerHTML = '<option value="">All Device Types</option>';
                    Object.keys(stats.device_types).forEach(type => {
                        const option = document.createElement('option');
                        option.value = type;
                        option.textContent = type + ' (' + stats.device_types[type] + ')';
                        typeFilter.appendChild(option);
                    });
                }
                
                // Load devices
                const devicesResponse = await fetch('/devices?page_size=500');
                const devicesData = await devicesResponse.json();
                
                if (devicesData.status === 'success') {
                    allDevices = devicesData.data.items;
                    displayDevices(allDevices);
                }
                
            } catch (error) {
                console.error('Error loading data:', error);
                document.getElementById('devices-tbody').innerHTML = '<tr><td colspan="7" style="text-align: center; color: red;">Error loading data</td></tr>';
            }
        }
        
        function displayDevices(devices) {
            const tbody = document.getElementById('devices-tbody');
            
            if (devices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No devices found</td></tr>';
                return;
            }
            
            tbody.innerHTML = devices.map(device => `
                <tr>
                    <td>${device.device_name || device.hostname || 'Unknown'}</td>
                    <td><code>${device.mac_address}</code></td>
                    <td>${device.current_ip || '-'}</td>
                    <td>${device.device_type || 'Unknown'}</td>
                    <td>${device.operating_system || 'Unknown'}</td>
                    <td>${device.last_seen ? new Date(device.last_seen).toLocaleString() : '-'}</td>
                    <td class="${device.is_active ? 'status-active' : 'status-inactive'}">
                        ${device.is_active ? '✅ Active' : '❌ Inactive'}
                    </td>
                </tr>
            `).join('');
        }
        
        function filterDevices() {
            const typeFilter = document.getElementById('device-type-filter').value;
            const activeFilter = document.getElementById('active-filter').value;
            
            let filtered = allDevices;
            
            if (typeFilter) {
                filtered = filtered.filter(device => device.device_type === typeFilter);
            }
            
            if (activeFilter !== '') {
                const isActive = activeFilter === 'true';
                filtered = filtered.filter(device => device.is_active === isActive);
            }
            
            displayDevices(filtered);
        }
        
        // Load data on page load
        loadData();
        
        // Auto-refresh every 30 seconds
        setInterval(loadData, 30000);
    </script>
</body>
</html>
    """
    return render_template_string(html_template)

# Error Handlers

@app.errorhandler(404)
def not_found(error):
    return create_api_response(
        {"error": "Endpoint not found"}, 
        404, 
        "Not found"
    )

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return create_api_response(
        {"error": "Internal server error"}, 
        500, 
        "Internal server error"
    )

def main():
    """Run the API server."""
    print("Network Device Monitoring API Server")
    print("=" * 40)
    
    # Initialize components
    if not initialize_api_components():
        print("❌ Failed to initialize API components")
        return 1
    
    print("✅ API components initialized")
    print("📡 Starting REST API server...")
    print()
    print("API Endpoints:")
    print("  GET  /health           - System health check")
    print("  GET  /devices          - List all devices (with filtering)")
    print("  GET  /devices/{mac}    - Get device details")
    print("  GET  /devices/stats    - Network statistics")
    print("  GET  /devices/types    - Device type breakdown")
    print("  GET  /                 - Web interface")
    print()
    print("🌐 Web Interface: http://localhost:5000")
    print("📋 API Documentation: All endpoints return JSON")
    print()
    
    try:
        # Run Flask development server
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False  # Disable reloader to avoid double initialization
        )
    except KeyboardInterrupt:
        print("\n🛑 API server stopped")
    except Exception as e:
        print(f"❌ API server error: {e}")
    finally:
        if db_manager:
            db_manager.close_all_connections()

if __name__ == "__main__":
    main()