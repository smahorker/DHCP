#!/usr/bin/env python3
"""
Simple script to verify database contents
"""

import psycopg2
import psycopg2.extras

db_config = {
    'host': 'localhost',
    'port': 5432,
    'database': 'network_devices',
    'user': 'network_admin',
    'password': 'secure_password_123'
}

try:
    conn = psycopg2.connect(**db_config)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Check devices
    cursor.execute("SELECT COUNT(*) as count FROM devices")
    device_count = cursor.fetchone()['count']
    print(f"Total devices: {device_count}")
    
    # Check sessions
    cursor.execute("SELECT COUNT(*) as count FROM analysis_sessions")
    session_count = cursor.fetchone()['count']
    print(f"Total sessions: {session_count}")
    
    # Sample devices
    cursor.execute("SELECT mac_address, vendor, device_type, overall_confidence FROM devices LIMIT 5")
    devices = cursor.fetchall()
    print("\nSample devices:")
    for device in devices:
        print(f"  {device['mac_address']} - {device['vendor']} - {device['device_type']} ({device['overall_confidence']})")
    
    # Check views
    cursor.execute("SELECT COUNT(*) as count FROM device_summary")
    view_count = cursor.fetchone()['count']
    print(f"\nDevice summary view count: {view_count}")
    
    cursor.close()
    conn.close()
    print("\nDatabase verification complete!")
    
except Exception as e:
    print(f"Error: {e}")