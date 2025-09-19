#!/usr/bin/env python3
"""
Query and fetch device data from PostgreSQL database in clean format
"""

import psycopg2
import psycopg2.extras
import json
from datetime import datetime
import logging
import argparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DeviceDataQuery:
    """Handles querying device data from PostgreSQL database."""
    
    def __init__(self, db_config=None):
        """Initialize query handler with database configuration."""
        self.db_config = db_config or {
            'host': 'localhost',
            'port': 5432,
            'database': 'network_devices',
            'user': 'network_admin',
            'password': 'secure_password_123'
        }
        self.connection = None
    
    def connect(self):
        """Establish database connection."""
        try:
            self.connection = psycopg2.connect(**self.db_config)
            logger.info("Connected to PostgreSQL database")
            return True
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def disconnect(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            logger.info("Disconnected from database")
    
    def get_latest_session_summary(self):
        """Get summary of the latest analysis session."""
        cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        query = """
        SELECT 
            s.id as session_id,
            s.timestamp,
            s.total_devices,
            st.high_confidence,
            st.medium_confidence,
            st.low_confidence,
            st.unknown_confidence,
            st.fingerbank_used,
            st.hostname_available
        FROM analysis_sessions s
        JOIN analysis_statistics st ON s.id = st.session_id
        WHERE s.total_devices > 0
        ORDER BY s.timestamp DESC
        LIMIT 1
        """
        
        cursor.execute(query)
        result = cursor.fetchone()
        cursor.close()
        
        if result:
            return dict(result)
        return None
    
    def get_all_devices(self, session_id=None, format_output=True):
        """Get all devices, optionally filtered by session."""
        cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if session_id:
            query = """
            SELECT 
                d.mac_address,
                d.vendor,
                d.device_type,
                d.operating_system,
                d.hostname,
                d.overall_confidence,
                d.has_vendor_class,
                d.fingerbank_score,
                s.timestamp as analysis_date
            FROM devices d
            JOIN analysis_sessions s ON d.session_id = s.id
            WHERE d.session_id = %s
            ORDER BY d.overall_confidence DESC, d.device_type, d.vendor
            """
            cursor.execute(query, (session_id,))
        else:
            query = """
            SELECT 
                d.mac_address,
                d.vendor,
                d.device_type,
                d.operating_system,
                d.hostname,
                d.overall_confidence,
                d.has_vendor_class,
                d.fingerbank_score,
                s.timestamp as analysis_date
            FROM devices d
            JOIN analysis_sessions s ON d.session_id = s.id
            WHERE s.id = (
                SELECT s2.id FROM analysis_sessions s2 
                WHERE s2.total_devices > 0 
                ORDER BY s2.timestamp DESC 
                LIMIT 1
            )
            ORDER BY d.overall_confidence DESC, d.device_type, d.vendor
            """
            cursor.execute(query)
        
        devices = cursor.fetchall()
        cursor.close()
        
        if format_output:
            return [dict(device) for device in devices]
        return devices
    
    def get_device_type_distribution(self, session_id=None):
        """Get device type distribution."""
        cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if session_id:
            query = """
            SELECT device_type, count, percentage
            FROM device_type_counts
            WHERE session_id = %s
            ORDER BY count DESC
            """
            cursor.execute(query, (session_id,))
        else:
            query = """
            SELECT device_type, count, percentage
            FROM device_type_counts dtc
            JOIN analysis_sessions s ON dtc.session_id = s.id
            WHERE s.id = (
                SELECT s2.id FROM analysis_sessions s2 
                WHERE s2.total_devices > 0 
                ORDER BY s2.timestamp DESC 
                LIMIT 1
            )
            ORDER BY count DESC
            """
            cursor.execute(query)
        
        result = cursor.fetchall()
        cursor.close()
        return [dict(row) for row in result]
    
    def get_vendor_distribution(self, session_id=None, limit=10):
        """Get vendor distribution."""
        cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if session_id:
            query = """
            SELECT vendor, count, percentage
            FROM vendor_counts
            WHERE session_id = %s
            ORDER BY count DESC
            LIMIT %s
            """
            cursor.execute(query, (session_id, limit))
        else:
            query = """
            SELECT vendor, count, percentage
            FROM vendor_counts vc
            JOIN analysis_sessions s ON vc.session_id = s.id
            WHERE s.id = (
                SELECT s2.id FROM analysis_sessions s2 
                WHERE s2.total_devices > 0 
                ORDER BY s2.timestamp DESC 
                LIMIT 1
            )
            ORDER BY count DESC
            LIMIT %s
            """
            cursor.execute(query, (limit,))
        
        result = cursor.fetchall()
        cursor.close()
        return [dict(row) for row in result]
    
    def get_confidence_distribution(self, session_id=None):
        """Get confidence level distribution."""
        cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if session_id:
            query = """
            SELECT 
                st.high_confidence,
                st.medium_confidence,
                st.low_confidence,
                st.unknown_confidence,
                (st.high_confidence + st.medium_confidence) as successful_classifications,
                s.total_devices,
                ROUND((st.high_confidence + st.medium_confidence) * 100.0 / s.total_devices, 2) as success_rate
            FROM analysis_statistics st
            JOIN analysis_sessions s ON st.session_id = s.id
            WHERE s.id = %s
            """
            cursor.execute(query, (session_id,))
        else:
            query = """
            SELECT 
                st.high_confidence,
                st.medium_confidence,
                st.low_confidence,
                st.unknown_confidence,
                (st.high_confidence + st.medium_confidence) as successful_classifications,
                s.total_devices,
                ROUND((st.high_confidence + st.medium_confidence) * 100.0 / s.total_devices, 2) as success_rate
            FROM analysis_statistics st
            JOIN analysis_sessions s ON st.session_id = s.id
            WHERE s.total_devices > 0
            ORDER BY s.timestamp DESC
            LIMIT 1
            """
            cursor.execute(query)
        
        result = cursor.fetchone()
        cursor.close()
        return dict(result) if result else None
    
    def search_devices(self, search_term, field=None):
        """Search devices by various criteria."""
        cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        search_term = f"%{search_term}%"
        
        if field:
            if field == 'vendor':
                query = """
                SELECT * FROM device_summary 
                WHERE vendor ILIKE %s
                ORDER BY overall_confidence DESC
                """
            elif field == 'device_type':
                query = """
                SELECT * FROM device_summary 
                WHERE device_type ILIKE %s
                ORDER BY overall_confidence DESC
                """
            elif field == 'hostname':
                query = """
                SELECT * FROM device_summary 
                WHERE hostname ILIKE %s
                ORDER BY overall_confidence DESC
                """
            elif field == 'mac':
                query = """
                SELECT * FROM device_summary 
                WHERE mac_address ILIKE %s
                ORDER BY overall_confidence DESC
                """
            else:
                raise ValueError(f"Invalid field: {field}")
            
            cursor.execute(query, (search_term,))
        else:
            # Search across multiple fields
            query = """
            SELECT * FROM device_summary 
            WHERE vendor ILIKE %s 
               OR device_type ILIKE %s 
               OR hostname ILIKE %s 
               OR mac_address ILIKE %s
               OR operating_system ILIKE %s
            ORDER BY overall_confidence DESC
            """
            cursor.execute(query, (search_term, search_term, search_term, search_term, search_term))
        
        result = cursor.fetchall()
        cursor.close()
        return [dict(row) for row in result]
    
    def get_complete_report(self, session_id=None):
        """Get a complete analysis report."""
        summary = self.get_latest_session_summary()
        if not summary:
            return None
        
        use_session_id = session_id or summary['session_id']
        
        report = {
            'session_info': summary,
            'devices': self.get_all_devices(use_session_id),
            'device_type_distribution': self.get_device_type_distribution(use_session_id),
            'vendor_distribution': self.get_vendor_distribution(use_session_id),
            'confidence_distribution': self.get_confidence_distribution(use_session_id)
        }
        
        return report

def print_formatted_devices(devices, limit=None):
    """Print devices in a formatted table."""
    if not devices:
        print("No devices found.")
        return
    
    # Limit results if specified
    if limit:
        devices = devices[:limit]
        if len(devices) < len(devices):
            print(f"Showing first {limit} results...")
    
    print(f"\n{'MAC Address':<19} {'Vendor':<25} {'Device Type':<20} {'OS':<20} {'Confidence':<10} {'Hostname':<15}")
    print("-" * 120)
    
    for device in devices:
        vendor = (device['vendor'] or 'Unknown')[:24]
        device_type = (device['device_type'] or 'Unknown')[:19]
        os = (device['operating_system'] or 'Unknown')[:19]
        hostname = (device['hostname'] or 'None')[:14]
        
        print(f"{device['mac_address']:<19} {vendor:<25} {device_type:<20} {os:<20} {device['overall_confidence']:<10} {hostname:<15}")

def main():
    """Main function to run queries."""
    parser = argparse.ArgumentParser(description='Query device data from PostgreSQL')
    parser.add_argument('--host', default='localhost', help='Database host')
    parser.add_argument('--port', type=int, default=5432, help='Database port')
    parser.add_argument('--database', default='network_devices', help='Database name')
    parser.add_argument('--user', default='network_admin', help='Database user')
    parser.add_argument('--password', default='secure_password_123', help='Database password')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List devices command
    list_parser = subparsers.add_parser('list', help='List all devices')
    list_parser.add_argument('--limit', type=int, help='Limit number of results')
    list_parser.add_argument('--session-id', help='Specific session ID')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search devices')
    search_parser.add_argument('term', help='Search term')
    search_parser.add_argument('--field', choices=['vendor', 'device_type', 'hostname', 'mac'], 
                              help='Specific field to search')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show statistics')
    stats_parser.add_argument('--session-id', help='Specific session ID')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate complete report')
    report_parser.add_argument('--session-id', help='Specific session ID')
    report_parser.add_argument('--output', help='Output file (JSON format)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Database configuration
    db_config = {
        'host': args.host,
        'port': args.port,
        'database': args.database,
        'user': args.user,
        'password': args.password
    }
    
    # Query data
    query_handler = DeviceDataQuery(db_config)
    
    if not query_handler.connect():
        return 1
    
    try:
        if args.command == 'list':
            devices = query_handler.get_all_devices(args.session_id)
            print_formatted_devices(devices, args.limit)
        
        elif args.command == 'search':
            devices = query_handler.search_devices(args.term, args.field)
            print(f"\nFound {len(devices)} matching devices:")
            print_formatted_devices(devices)
        
        elif args.command == 'stats':
            summary = query_handler.get_latest_session_summary()
            confidence = query_handler.get_confidence_distribution(args.session_id)
            device_types = query_handler.get_device_type_distribution(args.session_id)
            vendors = query_handler.get_vendor_distribution(args.session_id)
            
            print("\n=== ANALYSIS SUMMARY ===")
            print(f"Session ID: {summary['session_id']}")
            print(f"Analysis Date: {summary['timestamp']}")
            print(f"Total Devices: {summary['total_devices']}")
            print(f"Success Rate: {confidence['success_rate']}%")
            
            print("\n=== CONFIDENCE DISTRIBUTION ===")
            print(f"High Confidence: {confidence['high_confidence']} devices")
            print(f"Medium Confidence: {confidence['medium_confidence']} devices")
            print(f"Low Confidence: {confidence['low_confidence']} devices")
            print(f"Unknown: {confidence['unknown_confidence']} devices")
            
            print("\n=== TOP DEVICE TYPES ===")
            for dt in device_types[:5]:
                print(f"{dt['device_type']}: {dt['count']} ({dt['percentage']}%)")
            
            print("\n=== TOP VENDORS ===")
            for vendor in vendors[:5]:
                print(f"{vendor['vendor']}: {vendor['count']} ({vendor['percentage']}%)")
        
        elif args.command == 'report':
            report = query_handler.get_complete_report(args.session_id)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2, default=str))
        
        return 0
    
    finally:
        query_handler.disconnect()

if __name__ == "__main__":
    exit(main())