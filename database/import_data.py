#!/usr/bin/env python3
"""
Import JSON device analysis results into PostgreSQL database
"""

import json
import psycopg2
import psycopg2.extras
from datetime import datetime
from pathlib import Path
import logging
import uuid
import sys
import os

# Add parent directory to path to import from src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DeviceDataImporter:
    """Handles importing device analysis data into PostgreSQL database."""
    
    def __init__(self, db_config=None):
        """Initialize importer with database configuration."""
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
            self.connection.autocommit = False
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
    
    def import_json_file(self, json_file_path):
        """Import device data from JSON file."""
        if not self.connection:
            logger.error("No database connection available")
            return False
        
        try:
            # Load JSON data
            with open(json_file_path, 'r') as f:
                data = json.load(f)
            
            logger.info(f"Loading data from {json_file_path}")
            logger.info(f"Found {data['total_devices']} devices to import")
            
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Create analysis session
            session_id = str(uuid.uuid4())
            session_timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
            
            cursor.execute("""
                INSERT INTO analysis_sessions (id, timestamp, total_devices)
                VALUES (%s, %s, %s)
            """, (session_id, session_timestamp, data['total_devices']))
            
            logger.info(f"Created analysis session: {session_id}")
            
            # Import devices
            device_count = 0
            for device in data['devices']:
                cursor.execute("""
                    INSERT INTO devices (
                        session_id, mac_address, vendor, device_type, 
                        operating_system, hostname, overall_confidence,
                        has_vendor_class, fingerbank_score
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    session_id,
                    device['mac_address'],
                    device.get('vendor'),
                    device.get('device_type'),
                    device.get('operating_system'),
                    device.get('hostname'),
                    device['overall_confidence'],
                    device['has_vendor_class'],
                    device.get('fingerbank_score')
                ))
                device_count += 1
            
            logger.info(f"Imported {device_count} devices")
            
            # Import statistics
            stats = data['statistics']
            cursor.execute("""
                INSERT INTO analysis_statistics (
                    session_id, high_confidence, medium_confidence, low_confidence,
                    unknown_confidence, vendor_only, fingerbank_used, fallback_used,
                    hostname_available, vendor_class_available
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                session_id,
                stats['high_confidence'],
                stats['medium_confidence'],
                stats['low_confidence'],
                stats['unknown_confidence'],
                stats['vendor_only'],
                stats['fingerbank_used'],
                stats['fallback_used'],
                stats['hostname_available'],
                stats['vendor_class_available']
            ))
            
            # Import device type counts
            for device_type, count in data['device_types'].items():
                percentage = round(count * 100.0 / data['total_devices'], 2)
                cursor.execute("""
                    INSERT INTO device_type_counts (session_id, device_type, count, percentage)
                    VALUES (%s, %s, %s, %s)
                """, (session_id, device_type, count, percentage))
            
            # Import operating system counts
            for os, count in data['operating_systems'].items():
                percentage = round(count * 100.0 / data['total_devices'], 2)
                cursor.execute("""
                    INSERT INTO operating_system_counts (session_id, operating_system, count, percentage)
                    VALUES (%s, %s, %s, %s)
                """, (session_id, os, count, percentage))
            
            # Import vendor counts
            for vendor, count in data['vendors'].items():
                percentage = round(count * 100.0 / data['total_devices'], 2)
                cursor.execute("""
                    INSERT INTO vendor_counts (session_id, vendor, count, percentage)
                    VALUES (%s, %s, %s, %s)
                """, (session_id, vendor, count, percentage))
            
            # Commit transaction
            self.connection.commit()
            cursor.close()
            
            logger.info(f"Successfully imported all data for session {session_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to import data: {e}")
            if self.connection:
                self.connection.rollback()
            return False
    
    def verify_import(self, session_id):
        """Verify that data was imported correctly."""
        if not self.connection:
            logger.error("No database connection available")
            return False
        
        try:
            cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Check session
            cursor.execute("SELECT * FROM analysis_sessions WHERE id = %s", (session_id,))
            session = cursor.fetchone()
            if not session:
                logger.error(f"Session {session_id} not found")
                return False
            
            logger.info(f"Session: {session['total_devices']} devices at {session['timestamp']}")
            
            # Check devices
            cursor.execute("SELECT COUNT(*) as count FROM devices WHERE session_id = %s", (session_id,))
            device_count = cursor.fetchone()['count']
            logger.info(f"Devices imported: {device_count}")
            
            # Check statistics
            cursor.execute("SELECT * FROM analysis_statistics WHERE session_id = %s", (session_id,))
            stats = cursor.fetchone()
            if stats:
                logger.info(f"Statistics: {stats['high_confidence']} high, {stats['medium_confidence']} medium confidence")
            
            # Sample devices
            cursor.execute("""
                SELECT mac_address, vendor, device_type, overall_confidence 
                FROM devices WHERE session_id = %s LIMIT 5
            """, (session_id,))
            
            logger.info("Sample devices:")
            for device in cursor.fetchall():
                logger.info(f"  {device['mac_address']} - {device['vendor']} - {device['device_type']} ({device['overall_confidence']})")
            
            cursor.close()
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify import: {e}")
            return False

def main():
    """Main function to run the import process."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Import device analysis JSON data to PostgreSQL')
    parser.add_argument('json_file', help='Path to JSON file to import')
    parser.add_argument('--host', default='localhost', help='Database host')
    parser.add_argument('--port', type=int, default=5432, help='Database port')
    parser.add_argument('--database', default='network_devices', help='Database name')
    parser.add_argument('--user', default='network_admin', help='Database user')
    parser.add_argument('--password', default='secure_password_123', help='Database password')
    
    args = parser.parse_args()
    
    # Check if JSON file exists
    json_file = Path(args.json_file)
    if not json_file.exists():
        logger.error(f"JSON file not found: {json_file}")
        return 1
    
    # Database configuration
    db_config = {
        'host': args.host,
        'port': args.port,
        'database': args.database,
        'user': args.user,
        'password': args.password
    }
    
    # Import data
    importer = DeviceDataImporter(db_config)
    
    if not importer.connect():
        return 1
    
    try:
        session_id = importer.import_json_file(json_file)
        if session_id:
            logger.info("Import completed successfully")
            
            # Verify import
            if importer.verify_import(session_id):
                logger.info("Import verification successful")
            else:
                logger.warning("Import verification failed")
            
            return 0
        else:
            logger.error("Import failed")
            return 1
    
    finally:
        importer.disconnect()

if __name__ == "__main__":
    exit(main())