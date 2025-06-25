#!/usr/bin/env python3
"""
Database connection module for Network Device Monitoring System.
Provides connection pooling and database operations.
Phase 2: Database connection module with pooling
"""

import os
import json
import logging
from contextlib import contextmanager
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import psycopg2
from psycopg2 import pool, sql, extras
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database connections with connection pooling."""
    
    def __init__(self, min_connections: int = 2, max_connections: int = 10):
        """Initialize database connection pool."""
        self.db_params = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'database': os.getenv('DB_NAME', 'network_monitoring'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD', 'postgres')
        }
        
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.connection_pool = None
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize the connection pool."""
        try:
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                self.min_connections,
                self.max_connections,
                **self.db_params
            )
            logger.info(f"Database connection pool initialized ({self.min_connections}-{self.max_connections} connections)")
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = None
        try:
            conn = self.connection_pool.getconn()
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database operation failed: {e}")
            raise
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    @contextmanager
    def get_cursor(self, commit: bool = True, dict_cursor: bool = False):
        """Context manager for database cursors."""
        with self.get_connection() as conn:
            cursor_factory = RealDictCursor if dict_cursor else None
            cur = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cur
                if commit:
                    conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Database cursor operation failed: {e}")
                raise
            finally:
                cur.close()
    
    def close_all_connections(self):
        """Close all connections in the pool."""
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("All database connections closed")

class DHCPPacketStore:
    """Handles DHCP packet storage operations."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def insert_raw_packet(self, mac_address: str, ip_address: str = None, 
                         hostname: str = None, vendor_class: str = None,
                         dhcp_options: Dict = None) -> int:
        """Insert a raw DHCP packet into the database."""
        query = """
            INSERT INTO raw_dhcp_packets 
            (mac_address, ip_address, hostname, vendor_class, dhcp_options) 
            VALUES (%s, %s, %s, %s, %s) 
            RETURNING packet_id
        """
        
        with self.db.get_cursor() as cur:
            cur.execute(query, (
                mac_address,
                ip_address,
                hostname,
                vendor_class,
                json.dumps(dhcp_options) if dhcp_options else None
            ))
            packet_id = cur.fetchone()[0]
            logger.debug(f"Inserted raw DHCP packet with ID: {packet_id}")
            return packet_id
    
    def get_unprocessed_packets(self, limit: int = 100) -> List[Dict]:
        """Get unprocessed DHCP packets for processing."""
        query = """
            SELECT packet_id, mac_address, ip_address, hostname, 
                   vendor_class, dhcp_options, packet_timestamp
            FROM raw_dhcp_packets 
            WHERE processed = FALSE 
            ORDER BY packet_timestamp ASC 
            LIMIT %s
        """
        
        with self.db.get_cursor(commit=False, dict_cursor=True) as cur:
            cur.execute(query, (limit,))
            packets = cur.fetchall()
            logger.debug(f"Retrieved {len(packets)} unprocessed packets")
            return packets
    
    def mark_packets_processed(self, packet_ids: List[int]):
        """Mark packets as processed."""
        if not packet_ids:
            return
        
        query = """
            UPDATE raw_dhcp_packets 
            SET processed = TRUE 
            WHERE packet_id = ANY(%s)
        """
        
        with self.db.get_cursor() as cur:
            cur.execute(query, (packet_ids,))
            logger.debug(f"Marked {len(packet_ids)} packets as processed")
    
    def get_packet_statistics(self) -> Dict:
        """Get packet capture statistics."""
        query = """
            SELECT 
                COUNT(*) as total_packets,
                COUNT(*) FILTER (WHERE processed = TRUE) as processed_packets,
                COUNT(*) FILTER (WHERE processed = FALSE) as unprocessed_packets,
                COUNT(DISTINCT mac_address) as unique_devices,
                MIN(packet_timestamp) as first_packet,
                MAX(packet_timestamp) as last_packet
            FROM raw_dhcp_packets
        """
        
        with self.db.get_cursor(dict_cursor=True) as cur:
            cur.execute(query)
            stats = cur.fetchone()
            return dict(stats)

class DeviceClassificationStore:
    """Handles device classification storage operations."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def insert_classification(self, mac_address: str, fingerbank_device_id: int = None,
                            device_name: str = None, device_type: str = None,
                            operating_system: str = None, confidence_score: int = None,
                            fingerbank_raw_response: Dict = None) -> int:
        """Insert device classification result."""
        query = """
            INSERT INTO device_classifications 
            (mac_address, fingerbank_device_id, device_name, device_type, 
             operating_system, confidence_score, fingerbank_raw_response)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        
        with self.db.get_cursor() as cur:
            cur.execute(query, (
                mac_address,
                fingerbank_device_id,
                device_name,
                device_type,
                operating_system,
                confidence_score,
                json.dumps(fingerbank_raw_response) if fingerbank_raw_response else None
            ))
            classification_id = cur.fetchone()[0]
            logger.debug(f"Inserted device classification with ID: {classification_id}")
            return classification_id
    
    def get_latest_classification(self, mac_address: str) -> Optional[Dict]:
        """Get the latest classification for a device."""
        query = """
            SELECT id, mac_address, fingerbank_device_id, device_name, 
                   device_type, operating_system, confidence_score, 
                   fingerbank_raw_response, classified_at
            FROM device_classifications 
            WHERE mac_address = %s 
            ORDER BY classified_at DESC 
            LIMIT 1
        """
        
        with self.db.get_cursor(commit=False, dict_cursor=True) as cur:
            cur.execute(query, (mac_address,))
            result = cur.fetchone()
            return dict(result) if result else None

class ActiveDeviceStore:
    """Handles active device inventory operations."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def upsert_active_device(self, mac_address: str, current_ip: str = None,
                           hostname: str = None, device_name: str = None,
                           device_type: str = None, operating_system: str = None) -> bool:
        """Insert or update active device information."""
        query = """
            INSERT INTO active_devices 
            (mac_address, current_ip, hostname, device_name, device_type, operating_system, first_seen)
            VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (mac_address) DO UPDATE SET
                current_ip = COALESCE(EXCLUDED.current_ip, active_devices.current_ip),
                hostname = COALESCE(EXCLUDED.hostname, active_devices.hostname),
                device_name = COALESCE(EXCLUDED.device_name, active_devices.device_name),
                device_type = COALESCE(EXCLUDED.device_type, active_devices.device_type),
                operating_system = COALESCE(EXCLUDED.operating_system, active_devices.operating_system),
                last_seen = CURRENT_TIMESTAMP,
                is_active = TRUE
        """
        
        with self.db.get_cursor() as cur:
            cur.execute(query, (
                mac_address, current_ip, hostname, 
                device_name, device_type, operating_system
            ))
            logger.debug(f"Upserted active device: {mac_address}")
            return True
    
    def get_active_devices(self, include_inactive: bool = False) -> List[Dict]:
        """Get all active devices."""
        where_clause = "" if include_inactive else "WHERE is_active = TRUE"
        query = f"""
            SELECT mac_address, current_ip, hostname, last_seen, first_seen,
                   device_name, device_type, operating_system, is_active
            FROM active_devices 
            {where_clause}
            ORDER BY last_seen DESC
        """
        
        with self.db.get_cursor(commit=False, dict_cursor=True) as cur:
            cur.execute(query)
            devices = cur.fetchall()
            return [dict(device) for device in devices]
    
    def mark_inactive_devices(self, inactive_threshold_hours: int = 168):  # 7 days
        """Mark devices as inactive if not seen for specified hours."""
        query = """
            UPDATE active_devices 
            SET is_active = FALSE 
            WHERE last_seen < (CURRENT_TIMESTAMP - INTERVAL '%s hours')
            AND is_active = TRUE
        """
        
        with self.db.get_cursor() as cur:
            cur.execute(query, (inactive_threshold_hours,))
            count = cur.rowcount
            logger.info(f"Marked {count} devices as inactive")
            return count
    
    def get_device_summary(self) -> List[Dict]:
        """Get comprehensive device summary using the view."""
        query = "SELECT * FROM device_summary"
        
        with self.db.get_cursor(commit=False, dict_cursor=True) as cur:
            cur.execute(query)
            devices = cur.fetchall()
            return [dict(device) for device in devices]

# Global database manager instance
db_manager = None

def initialize_database(min_connections: int = 2, max_connections: int = 10) -> DatabaseManager:
    """Initialize the global database manager."""
    global db_manager
    db_manager = DatabaseManager(min_connections, max_connections)
    return db_manager

def get_database_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    global db_manager
    if db_manager is None:
        db_manager = initialize_database()
    return db_manager

# Convenience functions for easy access
def get_dhcp_store() -> DHCPPacketStore:
    """Get DHCP packet store instance."""
    return DHCPPacketStore(get_database_manager())

def get_classification_store() -> DeviceClassificationStore:
    """Get device classification store instance."""
    return DeviceClassificationStore(get_database_manager())

def get_device_store() -> ActiveDeviceStore:
    """Get active device store instance."""
    return ActiveDeviceStore(get_database_manager())

if __name__ == "__main__":
    # Test the database module
    print("Testing database module...")
    
    try:
        # Initialize database
        db_mgr = initialize_database()
        
        # Test stores
        dhcp_store = get_dhcp_store()
        device_store = get_device_store()
        classification_store = get_classification_store()
        
        # Test basic operations
        print("✓ Database connection pool initialized")
        print("✓ All store instances created successfully")
        
        # Get statistics
        stats = dhcp_store.get_packet_statistics()
        print(f"✓ Packet statistics: {stats}")
        
        devices = device_store.get_active_devices()
        print(f"✓ Active devices count: {len(devices)}")
        
    except Exception as e:
        print(f"✗ Database module test failed: {e}")
    finally:
        if db_manager:
            db_manager.close_all_connections()