#!/usr/bin/env python3
"""
Database connectivity test script for network monitoring system.
Tests PostgreSQL connection and basic operations.
"""

import os
import sys
import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_database_connection():
    """Test PostgreSQL database connection."""
    
    # Database connection parameters
    db_params = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': os.getenv('DB_PORT', '5432'),
        'database': os.getenv('DB_NAME', 'network_monitoring'),
        'user': os.getenv('DB_USER', 'postgres'),
        'password': os.getenv('DB_PASSWORD', '')
    }
    
    print("Testing PostgreSQL connection...")
    print(f"Host: {db_params['host']}")
    print(f"Port: {db_params['port']}")
    print(f"Database: {db_params['database']}")
    print(f"User: {db_params['user']}")
    print()
    
    try:
        # Attempt to connect
        conn = psycopg2.connect(**db_params)
        cur = conn.cursor()
        
        # Test basic query
        cur.execute("SELECT version();")
        version = cur.fetchone()
        print("✓ Database connection successful!")
        print(f"PostgreSQL version: {version[0]}")
        
        # Test table creation
        cur.execute("""
            CREATE TABLE IF NOT EXISTS connection_test (
                id SERIAL PRIMARY KEY,
                test_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                test_data VARCHAR(100)
            )
        """)
        
        # Test insert
        cur.execute(
            "INSERT INTO connection_test (test_data) VALUES (%s)",
            ("Test connection successful",)
        )
        
        # Test select
        cur.execute("SELECT * FROM connection_test ORDER BY id DESC LIMIT 1")
        result = cur.fetchone()
        print(f"✓ Test record created: ID {result[0]}, Time: {result[1]}")
        
        # Clean up test table
        cur.execute("DROP TABLE connection_test")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("✓ All database tests passed!")
        return True
        
    except psycopg2.Error as e:
        print(f"✗ Database connection failed: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("Network Monitoring System - Database Connectivity Test")
    print("=" * 55)
    
    success = test_database_connection()
    
    if success:
        print("\n✓ Database setup is ready!")
        sys.exit(0)
    else:
        print("\n✗ Database setup needs attention.")
        print("\nNext steps:")
        print("1. Ensure PostgreSQL is installed and running")
        print("2. Create a .env file with database credentials:")
        print("   DB_HOST=localhost")
        print("   DB_PORT=5432")
        print("   DB_NAME=network_monitoring")
        print("   DB_USER=your_username")
        print("   DB_PASSWORD=your_password")
        sys.exit(1)