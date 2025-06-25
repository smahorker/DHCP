-- Complete database schema for Network Device Monitoring System
-- Phase 2: Database Design & Setup

-- Drop existing tables if they exist (for clean rebuild)
DROP TABLE IF EXISTS device_connections CASCADE;
DROP TABLE IF EXISTS devices CASCADE;

-- Phase 2 Required Tables

-- Table 1: raw_dhcp_packets
-- Purpose: Store every captured DHCP packet for processing
CREATE TABLE IF NOT EXISTS raw_dhcp_packets (
    packet_id SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL,
    ip_address INET,
    hostname VARCHAR(255),
    vendor_class VARCHAR(255),
    dhcp_options JSON,
    packet_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table 2: device_classifications  
-- Purpose: Store Fingerbank API responses and device classifications
CREATE TABLE IF NOT EXISTS device_classifications (
    id SERIAL PRIMARY KEY,
    mac_address VARCHAR(17) NOT NULL,
    fingerbank_device_id INTEGER,
    device_name VARCHAR(255),
    device_type VARCHAR(100),
    operating_system VARCHAR(100),
    confidence_score INTEGER,
    fingerbank_raw_response JSON,
    classified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table 3: active_devices
-- Purpose: Current device inventory with latest information  
CREATE TABLE IF NOT EXISTS active_devices (
    mac_address VARCHAR(17) PRIMARY KEY,
    current_ip INET,
    hostname VARCHAR(255),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    device_name VARCHAR(255),
    device_type VARCHAR(100),
    operating_system VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE
);

-- Additional table for packet capture statistics
CREATE TABLE IF NOT EXISTS capture_statistics (
    id SERIAL PRIMARY KEY,
    session_start TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    session_end TIMESTAMP WITH TIME ZONE,
    packets_captured INTEGER DEFAULT 0,
    packets_processed INTEGER DEFAULT 0,
    unique_devices INTEGER DEFAULT 0,
    errors_encountered INTEGER DEFAULT 0,
    interface_name VARCHAR(50)
);

-- Create indexes for fast lookups as required
CREATE INDEX IF NOT EXISTS idx_raw_dhcp_packets_mac_address ON raw_dhcp_packets(mac_address);
CREATE INDEX IF NOT EXISTS idx_raw_dhcp_packets_processed ON raw_dhcp_packets(processed);
CREATE INDEX IF NOT EXISTS idx_raw_dhcp_packets_timestamp ON raw_dhcp_packets(packet_timestamp);

CREATE INDEX IF NOT EXISTS idx_device_classifications_mac_address ON device_classifications(mac_address);
CREATE INDEX IF NOT EXISTS idx_device_classifications_fingerbank_id ON device_classifications(fingerbank_device_id);
CREATE INDEX IF NOT EXISTS idx_device_classifications_classified_at ON device_classifications(classified_at);

CREATE INDEX IF NOT EXISTS idx_active_devices_last_seen ON active_devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_active_devices_is_active ON active_devices(is_active);
CREATE INDEX IF NOT EXISTS idx_active_devices_device_type ON active_devices(device_type);

-- Foreign key relationships
ALTER TABLE device_classifications 
ADD CONSTRAINT fk_device_classifications_mac 
FOREIGN KEY (mac_address) REFERENCES active_devices(mac_address) 
ON DELETE CASCADE ON UPDATE CASCADE;

-- Insert test records for validation
INSERT INTO raw_dhcp_packets (mac_address, ip_address, hostname, vendor_class, dhcp_options, processed) 
VALUES 
    ('00:11:22:33:44:55', '192.168.1.100'::inet, 'test-device-1', 'MSFT 5.0', '{"option_12": "test-device-1", "option_55": "1,3,6,15,119,95,252,44,46,47", "option_60": "MSFT 5.0"}', FALSE),
    ('aa:bb:cc:dd:ee:ff', '192.168.1.101'::inet, 'test-device-2', 'dhcpcd-6.8.2', '{"option_12": "test-device-2", "option_55": "1,28,2,3,15,6,119,12,44,47,26,121,42", "option_60": "dhcpcd-6.8.2"}', FALSE)
ON CONFLICT DO NOTHING;

INSERT INTO active_devices (mac_address, current_ip, hostname, device_name, device_type, operating_system) 
VALUES 
    ('00:11:22:33:44:55', '192.168.1.100'::inet, 'test-device-1', 'Windows Computer', 'Computer', 'Windows 10'),
    ('aa:bb:cc:dd:ee:ff', '192.168.1.101'::inet, 'test-device-2', 'Linux Computer', 'Computer', 'Linux')
ON CONFLICT (mac_address) DO UPDATE SET
    current_ip = EXCLUDED.current_ip,
    hostname = EXCLUDED.hostname,
    last_seen = CURRENT_TIMESTAMP;

-- Create a view for easy device monitoring
CREATE OR REPLACE VIEW device_summary AS
SELECT 
    ad.mac_address,
    ad.current_ip,
    ad.hostname,
    ad.device_name,
    ad.device_type,
    ad.operating_system,
    ad.last_seen,
    ad.first_seen,
    ad.is_active,
    dc.confidence_score,
    dc.classified_at,
    (SELECT COUNT(*) FROM raw_dhcp_packets rdp WHERE rdp.mac_address = ad.mac_address) as total_packets
FROM active_devices ad
LEFT JOIN LATERAL (
    SELECT confidence_score, classified_at 
    FROM device_classifications dc2 
    WHERE dc2.mac_address = ad.mac_address 
    ORDER BY classified_at DESC 
    LIMIT 1
) dc ON true
ORDER BY ad.last_seen DESC;

-- Grant permissions (adjust user as needed)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_app_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO your_app_user;