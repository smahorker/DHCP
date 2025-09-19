-- PostgreSQL schema for storing network device data
-- Optimized for the device classification results from DHCP analysis

-- Create database (run separately if needed)
-- CREATE DATABASE network_devices;

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Analysis Sessions table to track different analysis runs
CREATE TABLE analysis_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    total_devices INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Device Classifications table - main table for device data
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES analysis_sessions(id) ON DELETE CASCADE,
    mac_address VARCHAR(17) NOT NULL, -- MAC address format: XX:XX:XX:XX:XX:XX
    vendor VARCHAR(255),
    device_type VARCHAR(100),
    operating_system VARCHAR(100),
    hostname VARCHAR(255),
    overall_confidence VARCHAR(20) CHECK (overall_confidence IN ('high', 'medium', 'low', 'unknown')),
    has_vendor_class BOOLEAN NOT NULL DEFAULT FALSE,
    fingerbank_score INTEGER CHECK (fingerbank_score >= 0 AND fingerbank_score <= 100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Create unique constraint on session + MAC to prevent duplicates within same analysis
    UNIQUE(session_id, mac_address)
);

-- Analysis Statistics table for storing aggregated statistics
CREATE TABLE analysis_statistics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES analysis_sessions(id) ON DELETE CASCADE,
    high_confidence INTEGER NOT NULL DEFAULT 0,
    medium_confidence INTEGER NOT NULL DEFAULT 0,
    low_confidence INTEGER NOT NULL DEFAULT 0,
    unknown_confidence INTEGER NOT NULL DEFAULT 0,
    vendor_only INTEGER NOT NULL DEFAULT 0,
    fingerbank_used INTEGER NOT NULL DEFAULT 0,
    fallback_used INTEGER NOT NULL DEFAULT 0,
    hostname_available INTEGER NOT NULL DEFAULT 0,
    vendor_class_available INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Device Type Counts table for tracking device type distribution
CREATE TABLE device_type_counts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES analysis_sessions(id) ON DELETE CASCADE,
    device_type VARCHAR(100) NOT NULL,
    count INTEGER NOT NULL,
    percentage DECIMAL(5,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Operating System Counts table
CREATE TABLE operating_system_counts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES analysis_sessions(id) ON DELETE CASCADE,
    operating_system VARCHAR(100) NOT NULL,
    count INTEGER NOT NULL,
    percentage DECIMAL(5,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Vendor Counts table
CREATE TABLE vendor_counts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES analysis_sessions(id) ON DELETE CASCADE,
    vendor VARCHAR(255) NOT NULL,
    count INTEGER NOT NULL,
    percentage DECIMAL(5,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for better query performance
CREATE INDEX idx_devices_session_id ON devices(session_id);
CREATE INDEX idx_devices_mac_address ON devices(mac_address);
CREATE INDEX idx_devices_vendor ON devices(vendor);
CREATE INDEX idx_devices_device_type ON devices(device_type);
CREATE INDEX idx_devices_confidence ON devices(overall_confidence);
CREATE INDEX idx_devices_fingerbank_score ON devices(fingerbank_score);
CREATE INDEX idx_analysis_sessions_timestamp ON analysis_sessions(timestamp);

-- Views for common queries
-- View for device summary with session info
CREATE VIEW device_summary AS
SELECT 
    d.id,
    d.mac_address,
    d.vendor,
    d.device_type,
    d.operating_system,
    d.hostname,
    d.overall_confidence,
    d.has_vendor_class,
    d.fingerbank_score,
    s.timestamp as analysis_timestamp,
    d.created_at
FROM devices d
JOIN analysis_sessions s ON d.session_id = s.id;

-- View for latest analysis results
CREATE VIEW latest_devices AS
SELECT d.*
FROM devices d
JOIN analysis_sessions s ON d.session_id = s.id
WHERE s.timestamp = (SELECT MAX(timestamp) FROM analysis_sessions);

-- View for confidence distribution
CREATE VIEW confidence_distribution AS
SELECT 
    s.id as session_id,
    s.timestamp,
    COUNT(*) as total_devices,
    COUNT(*) FILTER (WHERE d.overall_confidence = 'high') as high_confidence,
    COUNT(*) FILTER (WHERE d.overall_confidence = 'medium') as medium_confidence,
    COUNT(*) FILTER (WHERE d.overall_confidence = 'low') as low_confidence,
    COUNT(*) FILTER (WHERE d.overall_confidence = 'unknown') as unknown_confidence,
    ROUND(COUNT(*) FILTER (WHERE d.overall_confidence = 'high') * 100.0 / COUNT(*), 2) as high_confidence_pct,
    ROUND(COUNT(*) FILTER (WHERE d.overall_confidence = 'medium') * 100.0 / COUNT(*), 2) as medium_confidence_pct
FROM analysis_sessions s
LEFT JOIN devices d ON s.id = d.session_id
GROUP BY s.id, s.timestamp;

-- View for device type summary
CREATE VIEW device_type_summary AS
SELECT 
    s.timestamp,
    d.device_type,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY s.id), 2) as percentage
FROM analysis_sessions s
JOIN devices d ON s.id = d.session_id
GROUP BY s.id, s.timestamp, d.device_type
ORDER BY s.timestamp DESC, count DESC;

-- Function to calculate statistics for a session
CREATE OR REPLACE FUNCTION calculate_session_statistics(session_uuid UUID)
RETURNS VOID AS $$
DECLARE
    total_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO total_count FROM devices WHERE session_id = session_uuid;
    
    -- Update device_type_counts
    INSERT INTO device_type_counts (session_id, device_type, count, percentage)
    SELECT 
        session_uuid,
        device_type,
        COUNT(*),
        ROUND(COUNT(*) * 100.0 / total_count, 2)
    FROM devices 
    WHERE session_id = session_uuid 
    GROUP BY device_type
    ON CONFLICT DO NOTHING;
    
    -- Update operating_system_counts
    INSERT INTO operating_system_counts (session_id, operating_system, count, percentage)
    SELECT 
        session_uuid,
        COALESCE(operating_system, 'Unknown'),
        COUNT(*),
        ROUND(COUNT(*) * 100.0 / total_count, 2)
    FROM devices 
    WHERE session_id = session_uuid 
    GROUP BY operating_system
    ON CONFLICT DO NOTHING;
    
    -- Update vendor_counts
    INSERT INTO vendor_counts (session_id, vendor, count, percentage)
    SELECT 
        session_uuid,
        COALESCE(vendor, 'Unknown'),
        COUNT(*),
        ROUND(COUNT(*) * 100.0 / total_count, 2)
    FROM devices 
    WHERE session_id = session_uuid 
    GROUP BY vendor
    ON CONFLICT DO NOTHING;
END;
$$ LANGUAGE plpgsql;