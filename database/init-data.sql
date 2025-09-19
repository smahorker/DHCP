-- Initial data setup for network devices database
-- This file runs after schema.sql during container initialization

-- Create a sample analysis session for testing
INSERT INTO analysis_sessions (id, timestamp, total_devices) 
VALUES ('550e8400-e29b-41d4-a716-446655440000', '2025-07-16 00:00:00+00', 0);

-- You can add any initial reference data here
-- For example, common device types or vendors

-- Common device types reference (optional)
CREATE TABLE IF NOT EXISTS reference_device_types (
    device_type VARCHAR(100) PRIMARY KEY,
    category VARCHAR(50),
    description TEXT
);

INSERT INTO reference_device_types (device_type, category, description) VALUES
('Phone', 'Mobile', 'Smartphones and mobile devices'),
('Computer', 'Computing', 'Desktop computers and workstations'),
('Laptop', 'Computing', 'Portable computers and laptops'),
('IoT Device', 'IoT', 'Internet of Things devices'),
('Smart Camera', 'Security', 'IP cameras and security devices'),
('Network Device', 'Infrastructure', 'Routers, switches, and network equipment'),
('Smart TV', 'Entertainment', 'Smart televisions and streaming devices'),
('Single Board Computer', 'Computing', 'Raspberry Pi and similar devices'),
('Gaming Console', 'Entertainment', 'Gaming systems and consoles'),
('Printer', 'Office', 'Printers and printing devices'),
('Smart Thermostat', 'IoT', 'Smart home thermostats and HVAC controls')
ON CONFLICT (device_type) DO NOTHING;

-- Grant permissions to the application user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO network_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO network_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO network_admin;