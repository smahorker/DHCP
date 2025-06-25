#!/usr/bin/env python3
"""
Network Device Monitoring System - Main Application
Integrates all phases: packet capture, parsing, classification, and inventory management.
"""

import os
import sys
import time
import signal
import threading
from datetime import datetime
import logging
from typing import List

# Import all our modules
from core.database import initialize_database, get_database_manager
from core.packet_capture import DHCPPacketCaptureEngine, DHCPPacketInfo
from core.dhcp_parser import DHCPPacketParser, DeviceFingerprint
from core.fingerbank_api import FingerbankAPIClient, DeviceClassificationManager
from core.device_inventory import DeviceInventoryManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class NetworkMonitoringSystem:
    """
    Main network monitoring system that orchestrates all components.
    Integrates all 6 phases into a complete solution.
    """
    
    def __init__(self, interface: str = None, fingerbank_api_key: str = None):
        """Initialize the complete network monitoring system."""
        logger.info("Initializing Network Device Monitoring System")
        
        # Initialize database
        self.db_manager = initialize_database()
        logger.info("✓ Database connection established")
        
        # Initialize packet capture (Phase 3)
        self.packet_capture = DHCPPacketCaptureEngine(interface=interface, store_packets=True)
        self.packet_capture.set_packet_callback(self._on_packet_captured)
        logger.info("✓ DHCP packet capture engine initialized")
        
        # Initialize packet parser (Phase 4)
        self.packet_parser = DHCPPacketParser()
        logger.info("✓ DHCP packet parser initialized")
        
        # Initialize Fingerbank API client (Phase 5)
        try:
            self.api_client = FingerbankAPIClient(api_key=fingerbank_api_key)
            self.classification_manager = DeviceClassificationManager(self.api_client)
            logger.info("✓ Fingerbank API client initialized")
        except Exception as e:
            logger.warning(f"Fingerbank API not available: {e}")
            self.api_client = None
            self.classification_manager = None
        
        # Initialize device inventory manager (Phase 6)
        self.inventory_manager = DeviceInventoryManager()
        logger.info("✓ Device inventory manager initialized")
        
        # Processing control
        self.is_running = False
        self.processing_thread = None
        self.processing_interval = 30  # Process every 30 seconds
        
        # Statistics
        self.start_time = None
        self.packets_processed = 0
        self.devices_classified = 0
        
        logger.info("Network Device Monitoring System initialized successfully")
    
    def _on_packet_captured(self, dhcp_info: DHCPPacketInfo):
        """Callback function for when DHCP packets are captured."""
        logger.debug(f"DHCP packet captured: {dhcp_info.mac_address} -> {dhcp_info.ip_address}")
        # Packet is automatically stored in database by capture engine
    
    def _processing_loop(self):
        """Main processing loop that runs in separate thread."""
        logger.info("Starting packet processing loop")
        
        while self.is_running:
            try:
                # Phase 4: Process unprocessed DHCP packets
                fingerprints = self.packet_parser.process_unprocessed_packets(batch_size=50)
                
                if fingerprints:
                    logger.info(f"Processed {len(fingerprints)} device fingerprints")
                    self.packets_processed += len(fingerprints)
                    
                    # Phase 5: Classify devices with Fingerbank API (if available)
                    if self.classification_manager and fingerprints:
                        # Filter valid fingerprints
                        valid_fingerprints = [fp for fp in fingerprints if self.packet_parser.validate_fingerprint_data(fp)]
                        
                        if valid_fingerprints:
                            logger.info(f"Classifying {len(valid_fingerprints)} devices with Fingerbank API")
                            
                            # Process in smaller batches to respect rate limits
                            batch_size = 10
                            for i in range(0, len(valid_fingerprints), batch_size):
                                batch = valid_fingerprints[i:i+batch_size]
                                
                                # Check if we can make requests
                                if self.api_client.rate_limiter.can_make_request():
                                    self.classification_manager.classify_and_store_fingerprints(batch, batch_delay=2.0)
                                    self.devices_classified += len(batch)
                                else:
                                    logger.info("Rate limit reached, deferring classification to next cycle")
                                    break
                
                # Phase 6: Update device inventory and mark inactive devices
                inactive_count = self.inventory_manager.mark_inactive_devices()
                if inactive_count > 0:
                    logger.info(f"Marked {inactive_count} devices as inactive")
                
                # Wait before next processing cycle
                time.sleep(self.processing_interval)
                
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                time.sleep(self.processing_interval)
    
    def start(self):
        """Start the network monitoring system."""
        if self.is_running:
            logger.warning("System is already running")
            return
        
        logger.info("Starting Network Device Monitoring System")
        
        self.is_running = True
        self.start_time = datetime.now()
        
        # Start packet capture
        self.packet_capture.start()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
        self.processing_thread.start()
        
        logger.info("✓ Network monitoring system started successfully")
        logger.info("System is now capturing DHCP packets and monitoring network devices")
        logger.info("ONLY DHCP traffic is captured - your other applications are not monitored")
    
    def stop(self):
        """Stop the network monitoring system."""
        if not self.is_running:
            logger.warning("System is not running")
            return
        
        logger.info("Stopping Network Device Monitoring System")
        
        self.is_running = False
        
        # Stop packet capture
        self.packet_capture.stop()
        
        # Wait for processing thread to finish
        if self.processing_thread:
            self.processing_thread.join(timeout=10)
        
        # Close database connections
        self.db_manager.close_all_connections()
        
        logger.info("✓ Network monitoring system stopped")
    
    def get_system_status(self) -> dict:
        """Get comprehensive system status."""
        runtime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        status = {
            'system': {
                'is_running': self.is_running,
                'runtime_seconds': runtime,
                'start_time': self.start_time.isoformat() if self.start_time else None
            },
            'packet_capture': self.packet_capture.get_statistics(),
            'packet_processing': self.packet_parser.get_processing_statistics(),
            'device_inventory': self.inventory_manager.get_inventory_statistics(),
            'system_totals': {
                'packets_processed': self.packets_processed,
                'devices_classified': self.devices_classified
            }
        }
        
        # Add API statistics if available
        if self.api_client:
            status['fingerbank_api'] = self.api_client.get_api_statistics()
        
        return status
    
    def get_device_list(self, include_inactive: bool = False) -> List[dict]:
        """Get list of discovered devices."""
        devices = self.inventory_manager.get_device_inventory(include_inactive=include_inactive)
        
        return [{
            'mac_address': device.mac_address,
            'device_name': device.device_name or 'Unknown Device',
            'device_type': device.device_type or 'Unknown',
            'operating_system': device.operating_system or 'Unknown',
            'current_ip': device.current_ip,
            'hostname': device.hostname,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            'is_active': device.is_active,
            'confidence_score': device.confidence_score,
            'total_packets': device.total_packets
        } for device in devices]
    
    def print_status_report(self):
        """Print a comprehensive status report."""
        print("\n" + "="*60)
        print("NETWORK DEVICE MONITORING SYSTEM - STATUS REPORT")
        print("="*60)
        
        status = self.get_system_status()
        
        # System status
        print(f"System Status: {'RUNNING' if status['system']['is_running'] else 'STOPPED'}")
        if status['system']['runtime_seconds']:
            runtime_hours = status['system']['runtime_seconds'] / 3600
            print(f"Runtime: {runtime_hours:.1f} hours")
        
        # Packet capture stats
        capture_stats = status['packet_capture']
        print(f"\nPacket Capture:")
        print(f"  Interface: {capture_stats['interface']}")
        print(f"  Filter: {capture_stats['packet_filter']}")
        print(f"  Packets Captured: {capture_stats['packets_captured']}")
        print(f"  Errors: {capture_stats['errors_encountered']}")
        
        # Device inventory
        inventory_stats = status['device_inventory']
        print(f"\nDevice Inventory:")
        print(f"  Total Devices: {inventory_stats.get('total_devices', 0)}")
        print(f"  Active Devices: {inventory_stats.get('active_devices', 0)}")
        print(f"  Recent Activity (24h): {inventory_stats.get('recent_activity_24h', 0)}")
        
        # Device types breakdown
        device_types = inventory_stats.get('device_types', {})
        if device_types:
            print("  Device Types:")
            for dtype, count in sorted(device_types.items()):
                print(f"    {dtype}: {count}")
        
        # API stats if available
        if 'fingerbank_api' in status:
            api_stats = status['fingerbank_api']
            print(f"\nFingerbank API:")
            print(f"  Total Requests: {api_stats['total_requests']}")
            print(f"  Success Rate: {api_stats['success_rate']:.1f}%")
            print(f"  Rate Limit Used: {api_stats['rate_limit_status']['hourly_used']}/{api_stats['rate_limit_status']['hourly_limit']}")
        
        print("="*60)

def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown."""
    logger.info("Received shutdown signal, stopping system...")
    if hasattr(signal_handler, 'monitor'):
        signal_handler.monitor.stop()
    sys.exit(0)

def main():
    """Main entry point for the network monitoring system."""
    print("Network Device Monitoring System")
    print("Phase 2-6 Complete Implementation")
    print("="*50)
    print("This system captures ONLY DHCP packets for device discovery.")
    print("Your other network traffic is NOT monitored.")
    print("="*50)
    
    # Check for required environment variables
    if not os.getenv('FINGERBANK_API_KEY'):
        print("WARNING: FINGERBANK_API_KEY not set. Device classification will be limited.")
        print("Get your API key from: https://fingerbank.org/api_keys")
        print()
    
    try:
        # Initialize system
        monitor = NetworkMonitoringSystem()
        signal_handler.monitor = monitor  # Store reference for signal handler
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start monitoring
        monitor.start()
        
        print("Network monitoring started successfully!")
        print("Press Ctrl+C to stop")
        print()
        
        # Main loop - print status every 5 minutes
        last_status_time = time.time()
        status_interval = 300  # 5 minutes
        
        while True:
            time.sleep(10)  # Check every 10 seconds
            
            current_time = time.time()
            if current_time - last_status_time >= status_interval:
                monitor.print_status_report()
                last_status_time = current_time
    
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        logger.error(f"System error: {e}")
        print(f"System error: {e}")
    finally:
        if 'monitor' in locals():
            monitor.stop()
        print("Network monitoring system stopped")

if __name__ == "__main__":
    main()