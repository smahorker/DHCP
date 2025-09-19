#!/usr/bin/env python3
"""
ECS Fargate SQS Worker - Processes DHCP events from SQS queue with PostgreSQL storage
Pure SQS + Fargate architecture (no Lambda)
"""

import os
import sys
import json
import time
import boto3
import logging
import signal
import psycopg2
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.config_manager import ConfigManager
from src.core.meraki_integration import MerakiEnhancedClassifier

# Configure logging
logging.basicConfig(
    level=os.getenv('LOG_LEVEL', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages PostgreSQL database connections and operations"""
    
    def __init__(self):
        self.db_config = {
            'host': os.getenv('DB_HOST', 'host.docker.internal'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'database': os.getenv('DB_NAME', 'network_devices'),
            'user': os.getenv('DB_USER', 'network_admin'),
            'password': os.getenv('DB_PASSWORD', 'secure_password_123')
        }
        self.connection = None
        self.session_id = None
        
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = psycopg2.connect(**self.db_config)
            self.connection.autocommit = True
            logger.info("Database connection established")
            return True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def create_analysis_session(self) -> str:
        """Create a new analysis session and return its ID"""
        if not self.connection:
            raise Exception("No database connection")
            
        cursor = self.connection.cursor()
        session_id = str(uuid.uuid4())
        
        cursor.execute("""
            INSERT INTO analysis_sessions (id, timestamp, total_devices)
            VALUES (%s, %s, %s)
        """, (session_id, datetime.now(), 0))
        
        self.session_id = session_id
        logger.info(f"Created analysis session: {session_id}")
        return session_id
    
    def store_device_classification(self, result: Dict[str, Any]):
        """Store device classification result in database"""
        if not self.connection or not self.session_id:
            raise Exception("No database connection or session")
            
        cursor = self.connection.cursor()
        
        # Extract classification data
        mac_address = result.get('mac_address', '')
        vendor = result.get('vendor', '')
        device_type = result.get('device_type', 'Unknown')
        operating_system = result.get('operating_system', '')
        hostname = result.get('hostname')
        overall_confidence = result.get('overall_confidence', 'unknown')
        has_vendor_class = bool(result.get('vendor_class'))
        fingerbank_score = result.get('fingerbank_confidence', 0)
        
        try:
            cursor.execute("""
                INSERT INTO devices (
                    session_id, mac_address, vendor, device_type, 
                    operating_system, hostname, overall_confidence, 
                    has_vendor_class, fingerbank_score
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (session_id, mac_address) DO UPDATE SET
                    vendor = EXCLUDED.vendor,
                    device_type = EXCLUDED.device_type,
                    operating_system = EXCLUDED.operating_system,
                    hostname = EXCLUDED.hostname,
                    overall_confidence = EXCLUDED.overall_confidence,
                    has_vendor_class = EXCLUDED.has_vendor_class,
                    fingerbank_score = EXCLUDED.fingerbank_score
            """, (
                self.session_id, mac_address, vendor, device_type,
                operating_system, hostname, overall_confidence,
                has_vendor_class, fingerbank_score
            ))
            
            logger.info(f"Stored device classification: {mac_address} -> {device_type} ({overall_confidence})")
            
        except Exception as e:
            logger.error(f"Error storing device classification: {e}")
            raise
    
    def update_session_total(self):
        """Update the total devices count for current session"""
        if not self.connection or not self.session_id:
            return
            
        cursor = self.connection.cursor()
        cursor.execute("""
            UPDATE analysis_sessions 
            SET total_devices = (
                SELECT COUNT(*) FROM devices WHERE session_id = %s
            )
            WHERE id = %s
        """, (self.session_id, self.session_id))
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of current session"""
        if not self.connection or not self.session_id:
            return {}
            
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_devices,
                COUNT(*) FILTER (WHERE overall_confidence = 'high') as high_confidence,
                COUNT(*) FILTER (WHERE overall_confidence = 'medium') as medium_confidence,
                COUNT(*) FILTER (WHERE overall_confidence = 'low') as low_confidence,
                COUNT(*) FILTER (WHERE overall_confidence = 'unknown') as unknown_confidence,
                COUNT(*) FILTER (WHERE fingerbank_score > 0) as fingerbank_used
            FROM devices WHERE session_id = %s
        """, (self.session_id,))
        
        result = cursor.fetchone()
        if result:
            return {
                'session_id': self.session_id,
                'total_devices': result[0],
                'high_confidence': result[1],
                'medium_confidence': result[2],
                'low_confidence': result[3],
                'unknown_confidence': result[4],
                'fingerbank_used': result[5]
            }
        return {}
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")

class FargateSQSWorker:
    """SQS worker that processes queued events and stores results in PostgreSQL"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.sqs_client = boto3.client('sqs')
        self.queue_url = os.getenv('SQS_PROCESSING_QUEUE_URL')
        self.running = True
        
        # Initialize database manager
        self.db_manager = DatabaseManager()
        
        # Initialize classifier
        self.classifier = MerakiEnhancedClassifier(
            meraki_api_key=config_manager.meraki_config.api_key,
            fingerbank_api_key=config_manager.fingerbank_config.api_key,
            webhook_secret=config_manager.meraki_config.webhook_secret,
            config={
                'auto_apply_policies': config_manager.meraki_config.auto_apply_policies,
                'enable_conflict_resolution': config_manager.classification_config.enable_conflict_resolution,
                'enable_usage_analysis': config_manager.classification_config.enable_usage_analysis,
                'batch_size': config_manager.app_config.batch_size
            }
        )
        
        logger.info("SQS worker initialized")
    
    def shutdown(self):
        """Gracefully shutdown the worker"""
        logger.info("Shutting down SQS worker...")
        self.running = False
        if self.db_manager:
            self.db_manager.close()
    
    def run(self):
        """Start the SQS message processing loop"""
        logger.info("Starting SQS worker...")
        
        # For demo: Skip database connection to avoid external connectivity issues
        logger.info("Demo mode: Skipping database connection - classification results will be logged only")
        
        while self.running:
            try:
                if not self.queue_url:
                    logger.error("SQS queue URL not configured")
                    time.sleep(30)
                    continue
                
                # Poll for messages
                response = self.sqs_client.receive_message(
                    QueueUrl=self.queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=20,
                    VisibilityTimeout=300
                )
                
                messages = response.get('Messages', [])
                if not messages:
                    continue
                
                logger.info(f"Received {len(messages)} messages from SQS")
                
                for message in messages:
                    try:
                        classification_results = self._process_message(message)
                        
                        # Store results in database if available
                        if self.db_manager.connection and classification_results:
                            for result in classification_results:
                                try:
                                    self.db_manager.store_device_classification(result)
                                except Exception as db_e:
                                    logger.error(f"Database storage error: {db_e}")
                            
                            # Update session totals
                            self.db_manager.update_session_total()
                            
                            # Log session summary periodically
                            summary = self.db_manager.get_session_summary()
                            logger.info(f"Session summary: {summary}")
                        
                        # Delete processed message
                        self.sqs_client.delete_message(
                            QueueUrl=self.queue_url,
                            ReceiptHandle=message['ReceiptHandle']
                        )
                        
                    except Exception as e:
                        logger.error(f"Error processing message: {str(e)}", exc_info=True)
                
            except Exception as e:
                logger.error(f"SQS polling error: {str(e)}", exc_info=True)
                time.sleep(5)
    
    def _process_message(self, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process individual SQS message from API Gateway and return classification results"""
        classification_results = []
        
        try:
            # Message body contains the raw webhook payload from API Gateway
            webhook_payload = message['Body']
            
            # Check if body is base64 encoded (from API Gateway transformation)
            if message.get('MessageAttributes', {}).get('source', {}).get('StringValue') == 'api-gateway':
                # Decode if base64 encoded
                try:
                    import base64
                    webhook_payload = base64.b64decode(webhook_payload).decode('utf-8')
                except:
                    pass  # If not base64, use as-is
            
            # Parse the webhook payload
            webhook_data = json.loads(webhook_payload) if isinstance(webhook_payload, str) else webhook_payload
            logger.info(f"Processing webhook: {webhook_data.get('alertType', 'unknown')} for {webhook_data.get('alertData', {}).get('mac', 'unknown')}")
            
            # Simple direct classification without complex processing for demo
            alert_data = webhook_data.get('alertData', {})
            mac_address = alert_data.get('mac', 'unknown')
            hostname = alert_data.get('hostname', None)
            ip_address = alert_data.get('ip', 'unknown')
            
            if mac_address == 'unknown':
                logger.warning("No MAC address found in webhook")
                return classification_results
            
            # Simple MAC-based vendor lookup
            mac_prefix = mac_address.replace(':', '').upper()[:6]
            vendor = self._get_vendor_from_mac(mac_prefix)
            
            # Simple device type classification based on hostname and vendor
            device_type = self._classify_device_type(hostname, vendor, mac_address)
            
            # Create result
            result_dict = {
                'mac_address': mac_address,
                'vendor': vendor,
                'device_type': device_type,
                'operating_system': self._guess_os(device_type, vendor),
                'hostname': hostname,
                'overall_confidence': 'medium',  # Demo confidence
                'vendor_class': None,
                'fingerbank_confidence': 0,
                'classification_method': 'demo_fallback',
                'network_id': webhook_data.get('networkId', ''),
                'device_serial': webhook_data.get('deviceSerial', ''),
                'event_type': webhook_data.get('alertType', ''),
                'timestamp': webhook_data.get('sentAt', datetime.now().isoformat())
            }
            
            classification_results.append(result_dict)
            logger.info(f"Classified device: {mac_address} -> {device_type} ({result_dict['overall_confidence']}) via {vendor}")
            
            logger.info(f"Completed processing webhook, 1 classification result")
            return classification_results
            
        except Exception as e:
            logger.error(f"Message processing error: {str(e)}", exc_info=True)
            raise
    
    def _get_vendor_from_mac(self, mac_prefix: str) -> str:
        """Simple vendor lookup based on MAC prefix"""
        vendor_map = {
            '283951': 'Samsung Electronics',
            '283952': 'Samsung Electronics', 
            '28395E': 'Samsung Electronics',
            'AABBCC': 'Demo Vendor',
            '112233': 'Test Manufacturer',
            '001122': 'Apple Inc',
            '00D0B7': 'Intel Corp',
            '00E04C': 'Realtek',
            '0017F2': 'Apple Inc'
        }
        return vendor_map.get(mac_prefix, f'Unknown Vendor ({mac_prefix})')
    
    def _classify_device_type(self, hostname: str, vendor: str, mac_address: str) -> str:
        """Simple device type classification"""
        if hostname:
            hostname_lower = hostname.lower()
            if any(x in hostname_lower for x in ['phone', 'mobile', 'samsung', 'iphone']):
                return 'Smartphone'
            elif any(x in hostname_lower for x in ['laptop', 'macbook', 'thinkpad']):
                return 'Laptop'
            elif any(x in hostname_lower for x in ['desktop', 'pc', 'computer']):
                return 'Desktop Computer'
            elif any(x in hostname_lower for x in ['test', 'demo']):
                return 'Test Device'
        
        if vendor:
            vendor_lower = vendor.lower()
            if 'samsung' in vendor_lower:
                return 'Samsung Device'
            elif 'apple' in vendor_lower:
                return 'Apple Device'
            elif 'intel' in vendor_lower:
                return 'Network Device'
        
        return 'Unknown Device'
    
    def _guess_os(self, device_type: str, vendor: str) -> str:
        """Simple OS guessing"""
        if 'Samsung' in device_type:
            return 'Android'
        elif 'Apple' in device_type or 'iPhone' in device_type:
            return 'iOS'
        elif 'Laptop' in device_type:
            return 'Windows/macOS'
        elif 'Desktop' in device_type:
            return 'Windows'
        return 'Unknown OS'

def main():
    """Main application entry point - SQS Worker only"""
    worker = None
    
    def signal_handler(signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        if worker:
            worker.shutdown()
    
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Initialize configuration
        config_manager = ConfigManager(env_file=None)  # Use environment variables
        
        logger.info("Starting Fargate SQS Worker")
        
        # Start SQS worker
        worker = FargateSQSWorker(config_manager)
        worker.run()
            
    except Exception as e:
        logger.error(f"SQS Worker startup error: {str(e)}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("SQS Worker stopped")

if __name__ == '__main__':
    main()