#!/usr/bin/env python3
"""
Meraki Cloud Integration for Enhanced Device Classification
Combines Meraki network data with existing classification system
"""

from .dhcp_device_analyzer import OptimizedDHCPDeviceAnalyzer
from .meraki_api_client import MerakiAPIClient
from .meraki_webhook_handler import MerakiWebhookHandler
from .dhcp_log_parser import DHCPLogEntry
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import threading
import time

@dataclass
class EnhancedClassificationResult:
    """Enhanced classification result with Meraki data"""
    mac_address: str
    device_type: str
    overall_confidence: str
    classification_method: str
    fingerbank_data: Dict
    meraki_data: Dict
    usage_patterns: Dict
    conflict_resolution: Optional[str] = None
    accuracy_enhancement: Optional[str] = None
    timestamp: str = ""

class MerakiEnhancedClassifier:
    def __init__(self, meraki_api_key: str, fingerbank_api_key: str, 
                 webhook_secret: str, config: Dict = None):
        # Initialize existing system
        self.device_analyzer = OptimizedDHCPDeviceAnalyzer(fingerbank_api_key)
        
        # Initialize Meraki components
        self.meraki_client = MerakiAPIClient(meraki_api_key)
        self.webhook_handler = MerakiWebhookHandler(webhook_secret, self.device_analyzer)
        
        # Configuration
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Enhanced classification stats
        self.meraki_classifications = 0
        self.accuracy_improvements = 0
        self.conflict_resolutions = 0
        self.classification_cache = {}
        
        # Device type mappings
        self.device_type_mappings = {
            'Mobile Device': ['Phone', 'Tablet'],
            'Computer': ['Laptop', 'Desktop', 'Computer'],
            'Gaming Console': ['Gaming Console', 'Gaming Device'],
            'Smart TV': ['Smart TV', 'Streaming Device', 'Media Player'],
            'IoT Device': ['IoT Device', 'Smart Home', 'Sensor'],
            'Network Infrastructure': ['Router', 'Switch', 'Access Point'],
            'Printer': ['Printer', 'Scanner', 'Multifunction Device']
        }

        # Manufacturer device type hints
        self.manufacturer_hints = {
            'Apple': ['Phone', 'Tablet', 'Computer', 'Smart TV'],
            'Samsung': ['Phone', 'Tablet', 'Smart TV'],
            'Google': ['Phone', 'Tablet', 'Smart TV', 'IoT Device'],
            'Amazon': ['Smart TV', 'IoT Device', 'Smart Speaker'],
            'Nintendo': ['Gaming Console'],
            'Sony': ['Gaming Console', 'Smart TV'],
            'Microsoft': ['Gaming Console', 'Computer', 'Tablet'],
            'HP': ['Printer', 'Computer'],
            'Canon': ['Printer', 'Scanner'],
            'Roku': ['Smart TV', 'Streaming Device'],
            'Nest': ['IoT Device', 'Smart Home'],
            'Ring': ['IoT Device', 'Security Camera'],
            'Philips': ['IoT Device', 'Smart Light']
        }

    def start_real_time_processing(self, port: int = 5000):
        """Start Flask webhook server for real-time processing"""
        self.logger.info(f"Starting Meraki webhook handler on port {port}")
        self.webhook_handler.start_server(port=port)

    def batch_classify_network(self, network_id: str, enhance_existing: bool = True) -> List[EnhancedClassificationResult]:
        """Batch classify all devices in a Meraki network"""
        try:
            self.logger.info(f"Starting batch classification for network {network_id}")
            
            # Get all clients from Meraki
            clients = self.meraki_client.get_network_clients(network_id)
            self.logger.info(f"Found {len(clients)} clients in network")
            
            classifications = []
            for client in clients:
                try:
                    # Skip clients without MAC addresses
                    if not client.get('mac'):
                        continue
                    
                    # Convert Meraki client data to DHCP format
                    dhcp_entry = self.convert_meraki_client_to_dhcp(client)
                    
                    # Classify using existing system
                    result = self.device_analyzer._classify_device(
                        client['mac'], [dhcp_entry]
                    )
                    
                    # Enhance with Meraki-specific data
                    enhanced_result = self.enhance_with_meraki_data(result, client, network_id)
                    classifications.append(enhanced_result)
                    
                    # Apply device policy if high confidence and enabled
                    if (enhance_existing and 
                        enhanced_result.overall_confidence in ['high', 'medium'] and
                        self.config.get('auto_apply_policies', False)):
                        self.apply_device_policy(network_id, client, enhanced_result)
                        
                except Exception as e:
                    self.logger.error(f"Error classifying client {client.get('mac', 'unknown')}: {e}")
                    continue
            
            self.meraki_classifications += len(classifications)
            self.logger.info(f"Completed batch classification: {len(classifications)} devices processed")
            
            return classifications
            
        except Exception as e:
            self.logger.error(f"Error in batch classification: {e}")
            return []

    def convert_meraki_client_to_dhcp(self, meraki_client: Dict) -> DHCPLogEntry:
        """Convert Meraki client data to DHCP format for existing system"""
        return DHCPLogEntry(
            mac_address=meraki_client.get('mac', ''),
            ip_address=meraki_client.get('ip', ''),
            hostname=meraki_client.get('description') or meraki_client.get('hostname'),
            message_type='ACK',
            timestamp=datetime.now(),
            vendor_class=None,
            user_class=None,
            dhcp_options={}
        )

    def enhance_with_meraki_data(self, classification_result, meraki_client: Dict, 
                               network_id: str) -> EnhancedClassificationResult:
        """Enhance classification with Meraki network data"""
        
        # Analyze usage patterns
        usage_patterns = self.analyze_usage_patterns(meraki_client)
        
        # Create enhanced result
        enhanced_result = EnhancedClassificationResult(
            mac_address=meraki_client.get('mac', ''),
            device_type=classification_result.device_type,
            overall_confidence=classification_result.overall_confidence,
            classification_method=classification_result.classification_method,
            fingerbank_data={
                'device_type': classification_result.device_type,
                'confidence': classification_result.overall_confidence,
                'method': classification_result.classification_method
            },
            meraki_data={
                'ssid': meraki_client.get('ssid'),
                'vlan': meraki_client.get('vlan'),
                'usage_data': meraki_client.get('usage', {}),
                'first_seen': meraki_client.get('firstSeen'),
                'last_seen': meraki_client.get('lastSeen'),
                'manufacturer': meraki_client.get('manufacturer'),
                'os': meraki_client.get('os'),
                'device_type_hint': meraki_client.get('deviceTypePrediction'),
                'network_id': network_id,
                'client_id': meraki_client.get('id'),
                'description': meraki_client.get('description')
            },
            usage_patterns=usage_patterns,
            timestamp=datetime.now().isoformat()
        )

        # Cross-validate with Meraki's device type prediction
        meraki_prediction = meraki_client.get('deviceTypePrediction')
        if meraki_prediction and meraki_prediction != classification_result.device_type:
            
            # Apply conflict resolution logic
            resolved_type, resolution_method = self.resolve_classification_conflict(
                classification_result.device_type,
                meraki_prediction,
                classification_result.overall_confidence,
                meraki_client.get('manufacturer', ''),
                usage_patterns
            )

            if resolved_type != classification_result.device_type:
                enhanced_result.device_type = resolved_type
                enhanced_result.classification_method += f"_meraki_enhanced_{resolution_method}"
                enhanced_result.conflict_resolution = (
                    f"Resolved conflict between {classification_result.device_type} "
                    f"and {meraki_prediction} using {resolution_method}"
                )
                self.accuracy_improvements += 1
                self.conflict_resolutions += 1

        # Apply additional accuracy enhancements
        accuracy_enhancement = self.apply_accuracy_enhancements(enhanced_result)
        if accuracy_enhancement:
            enhanced_result.accuracy_enhancement = accuracy_enhancement

        return enhanced_result

    def resolve_classification_conflict(self, fingerbank_type: str, meraki_type: str, 
                                      confidence: str, manufacturer: str,
                                      usage_patterns: Dict) -> Tuple[str, str]:
        """Resolve conflicts between classification sources"""
        
        # High confidence Fingerbank results take precedence
        if confidence == 'high':
            return fingerbank_type, 'high_confidence_fingerbank'

        # Cross-reference with manufacturer data
        if manufacturer in self.manufacturer_hints:
            valid_types = self.manufacturer_hints[manufacturer]
            
            if meraki_type in valid_types and fingerbank_type not in valid_types:
                return meraki_type, 'manufacturer_validation'
            elif fingerbank_type in valid_types:
                return fingerbank_type, 'manufacturer_confirmed'

        # Use usage patterns for additional validation
        if usage_patterns.get('device_confidence') == 'high':
            usage_suggested_type = usage_patterns.get('suggested_device_type')
            if usage_suggested_type:
                if usage_suggested_type == meraki_type:
                    return meraki_type, 'usage_pattern_validation'
                elif usage_suggested_type == fingerbank_type:
                    return fingerbank_type, 'usage_pattern_confirmed'

        # Default to Fingerbank for medium confidence
        if confidence == 'medium':
            return fingerbank_type, 'medium_confidence_default'
        
        # Low confidence - prefer Meraki prediction if available
        if meraki_type:
            return meraki_type, 'low_confidence_meraki_preferred'
            
        return fingerbank_type, 'fallback_fingerbank'

    def analyze_usage_patterns(self, meraki_client: Dict) -> Dict:
        """Analyze network usage patterns for device classification"""
        usage = meraki_client.get('usage', {})
        
        patterns = {
            'bandwidth_profile': 'unknown',
            'traffic_pattern': 'unknown',
            'device_confidence': 'low',
            'suggested_device_type': None
        }

        total_usage = usage.get('sent', 0) + usage.get('recv', 0)
        
        # High bandwidth suggests streaming/gaming devices
        if total_usage > 1000000000:  # >1GB
            patterns['bandwidth_profile'] = 'high'
            patterns['traffic_pattern'] = 'heavy_consumer'
            
            # Check if gaming console or streaming device fits
            potential_types = ['Gaming Console', 'Smart TV', 'Computer']
            patterns['suggested_device_type'] = 'Gaming Console'  # Most likely for high usage
            patterns['device_confidence'] = 'medium'

        # Medium bandwidth suggests regular devices
        elif total_usage > 100000000:  # >100MB
            patterns['bandwidth_profile'] = 'medium'
            patterns['traffic_pattern'] = 'regular_consumer'
            potential_types = ['Phone', 'Tablet', 'Computer']
            patterns['suggested_device_type'] = 'Phone'
            patterns['device_confidence'] = 'low'

        # Low bandwidth suggests IoT devices
        elif total_usage < 10000000:  # <10MB
            patterns['bandwidth_profile'] = 'low'
            patterns['traffic_pattern'] = 'minimal_consumer'
            patterns['suggested_device_type'] = 'IoT Device'
            patterns['device_confidence'] = 'medium'

        # Analyze connection patterns
        first_seen = meraki_client.get('firstSeen')
        last_seen = meraki_client.get('lastSeen')
        
        if first_seen and last_seen:
            try:
                first_time = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                last_time = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                connection_duration = last_time - first_time
                
                # Long-term connected devices (>7 days) likely IoT or infrastructure
                if connection_duration.days > 7:
                    patterns['connection_pattern'] = 'persistent'
                    if patterns['bandwidth_profile'] == 'low':
                        patterns['suggested_device_type'] = 'IoT Device'
                        patterns['device_confidence'] = 'high'
                        
                # Short-term connections likely mobile devices
                elif connection_duration.days < 1:
                    patterns['connection_pattern'] = 'transient'
                    if patterns['bandwidth_profile'] in ['medium', 'high']:
                        patterns['suggested_device_type'] = 'Phone'
                        patterns['device_confidence'] = 'medium'
                        
            except Exception as e:
                self.logger.debug(f"Error parsing connection times: {e}")

        return patterns

    def apply_accuracy_enhancements(self, result: EnhancedClassificationResult) -> Optional[str]:
        """Apply additional accuracy enhancement techniques"""
        enhancements = []
        
        # SSID-based enhancement
        ssid = result.meraki_data.get('ssid', '').lower()
        if 'guest' in ssid and result.device_type not in ['Phone', 'Tablet']:
            enhancements.append("guest_network_mobile_bias")
            
        # VLAN-based enhancement
        vlan = result.meraki_data.get('vlan')
        if vlan:
            # IoT VLANs typically in specific ranges
            if isinstance(vlan, int) and (100 <= vlan <= 199):
                if result.device_type != 'IoT Device':
                    enhancements.append("iot_vlan_detection")
                    
        # Time-based patterns
        first_seen = result.meraki_data.get('first_seen')
        if first_seen:
            try:
                seen_time = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                if seen_time.hour < 6 or seen_time.hour > 22:  # Off-hours connection
                    if result.device_type not in ['IoT Device', 'Security Camera']:
                        enhancements.append("off_hours_iot_bias")
            except Exception:
                pass
                
        return ", ".join(enhancements) if enhancements else None

    def apply_device_policy(self, network_id: str, client: Dict, 
                          result: EnhancedClassificationResult) -> bool:
        """Apply device policy based on classification"""
        try:
            # Apply classification to Meraki
            success = self.meraki_client.apply_device_classification(
                network_id, 
                client['mac'], 
                result.device_type, 
                result.overall_confidence
            )
            
            if success:
                self.logger.info(f"Applied Meraki policy for {client['mac']}: {result.device_type}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error applying device policy: {e}")
            return False

    def get_classification_stats(self) -> Dict:
        """Get comprehensive classification statistics"""
        return {
            'total_meraki_classifications': self.meraki_classifications,
            'accuracy_improvements': self.accuracy_improvements,
            'conflict_resolutions': self.conflict_resolutions,
            'improvement_rate': (
                self.accuracy_improvements / max(self.meraki_classifications, 1) * 100
            ),
            'webhook_stats': {
                'processed_events': self.webhook_handler.processed_events,
                'recent_classifications': len(self.webhook_handler.classification_results)
            }
        }

    def export_enhanced_results(self, results: List[EnhancedClassificationResult], 
                              filename: str = None) -> str:
        """Export enhanced classification results to JSON"""
        if not filename:
            filename = f"meraki_enhanced_classification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
        # Convert results to serializable format
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'total_classifications': len(results),
            'statistics': self.get_classification_stats(),
            'results': [asdict(result) for result in results]
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
            
        self.logger.info(f"Exported {len(results)} enhanced classifications to {filename}")
        return filename