#!/usr/bin/env python3
"""
Configuration Manager for Meraki Integration
Handles API keys, settings, and environment configuration
"""

import os
import json
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from dotenv import load_dotenv

@dataclass
class MerakiConfig:
    """Meraki-specific configuration"""
    api_key: str
    webhook_secret: str
    network_ids: list
    default_network_id: str = ""
    auto_apply_policies: bool = False
    webhook_timeout: int = 30
    max_retries: int = 3

@dataclass
class FingerbankConfig:
    """Fingerbank API configuration"""
    api_key: str
    cache_ttl: int = 3600
    max_requests_per_hour: int = 1000

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: Optional[str] = None
    redis_url: Optional[str] = None
    enable_caching: bool = True
    cache_ttl: int = 3600

@dataclass
class ApplicationConfig:
    """Application-wide configuration"""
    log_level: str = "INFO"
    webhook_port: int = 5000
    batch_size: int = 100
    enable_metrics: bool = True
    metrics_port: int = 9090
    flask_secret_key: str = ""
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None

@dataclass
class ClassificationConfig:
    """Classification behavior configuration"""
    enable_conflict_resolution: bool = True
    enable_usage_analysis: bool = True
    confidence_threshold: str = "medium"
    auto_tag_devices: bool = False
    classification_cache_ttl: int = 3600

class ConfigManager:
    """Centralized configuration management"""
    
    def __init__(self, config_file: Optional[str] = None, env_file: Optional[str] = None):
        self.config_file = config_file or "config/meraki_config.json"
        self.env_file = env_file or ".env"
        self.logger = logging.getLogger(__name__)
        
        # Load environment variables
        if os.path.exists(self.env_file):
            load_dotenv(self.env_file)
        
        # Initialize configuration
        self.meraki_config = self._load_meraki_config()
        self.fingerbank_config = self._load_fingerbank_config()
        self.database_config = self._load_database_config()
        self.app_config = self._load_app_config()
        self.classification_config = self._load_classification_config()
        
        # Validate required configuration
        self._validate_config()

    def _load_meraki_config(self) -> MerakiConfig:
        """Load Meraki configuration from environment and config file"""
        network_ids_str = os.getenv('MERAKI_NETWORK_IDS', '')
        network_ids = [nid.strip() for nid in network_ids_str.split(',') if nid.strip()]
        
        return MerakiConfig(
            api_key=os.getenv('MERAKI_API_KEY', ''),
            webhook_secret=os.getenv('WEBHOOK_SECRET', ''),
            network_ids=network_ids,
            default_network_id=os.getenv('DEFAULT_NETWORK_ID', network_ids[0] if network_ids else ''),
            auto_apply_policies=os.getenv('AUTO_APPLY_POLICIES', 'false').lower() == 'true',
            webhook_timeout=int(os.getenv('WEBHOOK_TIMEOUT', '30')),
            max_retries=int(os.getenv('MAX_WEBHOOK_RETRIES', '3'))
        )

    def _load_fingerbank_config(self) -> FingerbankConfig:
        """Load Fingerbank configuration"""
        return FingerbankConfig(
            api_key=os.getenv('FINGERBANK_API_KEY', ''),
            cache_ttl=int(os.getenv('FINGERBANK_CACHE_TTL', '3600')),
            max_requests_per_hour=int(os.getenv('FINGERBANK_MAX_REQUESTS', '1000'))
        )

    def _load_database_config(self) -> DatabaseConfig:
        """Load database configuration"""
        return DatabaseConfig(
            url=os.getenv('DATABASE_URL'),
            redis_url=os.getenv('REDIS_URL'),
            enable_caching=os.getenv('ENABLE_CACHING', 'true').lower() == 'true',
            cache_ttl=int(os.getenv('CACHE_TTL', '3600'))
        )

    def _load_app_config(self) -> ApplicationConfig:
        """Load application configuration"""
        return ApplicationConfig(
            log_level=os.getenv('LOG_LEVEL', 'INFO'),
            webhook_port=int(os.getenv('WEBHOOK_PORT', '5000')),
            batch_size=int(os.getenv('BATCH_SIZE', '100')),
            enable_metrics=os.getenv('ENABLE_METRICS', 'true').lower() == 'true',
            metrics_port=int(os.getenv('METRICS_PORT', '9090')),
            flask_secret_key=os.getenv('FLASK_SECRET_KEY', os.urandom(32).hex()),
            ssl_cert_path=os.getenv('SSL_CERT_PATH'),
            ssl_key_path=os.getenv('SSL_KEY_PATH')
        )

    def _load_classification_config(self) -> ClassificationConfig:
        """Load classification configuration"""
        return ClassificationConfig(
            enable_conflict_resolution=os.getenv('ENABLE_CONFLICT_RESOLUTION', 'true').lower() == 'true',
            enable_usage_analysis=os.getenv('ENABLE_USAGE_ANALYSIS', 'true').lower() == 'true',
            confidence_threshold=os.getenv('CONFIDENCE_THRESHOLD', 'medium'),
            auto_tag_devices=os.getenv('AUTO_TAG_DEVICES', 'false').lower() == 'true',
            classification_cache_ttl=int(os.getenv('CLASSIFICATION_CACHE_TTL', '3600'))
        )

    def _validate_config(self):
        """Validate required configuration parameters"""
        errors = []
        
        # Check required Meraki configuration
        if not self.meraki_config.api_key:
            errors.append("MERAKI_API_KEY is required")
        
        if not self.meraki_config.webhook_secret:
            errors.append("WEBHOOK_SECRET is required")
            
        # Check required Fingerbank configuration
        if not self.fingerbank_config.api_key:
            errors.append("FINGERBANK_API_KEY is required")
            
        # Validate network IDs format
        for network_id in self.meraki_config.network_ids:
            if not network_id.startswith(('L_', 'N_')):
                errors.append(f"Invalid Meraki network ID format: {network_id}")
        
        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors)
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    def save_config(self, filename: Optional[str] = None):
        """Save current configuration to JSON file"""
        config_data = {
            'meraki': asdict(self.meraki_config),
            'fingerbank': asdict(self.fingerbank_config),
            'database': asdict(self.database_config),
            'application': asdict(self.app_config),
            'classification': asdict(self.classification_config)
        }
        
        # Remove sensitive data from saved config
        config_data['meraki']['api_key'] = '***REDACTED***'
        config_data['fingerbank']['api_key'] = '***REDACTED***'
        if config_data['database']['url']:
            config_data['database']['url'] = '***REDACTED***'
        
        config_file = filename or self.config_file
        Path(config_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        self.logger.info(f"Configuration saved to {config_file}")

    def load_config_file(self, filename: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        config_file = filename or self.config_file
        
        if not os.path.exists(config_file):
            return {}
        
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading config file {config_file}: {e}")
            return {}

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                },
                'detailed': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': self.app_config.log_level,
                    'formatter': 'standard',
                    'stream': 'ext://sys.stdout'
                },
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': self.app_config.log_level,
                    'formatter': 'detailed',
                    'filename': 'logs/meraki_classifier.log',
                    'maxBytes': 10485760,  # 10MB
                    'backupCount': 5
                }
            },
            'loggers': {
                '': {  # root logger
                    'handlers': ['console', 'file'],
                    'level': self.app_config.log_level,
                    'propagate': False
                }
            }
        }

    def get_flask_config(self) -> Dict[str, Any]:
        """Get Flask application configuration"""
        return {
            'SECRET_KEY': self.app_config.flask_secret_key,
            'DEBUG': self.app_config.log_level == 'DEBUG',
            'TESTING': False,
            'JSON_SORT_KEYS': False,
            'JSONIFY_PRETTYPRINT_REGULAR': True
        }

    def get_webhook_config(self) -> Dict[str, Any]:
        """Get webhook handler configuration"""
        return {
            'secret': self.meraki_config.webhook_secret,
            'timeout': self.meraki_config.webhook_timeout,
            'max_retries': self.meraki_config.max_retries,
            'port': self.app_config.webhook_port
        }

    def update_config(self, section: str, updates: Dict[str, Any]):
        """Update configuration section"""
        if section == 'meraki':
            for key, value in updates.items():
                if hasattr(self.meraki_config, key):
                    setattr(self.meraki_config, key, value)
        elif section == 'fingerbank':
            for key, value in updates.items():
                if hasattr(self.fingerbank_config, key):
                    setattr(self.fingerbank_config, key, value)
        elif section == 'database':
            for key, value in updates.items():
                if hasattr(self.database_config, key):
                    setattr(self.database_config, key, value)
        elif section == 'application':
            for key, value in updates.items():
                if hasattr(self.app_config, key):
                    setattr(self.app_config, key, value)
        elif section == 'classification':
            for key, value in updates.items():
                if hasattr(self.classification_config, key):
                    setattr(self.classification_config, key, value)
        else:
            raise ValueError(f"Unknown configuration section: {section}")

    def __str__(self) -> str:
        """String representation of configuration (without sensitive data)"""
        return (
            f"ConfigManager(\n"
            f"  Meraki Networks: {len(self.meraki_config.network_ids)}\n"
            f"  Default Network: {self.meraki_config.default_network_id}\n"
            f"  Webhook Port: {self.app_config.webhook_port}\n"
            f"  Log Level: {self.app_config.log_level}\n"
            f"  Auto Apply Policies: {self.meraki_config.auto_apply_policies}\n"
            f"  Classification Features: conflict_resolution={self.classification_config.enable_conflict_resolution}, "
            f"usage_analysis={self.classification_config.enable_usage_analysis}\n"
            f")"
        )