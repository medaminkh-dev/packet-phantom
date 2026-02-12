#!/usr/bin/env python3
"""
Configuration Manager for Packet Phantom 

Features:
- JSON configuration file
- Environment variable overrides
- Validation of all parameters
- Default values for security
- Integration with privilege dropping
"""

import json
import os
import tempfile
from typing import Dict, Any
from pathlib import Path


class ConfigSchema:
    """Configuration schema with validation"""
    
    SCHEMA = {
        "type": "object",
        "required": ["version", "general", "security", "network", "evasion"],
        "properties": {
            "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
            "general": {
                "type": "object",
                "required": ["default_port", "default_ttl", "max_packet_size"],
                "properties": {
                    "default_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "default_ttl": {"type": "integer", "minimum": 1, "maximum": 255},
                    "max_packet_size": {"type": "integer", "minimum": 64, "maximum": 65535},
                    "log_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]},
                    "output_format": {"type": "string", "enum": ["text", "json", "color"]}
                }
            },
            "security": {
                "type": "object",
                "required": ["privilege_drop_user", "resource_limits", "rate_limits", "input_validation"],
                "properties": {
                    "privilege_drop_user": {"type": "string"},
                    "resource_limits": {
                        "type": "object",
                        "required": ["max_memory_mb", "max_cpu_percent"],
                        "properties": {
                            "max_memory_mb": {"type": "integer", "minimum": 50, "maximum": 2000},
                            "max_cpu_percent": {"type": "integer", "minimum": 10, "maximum": 100}
                        }
                    },
                    "rate_limits": {
                        "type": "object",
                        "required": ["default_rate", "max_rate", "burst_size"],
                        "properties": {
                            "default_rate": {"type": "integer", "minimum": 1, "maximum": 100000},
                            "max_rate": {"type": "integer", "minimum": 1, "maximum": 1000000},
                            "burst_size": {"type": "integer", "minimum": 1, "maximum": 10000}
                        }
                    },
                    "input_validation": {
                        "type": "object",
                        "required": ["validate_ips", "validate_ports", "validate_payloads"],
                        "properties": {
                            "validate_ips": {"type": "boolean"},
                            "validate_ports": {"type": "boolean"},
                            "validate_payloads": {"type": "boolean"},
                            "max_payload_size": {"type": "integer", "minimum": 0, "maximum": 1400}
                        }
                    }
                }
            },
            "network": {
                "type": "object",
                "required": ["source_ip", "interface", "timeout"],
                "properties": {
                    "source_ip": {"type": "string", "format": "ipv4"},
                    "interface": {"type": "string"},
                    "timeout": {"type": "number", "minimum": 0.1, "maximum": 60.0},
                    "socket_buffer_size": {"type": "integer", "minimum": 1024, "maximum": 1048576}
                }
            },
            "evasion": {
                "type": "object",
                "required": ["enabled", "ttl_mode", "options_mode", "fragmentation"],
                "properties": {
                    "enabled": {"type": "boolean"},
                    "ttl_mode": {"type": "string", "enum": ["fixed", "random", "sequence"]},
                    "ttl_range": {
                        "type": "object",
                        "properties": {
                            "min": {"type": "integer", "minimum": 1},
                            "max": {"type": "integer", "maximum": 255}
                        }
                    },
                    "options_mode": {"type": "string", "enum": ["fixed", "random", "scrambled"]},
                    "fragmentation": {
                        "type": "object",
                        "properties": {
                            "enabled": {"type": "boolean"},
                            "mtu": {"type": "integer", "minimum": 576, "maximum": 1500}
                        }
                    },
                    "padding": {
                        "type": "object",
                        "properties": {
                            "enabled": {"type": "boolean"},
                            "min_size": {"type": "integer", "minimum": 0},
                            "max_size": {"type": "integer", "maximum": 1400}
                        }
                    }
                }
            },
            "output": {
                "type": "object",
                "required": ["pcap_enabled", "console_enabled"],
                "properties": {
                    "pcap_enabled": {"type": "boolean"},
                    "pcap_directory": {"type": "string"},
                    "console_enabled": {"type": "boolean"},
                    "colors_enabled": {"type": "boolean"}
                }
            }
        }
    }
    
    @staticmethod
    def get_defaults() -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "version": "1.0.0",
            "general": {
                "default_port": 80,
                "default_ttl": 64,
                "max_packet_size": 65535,
                "log_level": "INFO",
                "output_format": "color"
            },
            "security": {
                "privilege_drop_user": "nobody",
                "resource_limits": {
                    "max_memory_mb": 200,
                    "max_cpu_percent": 70
                },
                "rate_limits": {
                    "default_rate": 100,
                    "max_rate": 100000,
                    "burst_size": 1000
                },
                "input_validation": {
                    "validate_ips": True,
                    "validate_ports": True,
                    "validate_payloads": True,
                    "max_payload_size": 1400
                }
            },
            "network": {
                "source_ip": "auto",
                "interface": "auto",
                "timeout": 5.0,
                "socket_buffer_size": 65535
            },
            "evasion": {
                "enabled": False,
                "ttl_mode": "fixed",
                "ttl_range": {
                    "min": 56,
                    "max": 64
                },
                "options_mode": "fixed",
                "fragmentation": {
                    "enabled": False,
                    "mtu": 1500
                },
                "padding": {
                    "enabled": False,
                    "min_size": 0,
                    "max_size": 100
                }
            },
            "output": {
                "pcap_enabled": False,
                "pcap_directory": os.path.join(tempfile.gettempdir(), "pcaps"),
                "console_enabled": True,
                "colors_enabled": True
            }
        }


class ConfigManager:
    """
    Configuration manager with file, env, and validation support
    
    Usage:
        config = ConfigManager("phantom_config.json")
        config.load()
        port = config.get("general.default_port")
        config.set("evasion.enabled", True)
        config.save()
    """
    
    ENV_PREFIX = "PHANTOM_"
    
    def __init__(self, config_file: str = None):
        """
        Initialize configuration manager
        
        Args:
            config_file: Path to JSON config file (default: phantom_config.json)
        """
        self.config_file = config_file or "phantom_config.json"
        self.config = ConfigSchema.get_defaults()
        self.schema = ConfigSchema()
        self.modified = False
    
    def load(self, config_file: str = None) -> bool:
        """
        Load configuration from file
        
        Args:
            config_file: Optional path override
            
        Returns:
            True if loaded successfully, False otherwise
        """
        if config_file:
            self.config_file = config_file
        
        path = Path(self.config_file)
        
        if not path.exists():
            print(f"[!] Config file not found: {self.config_file}")
            print("[i] Using defaults")
            return False
        
        try:
            with open(path, 'r') as f:
                loaded_config = json.load(f)
            
            # Merge with defaults (deep merge)
            self._merge_config(self.config, loaded_config)
            
            # Validate
            if not self.validate():
                print("[!] Config validation failed, using defaults")
                self.config = ConfigSchema.get_defaults()
                return False
            
            print(f"[+] Config loaded: {self.config_file}")
            return True
            
        except json.JSONDecodeError as e:
            print(f"[!] Config parse error: {e}")
            return False
        except Exception as e:
            print(f"[!] Config load error: {e}")
            return False
    
    def save(self, config_file: str = None) -> bool:
        """
        Save configuration to file
        
        Args:
            config_file: Optional path override
            
        Returns:
            True if saved successfully
        """
        if config_file:
            self.config_file = config_file
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            print(f"[+] Config saved: {self.config_file}")
            self.modified = False
            return True
            
        except Exception as e:
            print(f"[!] Config save error: {e}")
            return False
    
    def _merge_config(self, base: Dict, override: Dict) -> None:
        """Deep merge configuration"""
        for key, value in override.items():
            if (key in base and 
                isinstance(base[key], dict) and 
                isinstance(value, dict)):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def validate(self) -> bool:
        """Validate configuration against schema"""
        # Basic validation - check required sections exist
        required_sections = ["version", "general", "security", "network", "evasion", "output"]
        
        for section in required_sections:
            if section not in self.config:
                print(f"[!] Missing section: {section}")
                return False
        
        # Validate types and ranges
        try:
            self._validate_section("", self.schema.SCHEMA["properties"], self.config)
        except (ValueError, KeyError) as e:
            print(f"[!] Validation error: {e}")
            return False
        
        return True
    
    def _validate_section(self, path: str, schema: Dict, data: Dict) -> None:
        """Recursively validate configuration"""
        for key, spec in schema.get("properties", {}).items():
            if key not in data:
                if spec.get("required", False):
                    raise ValueError(f"{path}{key}: Required field missing")
                continue
            
            value = data[key]
            
            # Type validation
            expected_type = spec.get("type")
            if expected_type:
                if expected_type == "string" and not isinstance(value, str):
                    raise ValueError(f"{path}{key}: Expected string")
                elif expected_type == "integer" and not isinstance(value, int):
                    raise ValueError(f"{path}{key}: Expected integer")
                elif expected_type == "number" and not isinstance(value, (int, float)):
                    raise ValueError(f"{path}{key}: Expected number")
                elif expected_type == "boolean" and not isinstance(value, bool):
                    raise ValueError(f"{path}{key}: Expected boolean")
                elif expected_type == "object" and not isinstance(value, dict):
                    raise ValueError(f"{path}{key}: Expected object")
            
            # Enum validation
            if "enum" in spec and value not in spec["enum"]:
                raise ValueError(f"{path}{key}: Must be one of {spec['enum']}")
            
            # Range validation
            if "minimum" in spec and value < spec["minimum"]:
                raise ValueError(f"{path}{key}: Must be >= {spec['minimum']}")
            if "maximum" in spec and value > spec["maximum"]:
                raise ValueError(f"{path}{key}: Must be <= {spec['maximum']}")
            
            # Nested validation
            if isinstance(value, dict) and "properties" in spec:
                self._validate_section(f"{path}{key}.", spec["properties"], value)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., "security.rate_limits.default_rate")
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        # Check environment variable first
        env_key = (self.ENV_PREFIX + key.upper().replace(".", "_"))
        env_value = os.environ.get(env_key)
        if env_value is not None:
            return self._parse_env_value(env_value)
        
        # Navigate through config
        keys = key.split(".")
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value"""
        # Boolean
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        
        # Integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Float
        try:
            return float(value)
        except ValueError:
            pass
        
        # String
        return value
    
    def set(self, key: str, value: Any) -> bool:
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key
            value: Value to set
            
        Returns:
            True if successful
        """
        keys = key.split(".")
        
        # Navigate to parent
        current = self.config
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        # Set value
        current[keys[-1]] = value
        self.modified = True
        return True
    
    def apply_security_settings(self) -> bool:
        """
        Apply security settings from config
        
        Returns:
            True if successful
        """
        try:
            from security.rate_limiter import TokenBucket
            
            # Configure default rate limiter
            default_rate = self.get("security.rate_limits.default_rate", 100)
            burst_size = self.get("security.rate_limits.burst_size", 1000)
            
            TokenBucket.default_rate = default_rate
            TokenBucket.default_burst = burst_size
            
            return True
        except ImportError:
            print("[!] Security modules not available")
            return False
    
    def export_for_cli(self) -> Dict:
        """Export configuration for CLI usage"""
        return {
            "default_port": self.get("general.default_port"),
            "default_ttl": self.get("general.default_ttl"),
            "max_packet_size": self.get("general.max_packet_size"),
            "default_rate": self.get("security.rate_limits.default_rate"),
            "evasion_enabled": self.get("evasion.enabled"),
            "pcap_enabled": self.get("output.pcap_enabled"),
            "pcap_directory": self.get("output.pcap_directory")
        }


def create_default_config(filename: str = "phantom_config.json") -> bool:
    """Create default configuration file"""
    config = ConfigManager(filename)
    config.config = ConfigSchema.get_defaults()
    return config.save()


if __name__ == "__main__":
    # Create default config
    create_default_config()
