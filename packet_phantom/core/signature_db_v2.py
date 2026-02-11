"""
Signature Database V2 for Behavioral OS Fingerprinting
========================================================

This module provides the SignatureDatabaseV2 class for managing v2 format
OS fingerprinting signatures. It supports saving, loading, and converting
signatures between formats.

Author: Dr. Packet (Network Security Research Division)
Version: 2.0.0
"""

from __future__ import annotations

import json
import os
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


# Validation constants
VALID_TTL_MIN = 1
VALID_TTL_MAX = 255
VALID_WINDOW_SIZE_MIN = 1
VALID_WINDOW_SIZE_MAX = 65535
VALID_CONFIDENCE_MIN = 0.0
VALID_CONFIDENCE_MAX = 1.0
FORMAT_VERSION = "2.0.0"


class SignatureValidationError(Exception):
    """Raised when signature validation fails."""
    pass


class SignatureNotFoundError(Exception):
    """Raised when a signature cannot be found."""
    pass


class SignatureDatabaseV2:
    """
    Database manager for v2 format behavioral OS fingerprinting signatures.
    
    This class provides methods for:
    - Saving signatures to the database
    - Loading signatures from the database
    - Listing all available signatures
    - Converting legacy signatures to v2 format
    - Validating signatures against the schema
    
    Attributes:
        db_path: Path to the signature database directory
        signatures: Dictionary of loaded signatures
    """
    
    # Congestion control algorithm mappings
    CC_ALGORITHMS = {
        "reno": "reno",
        "cubic": "cubic",
        "bbr": "bbr",
        "vegas": "vegas",
        "westwood": "westwood",
        "unknown": "unknown"
    }
    
    # IP ID pattern mappings
    IPID_PATTERNS = {
        "sequential": "sequential",
        "random": "random",
        "incrementing": "incrementing",
        "zero": "zero",
        "broken": "broken"
    }
    
    # Environment types
    ENVIRONMENTS = ["physical", "virtual", "container", "cloud"]
    
    def __init__(self, db_path: str = "signatures/v2/"):
        """
        Initialize the signature database.
        
        Args:
            db_path: Path to the directory containing v2 signatures.
                    Defaults to "signatures/v2/"
        """
        self.db_path = Path(db_path)
        self.signatures: Dict[str, Dict[str, Any]] = {}
        self._schema_cache: Optional[Dict[str, Any]] = None
        
    @property
    def schema_path(self) -> Path:
        """Get the path to the v2 schema file."""
        return Path(__file__).parent.parent.parent / "signatures" / "v2_schema.json"
    
    @property
    def legacy_signatures_path(self) -> Path:
        """Get the path to the legacy signatures (from os_fingerprint.py)."""
        return Path(__file__).parent / "os_fingerprint.py"
    
    def _load_schema(self) -> Dict[str, Any]:
        """Load the v2 schema definition."""
        if self._schema_cache is None:
            schema_file = self.schema_path
            if schema_file.exists():
                with open(schema_file, 'r') as f:
                    self._schema_cache = json.load(f)
            else:
                # Fallback to inline schema definition
                self._schema_cache = self._get_inline_schema()
        return self._schema_cache
    
    def _get_inline_schema(self) -> Dict[str, Any]:
        """Get inline schema definition as fallback."""
        return {
            "format_version": FORMAT_VERSION,
            "dimensions": {
                "D1": "Static TCP fingerprinting (TTL, window size, options)",
                "D2": "TCP behavior under load",
                "D3": "Temporal analysis (jitter, response speed)",
                "D4": "ICMP response patterns",
                "D5": "Error handling patterns",
                "D6": "UDP behavior",
                "D7": "TLS/SSL handshake characteristics",
                "D8": "Hardware/virtualization detection"
            }
        }
    
    def _validate_ttl(self, ttl: int) -> bool:
        """Validate TTL value."""
        return VALID_TTL_MIN <= ttl <= VALID_TTL_MAX
    
    def _validate_window_size(self, window_size: int) -> bool:
        """Validate window size value."""
        return VALID_WINDOW_SIZE_MIN <= window_size <= VALID_WINDOW_SIZE_MAX
    
    def _validate_confidence(self, confidence: float) -> bool:
        """Validate confidence value."""
        return VALID_CONFIDENCE_MIN <= confidence <= VALID_CONFIDENCE_MAX
    
    def _validate_timestamp(self, timestamp: str) -> bool:
        """Validate ISO8601 timestamp format."""
        try:
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return True
        except (ValueError, AttributeError):
            return False
    
    def validate_signature(self, signature: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate a signature against the v2 schema.
        
        Args:
            signature: The signature dictionary to validate.
            
        Returns:
            Tuple of (is_valid: bool, errors: List[str])
        """
        errors = []
        
        # Check format_version
        if signature.get('format_version') != FORMAT_VERSION:
            errors.append(f"Invalid format_version: expected '{FORMAT_VERSION}', got '{signature.get('format_version')}'")
        
        # Get structure (v2 format has nested structure)
        structure = signature.get('structure', {})
        
        # Validate metadata (v2 format has metadata nested in structure)
        metadata = structure.get('metadata', signature.get('metadata', {}))
        if not metadata:
            errors.append("Missing required 'structure.metadata' field")
        else:
            if not metadata.get('target_os'):
                errors.append("Missing required 'structure.metadata.target_os' field")
            if not metadata.get('version'):
                errors.append("Missing required 'structure.metadata.version' field")
            
            confidence = metadata.get('confidence')
            if confidence is not None:
                if not self._validate_confidence(confidence):
                    errors.append(f"Invalid confidence: {confidence} (must be {VALID_CONFIDENCE_MIN}-{VALID_CONFIDENCE_MAX})")
            
            probe_timestamp = metadata.get('probe_timestamp')
            if probe_timestamp:
                if not self._validate_timestamp(probe_timestamp):
                    errors.append(f"Invalid probe_timestamp format: {probe_timestamp} (must be ISO8601)")
            
            environment = metadata.get('environment')
            if environment and environment not in self.ENVIRONMENTS:
                errors.append(f"Invalid environment: {environment} (must be one of {self.ENVIRONMENTS})")
        
        # Validate probe_responses (v2 format has probe_responses nested in structure)
        probe_responses = structure.get('probe_responses', signature.get('probe_responses', {}))
        tcp_syn_ack = probe_responses.get('tcp_syn_ack', {})
        if tcp_syn_ack:
            ttl = tcp_syn_ack.get('ttl')
            if ttl and not self._validate_ttl(ttl):
                errors.append(f"Invalid ttl in tcp_syn_ack: {ttl} (must be {VALID_TTL_MIN}-{VALID_TTL_MAX})")
            
            window_size = tcp_syn_ack.get('window_size')
            if window_size and not self._validate_window_size(window_size):
                errors.append(f"Invalid window_size in tcp_syn_ack: {window_size} (must be {VALID_WINDOW_SIZE_MIN}-{VALID_WINDOW_SIZE_MAX})")
        
        # Validate temporal (v2 format has temporal nested in structure)
        temporal = structure.get('temporal', signature.get('temporal', {}))
        if temporal:
            consistency_score = temporal.get('consistency_score')
            if consistency_score is not None:
                if not self._validate_confidence(consistency_score):
                    errors.append(f"Invalid consistency_score: {consistency_score} (must be {VALID_CONFIDENCE_MIN}-{VALID_CONFIDENCE_MAX})")
        
        return len(errors) == 0, errors
    
    def save(self, signature_id: str, data: Dict[str, Any]) -> bool:
        """
        Save a signature to the database.
        
        Args:
            signature_id: Unique identifier for the signature.
            data: Signature data dictionary in v2 format.
            
        Returns:
            True if saved successfully, False otherwise.
        """
        # Validate signature
        is_valid, errors = self.validate_signature(data)
        if not is_valid:
            logger.error(f"Signature validation failed for '{signature_id}': {errors}")
            raise SignatureValidationError(f"Validation failed: {errors}")
        
        # Ensure format_version is set
        data['format_version'] = FORMAT_VERSION
        
        # Create database directory if it doesn't exist
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # Generate filename from signature_id
        filename = self._generate_filename(signature_id)
        file_path = self.db_path / filename
        
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Update in-memory cache
            self.signatures[signature_id] = data
            
            logger.info(f"Saved signature '{signature_id}' to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save signature '{signature_id}': {e}")
            return False
    
    def load(self, signature_id: str) -> Dict[str, Any]:
        """
        Load a signature from the database.
        
        Args:
            signature_id: The signature ID to load.
            
        Returns:
            The signature data dictionary.
            
        Raises:
            SignatureNotFoundError: If the signature is not found.
        """
        # Check in-memory cache first
        if signature_id in self.signatures:
            return self.signatures[signature_id]
        
        # Search for the signature file
        filename = self._generate_filename(signature_id)
        file_path = self.db_path / filename
        
        if not file_path.exists():
            # Try searching all files in the directory
            for sig_file in self.db_path.glob("*.json"):
                with open(sig_file, 'r') as f:
                    sig_data = json.load(f)
                    if sig_data.get('metadata', {}).get('target_os') == signature_id:
                        self.signatures[signature_id] = sig_data
                        return sig_data
            
            raise SignatureNotFoundError(f"Signature '{signature_id}' not found in {self.db_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Validate loaded signature
        is_valid, errors = self.validate_signature(data)
        if not is_valid:
            logger.warning(f"Loaded signature '{signature_id}' has validation issues: {errors}")
        
        self.signatures[signature_id] = data
        return data
    
    def load_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Load all signatures from the database.
        
        Returns:
            Dictionary mapping signature IDs to their data.
        """
        self.signatures.clear()
        
        if not self.db_path.exists():
            logger.warning(f"Signature database directory {self.db_path} does not exist")
            return {}
        
        for file_path in self.db_path.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    signature_id = data.get('metadata', {}).get('target_os', file_path.stem)
                    self.signatures[signature_id] = data
            except Exception as e:
                logger.error(f"Failed to load signature from {file_path}: {e}")
        
        logger.info(f"Loaded {len(self.signatures)} signatures from {self.db_path}")
        return self.signatures
    
    def list_signatures(self) -> List[str]:
        """
        List all signature IDs in the database.
        
        Returns:
            List of signature IDs.
        """
        # Ensure all signatures are loaded
        if not self.signatures:
            self.load_all()
        
        return list(self.signatures.keys())
    
    def delete(self, signature_id: str) -> bool:
        """
        Delete a signature from the database.
        
        Args:
            signature_id: The signature ID to delete.
            
        Returns:
            True if deleted successfully, False otherwise.
        """
        if signature_id not in self.signatures:
            # Try to find and delete the file
            filename = self._generate_filename(signature_id)
            file_path = self.db_path / filename
            
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Deleted signature file {file_path}")
                return True
            
            return False
        
        # Remove from in-memory cache
        filename = self._generate_filename(signature_id)
        file_path = self.db_path / filename
        
        if file_path.exists():
            file_path.unlink()
        
        del self.signatures[signature_id]
        logger.info(f"Deleted signature '{signature_id}'")
        return True
    
    def _generate_filename(self, signature_id: str) -> str:
        """Generate a filename from a signature ID."""
        # Sanitize filename
        safe_id = re.sub(r'[^\w\-]', '_', signature_id)
        return f"{safe_id}.json"
    
    def convert_legacy_signature(
        self, 
        legacy_name: str, 
        legacy_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Convert a legacy signature (from old format or Nmap-style) to v2 format.
        
        Args:
            legacy_name: Name of the legacy signature.
            legacy_data: Legacy signature data dictionary.
            
        Returns:
            Converted v2 format signature.
        """
        # Extract class info
        class_info = legacy_data.get('class', {})
        vendor = class_info.get('vendor', 'Unknown')
        os_family = class_info.get('family', 'Unknown')
        version = class_info.get('version', 'Unknown')
        device_type = class_info.get('type', 'general-purpose')
        
        # Extract TCP info
        tcp_info = legacy_data.get('tcp', {})
        options = []
        options_mask = tcp_info.get('options_mask', '')
        
        # Map options mask to actual option names
        if 'M' in options_mask:
            options.append("MSS")
        if 'W' in options_mask:
            options.append("WScale")
        if 'S' in options_mask:
            options.append("SACK")
        if 'T' in options_mask:
            options.append("Timestamp")
        
        window_sizes = tcp_info.get('window_size', [65535])
        window_size = window_sizes[0] if window_sizes else 65535
        mss_values = tcp_info.get('mss_values', [])
        mss = mss_values[0] if mss_values else None
        wscale_values = tcp_info.get('wscale_values', [])
        wscale = wscale_values[0] if wscale_values else None
        
        # Extract IP info
        ip_info = legacy_data.get('ip', {})
        ttl = ip_info.get('ttl', 64)
        df_flag = ip_info.get('df_flag', True)
        
        # Extract temporal info
        temporal_info = legacy_data.get('temporal', {})
        response_speed = temporal_info.get('response_speed', 'normal')
        scheduler_behavior = temporal_info.get('scheduler_behavior', 'interrupt_driven')
        
        # Extract congestion info
        congestion_info = legacy_data.get('congestion', {})
        algorithm = congestion_info.get('algorithm', 'unknown')
        
        # Extract hardware info
        hardware_info = legacy_data.get('hardware', {})
        is_virtual = hardware_info.get('virtualization', False)
        hw_type = hardware_info.get('type', 'physical')
        provider = hardware_info.get('provider', None)
        
        # Determine environment
        if hw_type == 'virtual' or is_virtual:
            environment = 'virtual'
        elif hw_type == 'cloud' or provider:
            environment = 'cloud'
        else:
            environment = 'physical'
        
        # Determine response time estimate based on response_speed
        response_time_map = {
            'immediate': 0.01,
            'fast': 0.15,
            'normal': 0.5,
            'slow': 1.0,
            'very_slow': 5.0
        }
        response_time_ms = response_time_map.get(response_speed, 0.5)
        
        # Extract quirks
        quirks = legacy_data.get('quirks', [])
        
        # Build v2 format signature
        v2_signature = {
            "format_version": FORMAT_VERSION,
            "dimensions": {
                "D1": "Static TCP fingerprinting (TTL, window size, options)",
                "D2": "TCP behavior under load",
                "D3": "Temporal analysis (jitter, response speed)",
                "D4": "ICMP response patterns",
                "D5": "Error handling patterns",
                "D6": "UDP behavior",
                "D7": "TLS/SSL handshake characteristics",
                "D8": "Hardware/virtualization detection"
            },
            "structure": {
                "probe_responses": {
                    "tcp_syn_ack": {
                        "ttl": ttl,
                        "window_size": window_size,
                        "options": options,
                        "df_bit": df_flag,
                        "mss": mss,
                        "wscale": wscale,
                        "sack_permitted": tcp_info.get('sack_permitted', False),
                        "timestamp": tcp_info.get('timestamp', False)
                    }
                },
                "temporal": {
                    "response_time_ms": response_time_ms,
                    "jitter_ms": 0.05,
                    "consistency_score": 0.9,
                    "response_speed": response_speed,
                    "scheduler_behavior": scheduler_behavior
                },
                "metadata": {
                    "target_os": os_family,
                    "version": version,
                    "confidence": 0.85,
                    "probe_timestamp": datetime.now(timezone.utc).isoformat(),
                    "environment": environment,
                    "vendor": vendor,
                    "family": os_family,
                    "device_type": device_type
                },
                "behavioral": {
                    "congestion": {
                        "algorithm": algorithm,
                        "window_scaling": congestion_info.get('window_scaling', True)
                    },
                    "ip": {
                        "ttl": ttl,
                        "df_flag": df_flag,
                        "ip_id_pattern": ip_info.get('ip_id_pattern', 'incrementing')
                    },
                    "hardware": {
                        "virtualization": is_virtual,
                        "type": hw_type,
                        "provider": provider
                    },
                    "quirks": quirks
                }
            }
        }
        
        logger.info(f"Converted legacy signature '{legacy_name}' to v2 format")
        return v2_signature
    
    def import_legacy_database(self, legacy_signatures: Dict[str, Dict[str, Any]]) -> int:
        """
        Import multiple legacy signatures and convert them to v2 format.
        
        Args:
            legacy_signatures: Dictionary of legacy signatures.
            
        Returns:
            Number of successfully imported signatures.
        """
        imported = 0
        for name, data in legacy_signatures.items():
            try:
                v2_sig = self.convert_legacy_signature(name, data)
                v2_id = f"{v2_sig['structure']['metadata']['vendor']}_{v2_sig['structure']['metadata']['target_os']}_{v2_sig['structure']['metadata']['version']}"
                if self.save(v2_id, v2_sig):
                    imported += 1
            except Exception as e:
                logger.error(f"Failed to import legacy signature '{name}': {e}")
        
        return imported
    
    def export_to_legacy_format(self, signature_id: str) -> Dict[str, Any]:
        """
        Export a v2 signature to legacy format for backward compatibility.
        
        Args:
            signature_id: The signature ID to export.
            
        Returns:
            Legacy format signature dictionary.
        """
        v2_sig = self.load(signature_id)
        
        structure = v2_sig.get('structure', {})
        metadata = structure.get('metadata', {})
        tcp_syn_ack = structure.get('probe_responses', {}).get('tcp_syn_ack', {})
        behavioral = structure.get('behavioral', {})
        ip = behavioral.get('ip', {})
        congestion = behavioral.get('congestion', {})
        
        # Build options mask
        options = tcp_syn_ack.get('options', [])
        options_mask = ''
        if 'MSS' in options:
            options_mask += 'M'
        if 'WScale' in options:
            options_mask += 'W'
        if 'SACK' in options:
            options_mask += 'S'
        if 'Timestamp' in options:
            options_mask += 'T'
        
        legacy_sig = {
            'class': {
                'vendor': metadata.get('vendor', 'Unknown'),
                'family': metadata.get('family', 'Unknown'),
                'type': metadata.get('device_type', 'general-purpose'),
                'version': metadata.get('version', 'Unknown')
            },
            'tcp': {
                'window_size': [tcp_syn_ack.get('window_size', 65535)],
                'options_mask': options_mask,
                'mss_values': [tcp_syn_ack.get('mss')] if tcp_syn_ack.get('mss') else [],
                'wscale_values': [tcp_syn_ack.get('wscale')] if tcp_syn_ack.get('wscale') else [],
                'sack_permitted': tcp_syn_ack.get('sack_permitted', False),
                'timestamp': tcp_syn_ack.get('timestamp', False)
            },
            'ip': {
                'ttl': ip.get('ttl', 64),
                'df_flag': ip.get('df_flag', True),
                'ip_id_pattern': ip.get('ip_id_pattern', 'incrementing')
            },
            'temporal': {
                'response_speed': structure.get('temporal', {}).get('response_speed', 'normal'),
                'scheduler_behavior': structure.get('temporal', {}).get('scheduler_behavior', 'hybrid')
            },
            'congestion': {
                'algorithm': congestion.get('algorithm', 'unknown'),
                'window_scaling': congestion.get('window_scaling', True)
            }
        }
        
        return legacy_sig
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the signature database.
        
        Returns:
            Dictionary containing database statistics.
        """
        if not self.signatures:
            self.load_all()
        
        # Count by vendor
        vendors = {}
        device_types = {}
        environments = {}
        
        for sig in self.signatures.values():
            metadata = sig.get('structure', {}).get('metadata', {})
            vendor = metadata.get('vendor', 'Unknown')
            device_type = metadata.get('device_type', 'unknown')
            environment = metadata.get('environment', 'unknown')
            
            vendors[vendor] = vendors.get(vendor, 0) + 1
            device_types[device_type] = device_types.get(device_type, 0) + 1
            environments[environment] = environments.get(environment, 0) + 1
        
        return {
            "total_signatures": len(self.signatures),
            "by_vendor": vendors,
            "by_device_type": device_types,
            "by_environment": environments,
            "database_path": str(self.db_path)
        }
    
    def search(self, query: str) -> List[str]:
        """
        Search for signatures by query string.
        
        Args:
            query: Search query string.
            
        Returns:
            List of matching signature IDs.
        """
        if not self.signatures:
            self.load_all()
        
        query_lower = query.lower()
        results = []
        
        for sig_id, sig_data in self.signatures.items():
            metadata = sig_data.get('structure', {}).get('metadata', {})
            
            # Search in various fields
            searchable_fields = [
                metadata.get('target_os', ''),
                metadata.get('version', ''),
                metadata.get('vendor', ''),
                metadata.get('family', ''),
                metadata.get('device_type', '')
            ]
            
            for field in searchable_fields:
                if query_lower in field.lower():
                    results.append(sig_id)
                    break
        
        return results
    
    def get_schema(self) -> Dict[str, Any]:
        """Get the v2 schema definition."""
        return self._load_schema()


def convert_nmap_style_to_v2(nmap_sig: Dict[str, Any], signature_id: str) -> Dict[str, Any]:
    """
    Convert an Nmap-style signature to v2 format.
    
    Args:
        nmap_sig: Nmap-style signature dictionary.
        signature_id: Unique identifier for the signature.
        
    Returns:
        Converted v2 format signature.
    """
    # Extract fields from Nmap-style signature
    # Nmap signatures typically have fields like:
    # - osclass: vendor, type, osfamily, osgen
    # - ports: port used for fingerprinting
    # - seq: sequence characteristics
    # - tcp: TCP characteristics
    
    osclass = nmap_sig.get('osclass', {})
    tcp = nmap_sig.get('tcp', {})
    
    # Build v2 signature
    v2_sig = {
        "format_version": FORMAT_VERSION,
        "dimensions": {
            "D1": "Static TCP fingerprinting (TTL, window size, options)",
            "D2": "TCP behavior under load",
            "D3": "Temporal analysis (jitter, response speed)",
            "D4": "ICMP response patterns",
            "D5": "Error handling patterns",
            "D6": "UDP behavior",
            "D7": "TLS/SSL handshake characteristics",
            "D8": "Hardware/virtualization detection"
        },
        "structure": {
            "probe_responses": {
                "tcp_syn_ack": {
                    "ttl": tcp.get('ttl', 64),
                    "window_size": tcp.get('window', 65535),
                    "options": tcp.get('options', '').split(),
                    "df_bit": tcp.get('df', True)
                }
            },
            "temporal": {
                "response_time_ms": 0.5,
                "jitter_ms": 0.1,
                "consistency_score": 0.8,
                "response_speed": "normal",
                "scheduler_behavior": "hybrid"
            },
            "metadata": {
                "target_os": osclass.get('osfamily', 'Unknown'),
                "version": osclass.get('osgen', ''),
                "confidence": float(osclass.get('accuracy', 90)) / 100.0,
                "probe_timestamp": datetime.now(timezone.utc).isoformat(),
                "environment": "physical",
                "vendor": osclass.get('vendor', 'Unknown'),
                "family": osclass.get('osfamily', 'Unknown'),
                "device_type": osclass.get('type', 'general-purpose')
            },
            "behavioral": {
                "congestion": {
                    "algorithm": "unknown",
                    "window_scaling": True
                },
                "ip": {
                    "ttl": tcp.get('ttl', 64),
                    "df_flag": tcp.get('df', True),
                    "ip_id_pattern": "incrementing"
                },
                "quirks": []
            }
        }
    }
    
    return v2_sig


# Example usage and testing
if __name__ == "__main__":
    # Initialize database
    db = SignatureDatabaseV2()
    
    # Example v2 signature
    example_sig = {
        "format_version": FORMAT_VERSION,
        "dimensions": {
            "D1": "Static TCP fingerprinting (TTL, window size, options)",
            "D2": "TCP behavior under load",
            "D3": "Temporal analysis (jitter, response speed)",
            "D4": "ICMP response patterns",
            "D5": "Error handling patterns",
            "D6": "UDP behavior",
            "D7": "TLS/SSL handshake characteristics",
            "D8": "Hardware/virtualization detection"
        },
        "structure": {
            "probe_responses": {
                "tcp_syn_ack": {
                    "ttl": 64,
                    "window_size": 65535,
                    "options": ["MSS", "WScale", "SACK", "Timestamp"],
                    "df_bit": True,
                    "mss": 1460,
                    "wscale": 7,
                    "sack_permitted": True,
                    "timestamp": True
                }
            },
            "temporal": {
                "response_time_ms": 0.15,
                "jitter_ms": 0.02,
                "consistency_score": 0.95,
                "response_speed": "fast",
                "scheduler_behavior": "interrupt_driven"
            },
            "metadata": {
                "target_os": "Linux",
                "version": "5.x",
                "confidence": 0.95,
                "probe_timestamp": datetime.now(timezone.utc).isoformat(),
                "environment": "physical",
                "vendor": "Linux",
                "family": "Linux",
                "device_type": "general-purpose"
            },
            "behavioral": {
                "congestion": {
                    "algorithm": "cubic",
                    "window_scaling": True
                },
                "ip": {
                    "ttl": 64,
                    "df_flag": True,
                    "ip_id_pattern": "incrementing"
                },
                "quirks": ["TSval", "WSopt"]
            }
        }
    }
    
    # Save example signature
    db.save("Linux_5.x", example_sig)
    
    # Load and list signatures
    signatures = db.list_signatures()
    print(f"Available signatures: {signatures}")
    
    # Get statistics
    stats = db.get_statistics()
    print(f"Database statistics: {stats}")
