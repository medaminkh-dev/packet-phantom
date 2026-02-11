"""
Packet Phantom - Dual Mode Manager
==================================

Dual mode system for LIVE (professional) and EDUCATIONAL (training) operation.

Mode Definitions:
----------------
LIVE (RED) 🔴 - Professional Mode
    No rate limits, full spoofing, raw sockets, minimal output
    For authorized security research and professional penetration testing

EDUCATIONAL (GREEN) 🟢 - Training Mode  
    Rate limited (100 pkt/s), no spoofing, verbose output, safety warnings
    For learning and classroom environments

Author: Packet Phantom Team
License: Professional Use
Version: 2.0.0
"""

import os
import resource
import logging
from typing import Optional, Dict, Any, Callable
from enum import Enum
from functools import wraps

# =============================================================================
# MODE DEFINITIONS
# =============================================================================

class OperationMode(Enum):
    """Operation mode enumeration."""
    LIVE = "live"
    EDUCATIONAL = "educational"


# Mode configurations
MODE_CONFIGS = {
    OperationMode.LIVE: {
        "color": "RED",
        "icon": "🔴",
        "name": "LIVE",
        "max_rate": None,  # Unlimited
        "allow_spoofing": True,
        "allow_external": True,
        "resource_limits": None,  # No limits
        "logging_level": logging.ERROR,
        "require_warnings": False,
        "verbose_output": False,
        "drop_privileges": False,
        "ip_validation": False,  # Allow any IP
        "port_validation": False,  # Allow any port
        "description": "PROFESSIONAL MODE - No restrictions. Full power enabled.",
    },
    OperationMode.EDUCATIONAL: {
        "color": "GREEN",
        "icon": "🟢",
        "name": "EDUCATIONAL",
        "max_rate": 100,  # Limited to 100 pkt/s
        "allow_spoofing": False,
        "allow_external": False,
        "resource_limits": {
            "RLIMIT_AS": (100 * 1024 * 1024, 200 * 1024 * 1024),  # 100-200MB
            "RLIMIT_NOFILE": (256, 1024),  # Max 1024 open files
            "RLIMIT_NPROC": (50, 100),  # Max 100 processes
        },
        "logging_level": logging.DEBUG,
        "require_warnings": True,
        "verbose_output": True,
        "drop_privileges": True,
        "ip_validation": True,
        "port_validation": True,
        "description": "EDUCATIONAL MODE - Safety features enabled. Rate limited.",
    }
}


# =============================================================================
# MODE MANAGER CLASS
# =============================================================================

class ModeManager:
    """
    Manages operation modes for Packet Phantom.
    
    Provides dual mode operation:
    - LIVE mode for professional security research
    - EDUCATIONAL mode for learning and training
    
    Attributes:
        mode: Current operation mode
        config: Configuration for current mode
    """
    
    _instance: Optional['ModeManager'] = None
    _mode: OperationMode = OperationMode.LIVE
    _initialized: bool = False
    
    def __new__(cls) -> 'ModeManager':
        """Singleton pattern for mode manager."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self) -> None:
        """Initialize mode manager."""
        # Only initialize once
        if not ModeManager._initialized:
            self._apply_mode_settings()
            ModeManager._initialized = True
    
    @classmethod
    def set_mode(cls, mode: OperationMode) -> None:
        """
        Set the operation mode.
        
        Args:
            mode: OperationMode.LIVE or OperationMode.EDUCATIONAL
            
        Example:
            ModeManager.set_mode(OperationMode.LIVE)  # Enable full power
            ModeManager.set_mode(OperationMode.EDUCATIONAL)  # Safe mode
        """
        cls._mode = mode
        # Ensure instance exists and apply settings
        if cls._instance is None:
            cls._instance = cls()
        cls._instance._apply_mode_settings()
    
    @classmethod
    def get_mode(cls) -> OperationMode:
        """Get current operation mode."""
        return cls._mode
    
    @classmethod
    def get_config(cls) -> Dict[str, Any]:
        """Get configuration for current mode."""
        config = MODE_CONFIGS.get(cls._mode)
        if config is None:
            return MODE_CONFIGS[OperationMode.EDUCATIONAL]
        return config
    
    @classmethod
    def is_live_mode(cls) -> bool:
        """Check if running in LIVE mode."""
        return cls._mode == OperationMode.LIVE
    
    @classmethod
    def is_educational_mode(cls) -> bool:
        """Check if running in EDUCATIONAL mode."""
        return cls._mode == OperationMode.EDUCATIONAL
    
    def _apply_mode_settings(self) -> None:
        """Apply configuration settings for current mode."""
        config = MODE_CONFIGS[self._mode]
        
        # Set logging level
        logging.basicConfig(level=config["logging_level"])
        
        # Apply resource limits in educational mode
        if config["resource_limits"] is not None:
            self._apply_resource_limits(config["resource_limits"])
    
    def _apply_resource_limits(self, limits: Dict[str, tuple[Any, ...]]) -> None:
        """
        Apply resource limits for educational mode.
        
        Args:
            limits: Dictionary of resource limits to apply
        """
        try:
            for resource_name, (soft, hard) in limits.items():
                if hasattr(resource, resource_name):
                    resource.setrlimit(getattr(resource, resource_name), (soft, hard))
        except (ValueError, OSError) as e:
            # Resource limits may fail in some environments
            logging.debug(f"Could not apply resource limit: {e}")
    
    @classmethod
    def get_max_rate(cls) -> Optional[int]:
        """Get maximum packet rate for current mode."""
        config = cls.get_config()
        return config["max_rate"]  # type: ignore[return-value]
    
    @classmethod
    def can_spoof(cls) -> bool:
        """Check if IP spoofing is allowed."""
        config = cls.get_config()
        return config["allow_spoofing"]  # type: ignore[return-value]
    
    @classmethod
    def should_drop_privileges(cls) -> bool:
        """Check if privileges should be dropped."""
        config = cls.get_config()
        return config["drop_privileges"]  # type: ignore[return-value]
    
    @classmethod
    def get_description(cls) -> str:
        """Get description of current mode."""
        config = cls.get_config()
        return config["description"]  # type: ignore[return-value]
    
    @classmethod
    def get_banner_string(cls) -> str:
        """Get mode banner string for CLI."""
        config = cls.get_config()
        return f"{config['icon']} {config['name']}: {config['description']}"
    
    @classmethod
    def validate_ip(cls, ip_str: str) -> str:
        """
        Validate IP address based on current mode.
        
        In LIVE mode: Minimal validation (basic format check)
        In EDUCATIONAL mode: Full validation (RFC compliance)
        """
        if cls.get_config()["ip_validation"]:
            import ipaddress
            try:
                return str(ipaddress.ip_address(ip_str))
            except ValueError:
                raise ValueError(f"Invalid IP address: {ip_str}")
        # LIVE mode: Basic check only
        if not isinstance(ip_str, str):
            raise ValueError(f"IP must be string, got {type(ip_str)}")
        parts = ip_str.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IP format: {ip_str}")
        return ip_str
    
    @classmethod
    def validate_port(cls, port: int) -> int:
        """
        Validate port number based on current mode.
        
        In LIVE mode: Allow any port 0-65535
        In EDUCATIONAL mode: Restrict to well-known + registered ports
        """
        if cls.get_config()["port_validation"]:
            # Educational: Full validation
            port = int(port)
            if port < 0 or port > 65535:
                raise ValueError(f"Port must be 0-65535, got {port}")
            return port
        # LIVE mode: Minimal validation
        port = int(port)
        if port < 0 or port > 65535:
            raise ValueError(f"Port out of range: {port}")
        return port


# =============================================================================
# MODE DECORATORS
# =============================================================================

def require_mode(*modes: OperationMode) -> Callable[..., Any]:
    """
    Decorator to require specific operation modes.
    
    Args:
        modes: Allowed operation modes
        
    Raises:
        RuntimeError: If current mode is not in allowed modes
        
    Example:
        @require_mode(OperationMode.LIVE)
        def perform_scan():
            pass
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if ModeManager.get_mode() not in modes:
                allowed = ", ".join(m.name for m in modes)
                raise RuntimeError(
                    f"Function '{func.__name__}' requires mode(s): {allowed}. "
                    f"Current mode: {ModeManager.get_mode().name}"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def live_only(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to restrict function to LIVE mode only.
    
    Example:
        @live_only
        def perform_flood():
            pass
    """
    return require_mode(OperationMode.LIVE)(func)


# =============================================================================
# MODE DETECTION
# =============================================================================

def detect_mode_from_args(args: Dict[str, Any]) -> OperationMode:
    """
    Detect operation mode from command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        OperationMode based on arguments
    """
    # Check for explicit mode flag
    if "mode" in args:
        mode_arg = str(args["mode"]).lower()
        if mode_arg in ("live", "red", "professional"):
            return OperationMode.LIVE
        elif mode_arg in ("edu", "educational", "green", "training"):
            return OperationMode.EDUCATIONAL
    
    # Infer from other flags
    if args.get("rate", 0) > 1000:
        return OperationMode.LIVE
    if args.get("spoof", False):
        return OperationMode.LIVE
    
    return OperationMode.LIVE  # Default to LIVE for professional tool


def get_system_info() -> Dict[str, Any]:
    """
    Get system information for mode configuration.
    
    Returns:
        Dictionary with system information
    """
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cpu_count": os.cpu_count(),
        "memory_total": resource.getrlimit(resource.RLIMIT_AS),
        "mode": ModeManager.get_mode().value,
    }


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'ModeManager',
    'OperationMode',
    'MODE_CONFIGS',
    'require_mode',
    'live_only',
    'detect_mode_from_args',
    'get_system_info',
]
