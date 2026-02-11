"""
Network Utilities Module
========================

Provides network interface detection and utility functions for Packet Phantom.


Version: 2.0.0
"""

import socket
import json
from typing import List, Dict, Optional
import subprocess  # nosec B404 - subprocess needed for network interface enumeration


def get_local_ip() -> str:
    """Get the local IP address of this machine."""
    try:
        # Create a UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip: str = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def list_network_interfaces() -> List[Dict[str, str]]:
    """
    List all available network interfaces with their details.
    
    Returns:
        List of dictionaries containing interface information
    """
    interfaces = []
    
    try:
        # Use subprocess to get interface details
        # nosec B603 B607 - ip command with hardcoded args, safe for network enumeration
        result = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for iface in data:
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        interfaces.append({
                            "name": iface.get("ifname", "unknown"),
                            "ip": addr_info.get("local", "N/A"),
                            "prefix": addr_info.get("prefixlen", ""),
                            "mac": iface.get("address", "N/A")
                        })
        else:
            # Fallback method
            interfaces = _fallback_list_interfaces()
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, BlockingIOError, OSError):
        # Fallback method if ip command fails
        interfaces = _fallback_list_interfaces()
    
    return interfaces


def _fallback_list_interfaces() -> List[Dict[str, str]]:
    """
    Fallback method to list network interfaces using socket.
    
    Returns:
        List of interface information dictionaries
    """
    interfaces = []
    
    try:
        # Get all network interfaces using socket
        hostname = socket.gethostname()
        _local_ip = socket.gethostbyname(hostname)  # noqa: F841 - kept for potential future use
        
        interfaces.append({
            "name": "lo",
            "ip": "127.0.0.1",
            "prefix": "8",
            "mac": "00:00:00:00:00:00"
        })
        
        # Try to get actual interfaces
        import os
        if os.path.exists("/sys/class/net"):
            for iface_name in os.listdir("/sys/class/net"):
                if iface_name != "lo":
                    try:
                        # Get IP using socket
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        ip = s.getsockname()[0]
                        s.close()
                        
                        interfaces.append({
                            "name": iface_name,
                            "ip": ip,
                            "prefix": "24",
                            "mac": "N/A"
                        })
                    except Exception:
                        interfaces.append({
                            "name": iface_name,
                            "ip": "N/A",
                            "prefix": "N/A",
                            "mac": "N/A"
                        })
    except Exception:
        # Ultimate fallback
        interfaces = [
            {
                "name": "lo",
                "ip": "127.0.0.1",
                "prefix": "8",
                "mac": "00:00:00:00:00:00"
            }
        ]
    
    return interfaces


def get_default_interface() -> Optional[Dict[str, str]]:
    """
    Get the default network interface.
    
    Returns:
        Dictionary with default interface information or None
    """
    interfaces = list_network_interfaces()
    
    if not interfaces:
        return None
    
    # Try to find a non-loopback interface
    for iface in interfaces:
        if iface["name"] != "lo" and iface["ip"] != "127.0.0.1":
            return iface
    
    # Fallback to first interface
    return interfaces[0] if interfaces else None


def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to an IP address.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address string or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def calculate_checksum(data: bytes) -> int:
    """
    Calculate the checksum for network packet data.
    
    Args:
        data: Bytes to calculate checksum for
        
    Returns:
        Checksum value
    """
    if len(data) % 2:
        data += b'\x00'
    
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    
    total = (total >> 16) + (total & 0xFFFF)
    total = ~total & 0xFFFF
    
    return total


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'get_local_ip',
    'list_network_interfaces',
    'get_default_interface',
    'is_valid_ip',
    'resolve_hostname',
    'calculate_checksum',
]
