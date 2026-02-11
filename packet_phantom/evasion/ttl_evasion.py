"""
TTL Evasion Module
==================
Variable TTL generation for evasion research and network studies.

This module provides TTL randomization techniques for educational and
research purposes to understand how TTL affects network packet behavior.
"""

import secrets
from typing import List


class TTLEvasion:
    """TTL randomization for evasion studies.
    
    Provides realistic TTL values based on different operating systems
    and generates sequences with natural variation for research purposes.
    """
    
    # Typical TTL ranges for different OS
    WINDOWS_RANGE = (100, 128)
    LINUX_RANGE = (56, 64)
    MACOS_RANGE = (60, 64)
    ROUTER_RANGE = (50, 64)
    
    def __init__(self, base_ttl: int = 64):
        """Initialize TTL evasion with base TTL.
        
        Args:
            base_ttl: Base TTL value to use (default: 64)
        """
        self.base_ttl = base_ttl
    
    def _randint(self, low: int, high: int) -> int:
        """Generate cryptographically secure random integer in range."""
        return secrets.randbelow(high - low + 1) + low
    
    def _random(self) -> float:
        """Generate cryptographically secure random float between 0 and 1."""
        return secrets.randbelow(2**32) / 2**32
    
    def generate_sequence(self, length: int = 10) -> List[int]:
        """Generate realistic TTL sequence with natural variation.
        
        Creates a sequence of TTL values that vary around the base_ttl
        with occasional jumps to simulate real network conditions.
        
        Args:
            length: Number of TTL values to generate
            
        Returns:
            List of TTL values between 1 and 255
        """
        ttl_values = []
        current_ttl = self.base_ttl
        
        for _ in range(length):
            # 10% chance of a jump (simulates route changes)
            if self._random() < 0.1:
                # Random jump within ±20 of base
                current_ttl = self._randint(
                    max(1, self.base_ttl - 20),
                    min(255, self.base_ttl + 20)
                )
            else:
                # Small variation (±3) for gradual drift
                current_ttl = max(1, min(255, current_ttl + self._randint(-3, 3)))
            ttl_values.append(current_ttl)
        
        return ttl_values
    
    def get_realistic_ttl(self, os_type: str = 'linux') -> int:
        """Get realistic TTL based on OS type.
        
        Args:
            os_type: Operating system type ('windows', 'linux', 'macos', 'router')
            
        Returns:
            Realistic TTL value for the specified OS
        """
        ranges = {
            'windows': self.WINDOWS_RANGE,
            'linux': self.LINUX_RANGE,
            'macos': self.MACOS_RANGE,
            'router': self.ROUTER_RANGE
        }
        
        selected_range = ranges.get(os_type.lower(), self.LINUX_RANGE)
        return self._randint(selected_range[0], selected_range[1])
