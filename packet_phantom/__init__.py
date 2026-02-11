"""
Packet Phantom v2.0.0 - Professional Network Testing Tool
========================================================

A professional-grade network testing tool for security research.
Supports high-performance packet crafting, evasion techniques,
and multiple output formats.

Usage:
    from packet_phantom import cli
    from packet_phantom.evasion import EvasionSuite
    from packet_phantom.output import OutputManager

Author: Packet Phantom Team
Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "Packet Phantom Team"

from packet_phantom.core.mode_manager import ModeManager, OperationMode

__all__ = [
    'ModeManager',
    'OperationMode',
    '__version__',
]
