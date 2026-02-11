"""
Padding Generator Module
=======================
Packet padding generation for size evasion and research.

This module provides techniques to generate random padding for packets
to study size-based network behaviors and evasion techniques.
"""

import os
import secrets


class PaddingGenerator:
    """Generate random padding for packets.
    
    Provides padding generation for network research to study how
    packet sizes affect network behavior and evasion capabilities.
    """
    
    def generate_padding(self, min_size: int = 0, 
                        max_size: int = 1400) -> bytes:
        """Generate random padding bytes.
        
        Creates cryptographically secure random padding within
        the specified size range.
        
        Args:
            min_size: Minimum padding size in bytes
            max_size: Maximum padding size in bytes
            
        Returns:
            Random padding bytes
        """
        # Ensure valid range
        min_size = max(0, min_size)
        max_size = max(min_size, max_size)
        
        size = secrets.randbelow(max_size - min_size + 1) + min_size
        return os.urandom(size)
    
    def add_ip_padding(self, packet: bytes, 
                      target_size: int = 1500,
                      max_padding: int = 1400) -> bytes:
        """Add padding to IP packet if needed.
        
        Pads the packet payload to reach the target size for
        studying fragmentation and MTU behavior.
        
        Args:
            packet: Original IP packet bytes
            target_size: Desired total packet size
            max_padding: Maximum padding to add
            
        Returns:
            Padded packet bytes
        """
        if len(packet) >= target_size:
            return packet
        
        padding_needed = target_size - len(packet)
        max_pad = min(max_padding, padding_needed)
        padding = self.generate_padding(0, max_pad)
        
        # Ensure we reach target size
        if len(packet) + len(padding) < target_size:
            padding += b'\x00' * (target_size - len(packet) - len(padding))
        
        # Add padding to end of payload
        return packet + padding
    
    def add_tcp_padding(self, tcp_segment: bytes,
                       target_options_size: int = 40) -> bytes:
        """Add padding to TCP options if needed.
        
        Args:
            tcp_segment: Original TCP segment bytes
            target_options_size: Desired minimum options size
            
        Returns:
            TCP segment with padding
        """
        # Calculate current options size (header starts at byte 12)
        if len(tcp_segment) < 20:
            return tcp_segment
        
        data_offset = (tcp_segment[12] >> 4) * 4
        header_size = max(20, data_offset)
        
        if header_size >= target_options_size:
            return tcp_segment
        
        padding_needed = target_options_size - header_size
        padding = self.generate_padding(0, padding_needed)
        
        return tcp_segment + padding
    
    def generate_legal_padding(self, protocol: str = 'tcp') -> bytes:
        """Generate protocol-compliant padding.
        
        Args:
            protocol: Protocol type ('tcp', 'ip', 'icmp')
            
        Returns:
            Protocol-compliant padding bytes
        """
        padding_sizes = {
            'tcp': (0, 40),    # TCP options padding
            'ip': (0, 40),     # IP header padding
            'icmp': (0, 64)    # ICMP padding
        }
        
        size_range = padding_sizes.get(protocol.lower(), (0, 40))
        return self.generate_padding(size_range[0], size_range[1])
