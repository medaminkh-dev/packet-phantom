"""
Option Scrambler Module
=======================
TCP option randomization for evasion research and studies.

This module provides techniques to generate randomized but valid TCP options
for network research and educational purposes.
"""

import secrets
import struct


class OptionScrambler:
    """TCP option randomization for evasion studies.
    
    Generates randomized but valid TCP options to study how different
    implementations handle various option combinations.
    """
    
    # TCP Option Types
    OPTION_END = 0
    OPTION_NOP = 1
    OPTION_MSS = 2
    OPTION_WINDOW_SCALE = 3
    OPTION_SACK_PERMITTED = 4
    OPTION_SACK = 5
    OPTION_TIMESTAMP = 8
    
    def generate_options(self, 
                        include_mss: bool = True,
                        include_ws: bool = True,
                        include_timestamp: bool = False) -> bytes:
        """Generate randomized but valid TCP options.
        
        Creates a valid TCP options sequence with randomization for
        MSS, window scale, and timestamp values.
        
        Args:
            include_mss: Include Maximum Segment Size option
            include_ws: Include Window Scale option
            include_timestamp: Include Timestamp option
            
        Returns:
            Bytes containing randomized TCP options, 4-byte aligned
        """
        options = b''
        
        if include_mss:
            # Random MSS between 1400-1460 (typical Ethernet MSS)
            mss = secrets.randbelow(61) + 1400
            # MSS option: kind=2, len=4, value=mss
            options += struct.pack('!BBH', self.OPTION_MSS, 4, mss)
        
        # Add random NOPs (1-3) for padding/variation
        options += b'\x01' * (secrets.randbelow(3) + 1)
        
        if include_ws:
            # Random window scale (0-14 as per RFC 1323)
            ws = secrets.randbelow(15)
            # Window Scale option: kind=3, len=3, value=ws
            options += struct.pack('!BBH', self.OPTION_WINDOW_SCALE, 3, ws)
        
        # Add random NOPs (1-2) for padding/variation
        options += b'\x01' * (secrets.randbelow(2) + 1)
        
        if include_timestamp:
            # Random timestamp values
            ts_val = secrets.randbelow(2**32 - 1) + 1
            ts_echo = secrets.randbelow(2**32 - 1) + 1
            # Timestamp option: kind=8, len=10, ts_val, ts_echo
            options += struct.pack('!BBII', self.OPTION_TIMESTAMP, 10, ts_val, ts_echo)
        
        # Pad to 4-byte boundary with NOPs and EOL
        # EOL (0x00) can be used as padding
        while len(options) % 4 != 0:
            options += b'\x01'
        
        # Add EOL option (which also serves as padding if aligned)
        options += b'\x00'
        
        # Ensure still aligned (EOL doesn't break alignment)
        while len(options) % 4 != 0:
            options += b'\x01'
        
        return options
    
    def generate_sack_permitted(self) -> bytes:
        """Generate SACK Permitted option.
        
        Returns:
            SACK Permitted option bytes
        """
        return struct.pack('!BB', self.OPTION_SACK_PERMITTED, 2)
    
    def generate_sack_block(self, left_edge: int, right_edge: int) -> bytes:
        """Generate SACK block option.
        
        Args:
            left_edge: Left edge of the sack block
            right_edge: Right edge of the sack block
            
        Returns:
            SACK block option bytes
        """
        return struct.pack('!BBII', self.OPTION_SACK, 10, left_edge, right_edge)
