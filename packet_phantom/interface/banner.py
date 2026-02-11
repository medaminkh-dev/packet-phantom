#!/usr/bin/env python3
"""
Packet Phantom - Banner Module
=============================

Banner Module: Static, solid, inspired by Nmap/Metasploit/FFUF
Characteristics: No shifting, no breaking, minimal, essential
Cyber-styled ASCII art for "PACKET PHANTOM"

Author: Packet Phantom Team
Version: 2.0.0
"""

import sys
from typing import Optional


# ==============================================================================
# COLOR CODES
# ==============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Mode colors
    GREEN = '\033[32m'
    RED = '\033[31m'
    CYAN = '\033[36m'
    YELLOW = '\033[33m'
    
    # Extended colors
    LIGHT_GREEN = '\033[92m'
    LIGHT_RED = '\033[91m'
    LIGHT_CYAN = '\033[96m'
    LIGHT_YELLOW = '\033[93m'
    
    # Cyber neon colors
    NEON_GREEN = '\033[38;5;46m'
    NEON_RED = '\033[38;5;196m'
    NEON_CYAN = '\033[38;5;51m'
    NEON_YELLOW = '\033[38;5;226m'


# ==============================================================================
# CYBER ASCII ART FONTS FOR "PACKET PHANTOM"
# ==============================================================================

# Cyber Large Font (for full banner)
CYBER_BANNER_EDU = [
    "  ██████   █████  ███    ███ ███████      ██████  ██    ██ ███████ ██████  ",
    " ██       ██PP ██ ████  ████ ██          ██    ██ ██    ██ ██      ██PP ██ ",
    " ██  ███  ███████ ██ ████ ██ █████       ██ @@ ██ ██    ██ █████   ██████  ",
    " ██   ██  ██   ██ ██  ██  ██ ██          ██    ██  ██  ██  ██      ██   ██ ",
    "PP██████  ██   ██ ██      ██ ███████      ██████  PP ████   ███████ ██   ██ ",
]

CYBER_BANNER_LIVE = [
    "  ██████   █████  ███    ███ ███████      ██████  ██    ██ ███████ ██████  ",
    " ██       ██PP ██ ████  ████ ██          ██    ██ ██    ██ ██      ██PP ██ ",
    " ██  ███  ███████ ██ ████ ██ █████       ██ @@ ██ ██    ██ █████   ██████  ",
    " ██   ██  ██   ██ ██  ██  ██ ██          ██    ██  ██  ██  ██      ██   ██ ",
    "PP██████  ██   ██ ██      ██ ███████      ██████  PP ████   ███████ ██   ██ ",
]

# Network/Packet sub-header
SUB_HEADER = [
    "    ╔═══════════════════════════════════════════════════════════════╗",
    "    ║   [> PACKET FORGER v2.0.0 <]  [EDU MODE - SAFE TESTING]       ║",
    "    ╚═══════════════════════════════════════════════════════════════╝",
]

SUB_HEADER_LIVE = [
    "    ╔═══════════════════════════════════════════════════════════════╗",
    "    ║     [> PACKET FORGER v2.0.0 <]  [!!! LIVE MODE ACTIVE !!!]    ║",
    "    ║      ⚠ AUTHORIZED TESTING ONLY - PROCEED WITH CAUTION ⚠       ║",
    "    ╚═══════════════════════════════════════════════════════════════╝",
]

# Compact banner
COMPACT_EDU = "[ PACKET PHANTOM ] v2.0.0 | EDU Mode | Safe Testing"
COMPACT_LIVE = "[ PACKET PHANTOM ] v2.0.0 | ⚠ LIVE MODE ⚠ | Authorized Only"

# Minimal banner
MINIMAL_EDU = "▶ PP/2.0 [EDU]"
MINIMAL_LIVE = "▶ PP/2.0 [LIVE]"


# ==============================================================================
# ADAPTIVE BANNER CLASS
# ==============================================================================

class AdaptiveBanner:
    """
    Adaptive banner that changes colors based on operation mode.
    
    Attributes:
        mode: Operation mode (EDU or LIVE)
    """
    
    def __init__(self, mode: str = "EDU"):
        """
        Initialize the adaptive banner.
        
        Args:
            mode: Operation mode (EDU or LIVE)
        """
        self.mode = mode.upper()
        self.colors = self._get_mode_colors()
    
    def _get_mode_colors(self) -> dict:
        """
        Get color scheme based on operation mode.
        
        Returns:
            Dictionary of color codes for the current mode
        """
        if self.mode == "LIVE":
            return {
                'primary': Colors.RED,
                'secondary': Colors.YELLOW,
                'accent': Colors.LIGHT_RED,
                'dim': Colors.DIM,
                'bold': Colors.BOLD,
                'reset': Colors.RESET,
                'neon': Colors.NEON_RED,
                'border': Colors.YELLOW,
            }
        else:
            # EDU mode
            return {
                'primary': Colors.GREEN,
                'secondary': Colors.CYAN,
                'accent': Colors.LIGHT_CYAN,
                'dim': Colors.DIM,
                'bold': Colors.BOLD,
                'reset': Colors.RESET,
                'neon': Colors.NEON_GREEN,
                'border': Colors.CYAN,
            }
    
    def _colored(self, text: str, color: str) -> str:
        """Apply color to text if terminal supports it."""
        if sys.stdout.isatty():
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def banner_edu(self) -> str:
        """
        Generate full EDU mode banner with cyber styling.
        
        Returns:
            Formatted banner string for EDU mode
        """
        c = self.colors
        lines = [""]
        
        # Add cyber banner with primary color
        for line in CYBER_BANNER_EDU:
            lines.append(self._colored(line, c['primary']))
        
        # Add sub-header with border
        for line in SUB_HEADER:
            lines.append(self._colored(line, c['border']))
        
        lines.append("")
        return "\n".join(lines)
    
    def banner_live(self) -> str:
        """
        Generate full LIVE mode banner with cyber styling.
        
        Returns:
            Formatted banner string for LIVE mode
        """
        c = self.colors
        lines = [""]
        
        # Add cyber banner with primary color
        for line in CYBER_BANNER_LIVE:
            lines.append(self._colored(line, c['primary']))
        
        # Add warning sub-header with border
        for line in SUB_HEADER_LIVE:
            lines.append(self._colored(line, c['border']))
        
        lines.append("")
        return "\n".join(lines)
    
    def banner_compact(self) -> str:
        """
        Generate compact banner.
        
        Returns:
            Compact banner string based on mode
        """
        if self.mode == "LIVE":
            return self._colored(COMPACT_LIVE, self.colors['primary']) + "\n"
        else:
            return self._colored(COMPACT_EDU, self.colors['primary']) + "\n"
    
    def banner_minimal(self) -> str:
        """
        Generate minimal banner.
        
        Returns:
            Minimal banner string based on mode
        """
        if self.mode == "LIVE":
            return self._colored(MINIMAL_LIVE, self.colors['primary']) + "\n"
        else:
            return self._colored(MINIMAL_EDU, self.colors['primary']) + "\n"
    
    def generate(self, style: str = "full") -> str:
        """
        Generate banner in specified style.
        
        Args:
            style: Banner style (full, compact, minimal)
        
        Returns:
            Formatted banner string
        """
        style = style.lower()
        
        if style == "full":
            if self.mode == "LIVE":
                return self.banner_live()
            else:
                return self.banner_edu()
        elif style == "compact":
            return self.banner_compact()
        elif style == "minimal":
            return self.banner_minimal()
        else:
            # Default to full
            if self.mode == "LIVE":
                return self.banner_live()
            else:
                return self.banner_edu()
    
    def print_banner(self, style: str = "full") -> None:
        """
        Print banner to stdout.
        
        Args:
            style: Banner style (full, compact, minimal)
        """
        print(self.generate(style))


# ==============================================================================
# CONVENIENCE FUNCTIONS
# ==============================================================================

def create_banner(mode: str = "EDU", style: str = "full") -> str:
    """
    Create a banner string.
    
    Args:
        mode: Operation mode (EDU or LIVE)
        style: Banner style (full, compact, minimal)
    
    Returns:
        Formatted banner string
    """
    banner = AdaptiveBanner(mode)
    return banner.generate(style)


def print_banner(mode: str = "EDU", style: str = "full") -> None:
    """
    Print banner to stdout.
    
    Args:
        mode: Operation mode (EDU or LIVE)
        style: Banner style (full, compact, minimal)
    """
    banner = AdaptiveBanner(mode)
    banner.print_banner(style)


# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == "__main__":
    import sys
    
    # Parse command line arguments
    mode = "EDU"
    style = "full"
    
    if len(sys.argv) > 1:
        if sys.argv[1].upper() in ["EDU", "LIVE"]:
            mode = sys.argv[1].upper()
        else:
            print(f"Unknown mode: {sys.argv[1]}")
            print("Usage: python banner.py [EDU|LIVE] [full|compact|minimal]")
            sys.exit(1)
    
    if len(sys.argv) > 2:
        if sys.argv[2] in ["full", "compact", "minimal"]:
            style = sys.argv[2]
        else:
            print(f"Unknown style: {sys.argv[2]}")
            print("Usage: python banner.py [EDU|LIVE] [full|compact|minimal]")
            sys.exit(1)
    
    print_banner(mode, style)
