
class ConsoleColors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ConsoleFormatter:
    """Formatters for console output"""
    
    @staticmethod
    def success(msg: str) -> str:
        return f"{ConsoleColors.GREEN}[✓] {msg}{ConsoleColors.ENDC}"
    
    @staticmethod
    def error(msg: str) -> str:
        return f"{ConsoleColors.RED}[✗] {msg}{ConsoleColors.ENDC}"
    
    @staticmethod
    def warning(msg: str) -> str:
        return f"{ConsoleColors.YELLOW}[!] {msg}{ConsoleColors.ENDC}"
    
    @staticmethod
    def info(msg: str) -> str:
        return f"{ConsoleColors.BLUE}[i] {msg}{ConsoleColors.ENDC}"
    
    @staticmethod
    def packet_sent(dst: str, port: int, size: int) -> str:
        return f"{ConsoleColors.CYAN}[→] Sent {size}B to {dst}:{port}{ConsoleColors.ENDC}"
    
    @staticmethod
    def packet_received(src: str, port: int, size: int) -> str:
        return f"{ConsoleColors.CYAN}[←] Received {size}B from {src}:{port}{ConsoleColors.ENDC}"
