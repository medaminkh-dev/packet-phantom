"""
Service Detection Module for Packet Phantom God

Performs banner grabbing and version detection on open ports.
"""

import asyncio
import re
import ssl
import socket
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum


class ProbeType(Enum):
    """Types of service probes"""
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    TELNET = "telnet"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    REDIS = "redis"
    DNS = "dns"
    POP3 = "pop3"
    IMAP = "imap"
    LDAP = "ldap"
    SNMP = "snmp"
    MSSQL = "mssql"
    ORACLE = "oracle"
    VNC = "vnc"
    RDP = "rdp"
    MQTT = "mqtt"
    NTP = "ntp"
    MEMCACHED = "memcached"
    MONGODB = "mongodb"
    ELASTICSEARCH = "elasticsearch"
    RABBITMQ = "rabbitmq"
    KAFKA = "kafka"
    ZOOKEEPER = "zookeeper"
    UNKNOWN = "unknown"


@dataclass
class ServiceFingerprint:
    """Service fingerprint pattern"""
    port: int
    service: str
    probe_type: ProbeType
    regex: Optional[str]
    name: str
    priority: int = 10


# Comprehensive Service Fingerprint Database
SERVICE_PATTERNS: List[ServiceFingerprint] = [
    # SSH Services
    ServiceFingerprint(
        port=22,
        service="ssh",
        probe_type=ProbeType.SSH,
        regex=r"SSH-([\d.]+)-([^ \r\n]+)",
        name="OpenSSH",
        priority=10
    ),
    ServiceFingerprint(
        port=22,
        service="ssh",
        probe_type=ProbeType.SSH,
        regex=r"SSH-([\d.]+)-([^ \r\n]+)",
        name="Dropbear SSH",
        priority=9
    ),
    
    # HTTP Services
    ServiceFingerprint(
        port=80,
        service="http",
        probe_type=ProbeType.HTTP,
        regex=r"Server: ([^\r\n]+)",
        name="Apache HTTP Server",
        priority=10
    ),
    ServiceFingerprint(
        port=80,
        service="http",
        probe_type=ProbeType.HTTP,
        regex=r"Server: ([^\r\n]+)",
        name="Nginx",
        priority=10
    ),
    ServiceFingerprint(
        port=80,
        service="http",
        probe_type=ProbeType.HTTP,
        regex=r"^Microsoft-IIS/([\d.]+)",
        name="Microsoft IIS",
        priority=10
    ),
    ServiceFingerprint(
        port=8080,
        service="http",
        probe_type=ProbeType.HTTP,
        regex=r"Server: ([^\r\n]+)",
        name="Apache HTTP Server",
        priority=10
    ),
    ServiceFingerprint(
        port=8000,
        service="http",
        probe_type=ProbeType.HTTP,
        regex=r"Server: ([^\r\n]+)",
        name="Python HTTP Server",
        priority=8
    ),
    ServiceFingerprint(
        port=4434,
        service="http",
        probe_type=ProbeType.HTTP,
        regex=r"Server: ([^\r\n]+)",
        name="Dev HTTP Server",
        priority=7
    ),
    
    # HTTPS/SSL Services
    ServiceFingerprint(
        port=443,
        service="https",
        probe_type=ProbeType.HTTPS,
        regex=None,
        name="SSL/TLS",
        priority=10
    ),
    ServiceFingerprint(
        port=8443,
        service="https",
        probe_type=ProbeType.HTTPS,
        regex=None,
        name="SSL/TLS",
        priority=10
    ),
    
    # FTP Services
    ServiceFingerprint(
        port=21,
        service="ftp",
        probe_type=ProbeType.FTP,
        regex=r"220[ \t]+([^\r\n]+)",
        name="vsftpd",
        priority=10
    ),
    ServiceFingerprint(
        port=21,
        service="ftp",
        probe_type=ProbeType.FTP,
        regex=r"220[ \t]+([^\r\n]+)",
        name="ProFTPD",
        priority=9
    ),
    ServiceFingerprint(
        port=21,
        service="ftp",
        probe_type=ProbeType.FTP,
        regex=r"220[ \t]+([^\r\n]+)",
        name="Pure-FTPd",
        priority=8
    ),
    
    # SMTP Services
    ServiceFingerprint(
        port=25,
        service="smtp",
        probe_type=ProbeType.SMTP,
        regex=r"220[ \t]+([^\r\n]+)",
        name="Postfix",
        priority=10
    ),
    ServiceFingerprint(
        port=25,
        service="smtp",
        probe_type=ProbeType.SMTP,
        regex=r"220[ \t]+([^\r\n]+)",
        name="Sendmail",
        priority=9
    ),
    ServiceFingerprint(
        port=587,
        service="smtp",
        probe_type=ProbeType.SMTP,
        regex=r"220[ \t]+([^\r\n]+)",
        name="Postfix Submission",
        priority=10
    ),
    
    # Telnet Services
    ServiceFingerprint(
        port=23,
        service="telnet",
        probe_type=ProbeType.TELNET,
        regex=r"(.*)",
        name="Telnet",
        priority=10
    ),
    
    # MySQL Services
    ServiceFingerprint(
        port=3306,
        service="mysql",
        probe_type=ProbeType.MYSQL,
        regex=r"([\d.]+)[ \t]+(?:-\s*)?(?:[A-Za-z]+[ \t]+)?(?:Protocol][ \t]+(?:used)[ \t]+(?:)[ \t]+)?(?:[A-Za-z ]+)?(?:MySQL)",
        name="MySQL",
        priority=10
    ),
    ServiceFingerprint(
        port=3306,
        service="mysql",
        probe_type=ProbeType.MYSQL,
        regex=r"^([\d.]+)-MariaDB",
        name="MariaDB",
        priority=10
    ),
    
    # PostgreSQL Services
    ServiceFingerprint(
        port=5432,
        service="postgresql",
        probe_type=ProbeType.POSTGRESQL,
        regex=r"PostgreSQL[\t ]+([\d.]+)",
        name="PostgreSQL",
        priority=10
    ),
    
    # Redis Services
    ServiceFingerprint(
        port=6379,
        service="redis",
        probe_type=ProbeType.REDIS,
        regex=r"redis_version:([^\r\n]+)",
        name="Redis",
        priority=10
    ),
    
    # DNS Services
    ServiceFingerprint(
        port=53,
        service="dns",
        probe_type=ProbeType.DNS,
        regex=None,
        name="DNS",
        priority=10
    ),
    
    # POP3 Services
    ServiceFingerprint(
        port=110,
        service="pop3",
        probe_type=ProbeType.POP3,
        regex=r"^\+OK[ \t]+([^\r\n]+)",
        name="Dovecot POP3",
        priority=10
    ),
    
    # IMAP Services
    ServiceFingerprint(
        port=143,
        service="imap",
        probe_type=ProbeType.IMAP,
        regex=r"^\* OK [ \t]+([^\r\n]+)",
        name="Dovecot IMAP",
        priority=10
    ),
    
    # LDAP Services
    ServiceFingerprint(
        port=389,
        service="ldap",
        probe_type=ProbeType.LDAP,
        regex=None,
        name="OpenLDAP",
        priority=10
    ),
    ServiceFingerprint(
        port=636,
        service="ldaps",
        probe_type=ProbeType.LDAP,
        regex=None,
        name="OpenLDAP SSL",
        priority=10
    ),
    
    # SNMP Services
    ServiceFingerprint(
        port=161,
        service="snmp",
        probe_type=ProbeType.SNMP,
        regex=None,
        name="SNMP",
        priority=8
    ),
    
    # MSSQL Services
    ServiceFingerprint(
        port=1433,
        service="mssql",
        probe_type=ProbeType.MSSQL,
        regex=None,
        name="Microsoft SQL Server",
        priority=10
    ),
    
    # Oracle Services
    ServiceFingerprint(
        port=1521,
        service="oracle",
        probe_type=ProbeType.ORACLE,
        regex=None,
        name="Oracle Database",
        priority=10
    ),
    
    # VNC Services
    ServiceFingerprint(
        port=5900,
        service="vnc",
        probe_type=ProbeType.VNC,
        regex=r"RFB ([0-9.]+)",
        name="VNC Server",
        priority=10
    ),
    
    # RDP Services
    ServiceFingerprint(
        port=3389,
        service="rdp",
        probe_type=ProbeType.RDP,
        regex=None,
        name="Microsoft RDP",
        priority=10
    ),
    
    # MQTT Services
    ServiceFingerprint(
        port=1883,
        service="mqtt",
        probe_type=ProbeType.MQTT,
        regex=None,
        name="MQTT Broker",
        priority=8
    ),
    
    # NTP Services
    ServiceFingerprint(
        port=123,
        service="ntp",
        probe_type=ProbeType.NTP,
        regex=None,
        name="NTP",
        priority=7
    ),
    
    # Memcached Services
    ServiceFingerprint(
        port=11211,
        service="memcached",
        probe_type=ProbeType.MEMCACHED,
        regex=None,
        name="Memcached",
        priority=8
    ),
    
    # MongoDB Services
    ServiceFingerprint(
        port=27017,
        service="mongodb",
        probe_type=ProbeType.MONGODB,
        regex=None,
        name="MongoDB",
        priority=10
    ),
    
    # Elasticsearch Services
    ServiceFingerprint(
        port=9200,
        service="elasticsearch",
        probe_type=ProbeType.ELASTICSEARCH,
        regex=r'"name":"([^"]+)"',
        name="Elasticsearch",
        priority=10
    ),
    
    # RabbitMQ Services
    ServiceFingerprint(
        port=5672,
        service="rabbitmq",
        probe_type=ProbeType.RABBITMQ,
        regex=None,
        name="RabbitMQ",
        priority=8
    ),
    
    # Kafka Services
    ServiceFingerprint(
        port=9092,
        service="kafka",
        probe_type=ProbeType.KAFKA,
        regex=None,
        name="Apache Kafka",
        priority=8
    ),
    
    # Zookeeper Services
    ServiceFingerprint(
        port=2181,
        service="zookeeper",
        probe_type=ProbeType.ZOOKEEPER,
        regex=None,
        name="Apache Zookeeper",
        priority=8
    ),
]


class BannerExtractor:
    """Extract version information from service banners"""
    
    # Common version extraction patterns
    VERSION_PATTERNS = [
        # OpenSSH: OpenSSH_8.9p1 Ubuntu
        (r"OpenSSH_([0-9.p]+)[ \t]*([^\r\n]*)", "OpenSSH"),
        # Apache: Apache/2.4.41
        (r"Apache/([0-9.]+)", "Apache"),
        # Nginx: nginx/1.18.0
        (r"nginx/([0-9.]+)", "Nginx"),
        # Microsoft IIS: Microsoft-IIS/10.0
        (r"Microsoft-IIS/([0-9.]+)", "IIS"),
        # MySQL: 5.7.38
        (r"^([0-9]+\.[0-9]+\.[0-9]+)", "MySQL"),
        # MariaDB: 10.5.15-MariaDB
        (r"([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", "MariaDB"),
        # PostgreSQL: PostgreSQL 14.5
        (r"PostgreSQL[ \t]+([0-9.]+)", "PostgreSQL"),
        # Redis: redis_version:7.0.11
        (r"redis_version:([^\r\n]+)", "Redis"),
        # VNC: RFB 003.008
        (r"RFB ([0-9.]+)", "VNC"),
        # Elasticsearch: {"name":"node-name"
        (r'"version":"([0-9.]+)"', "Elasticsearch"),
        # PHP: PHP/7.4.3
        (r"PHP/([0-9.]+)", "PHP"),
        # Python: Python/3.8.10
        (r"Python/([0-9.]+)", "Python"),
        # LiteSpeed: LiteSpeed/5.4.12
        (r"LiteSpeed/([0-9.]+)", "LiteSpeed"),
        # Tomcat: Apache Tomcat/9.0.41
        (r"Apache Tomcat/([0-9.]+)", "Tomcat"),
        # JBoss: JBoss AS/7.x
        (r"JBoss AS/([0-9.]+)", "JBoss"),
        # Node.js: Node.js/16.13.0
        (r"Node\.js/([0-9.]+)", "Node.js"),
    ]
    
    @classmethod
    def extract_version(cls, banner: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract version string from banner.
        
        Returns:
            Tuple of (version_string, product_name) or (None, None)
        """
        if not banner:
            return None, None
        
        for pattern, product in cls.VERSION_PATTERNS:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                return version, product
        
        return None, None
    
    @classmethod
    def clean_banner(cls, banner: bytes) -> str:
        """
        Clean banner by removing control characters and decoding.
        
        Args:
            banner: Raw banner bytes
            
        Returns:
            Cleaned banner string
        """
        if not banner:
            return ""
        
        # Try UTF-8 first, then Latin-1
        try:
            banner_str = banner.decode('utf-8', errors='ignore')
        except Exception:
            try:
                banner_str = banner.decode('latin-1', errors='ignore')
            except Exception:
                banner_str = banner.decode('ascii', errors='ignore')
        
        # Remove control characters except newlines and tabs
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', banner_str)
        
        # Strip whitespace
        cleaned = cleaned.strip()
        
        return cleaned


class ProbeFunctions:
    """Async probe functions for different service types"""
    
    @staticmethod
    async def probe_http(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe HTTP service.
        
        Sends: GET / HTTP/1.1\r\nHost: {host}\r\n\r\n
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # Read response
            try:
                response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=timeout
                )
            except Exception:
                response = b""
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_https(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe HTTPS/SSL service.
        
        Performs TLS handshake to get certificate info.
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with SSL
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=timeout
            )
            
            # Try to get HTTP response
            try:
                writer.write(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except Exception:
                response = b""
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError, Exception):
            return None
    
    @staticmethod
    async def probe_ssh(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe SSH service.
        
        SSH servers send their banner immediately on connection.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read SSH banner
            try:
                banner = await asyncio.wait_for(
                    reader.read(256),
                    timeout=timeout
                )
            except Exception:
                banner = b""
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_ftp(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe FTP service.
        
        FTP servers send 220 banner on connection.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read FTP banner
            try:
                banner = await asyncio.wait_for(
                    reader.read(256),
                    timeout=timeout
                )
            except Exception:
                banner = b""
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_smtp(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe SMTP service.
        
        Sends EHLO or HELO and reads response.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read initial banner
            try:
                banner = await asyncio.wait_for(
                    reader.read(256),
                    timeout=timeout
                )
            except Exception:
                banner = b""
            
            # Send EHLO
            try:
                writer.write(f"EHLO localhost\r\n".encode())
                await writer.drain()
                ehlo_response = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout
                )
                banner += ehlo_response
            except Exception:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_telnet(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe Telnet service.
        
        Reads telnet negotiation and prompt.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read telnet data
            try:
                data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout
                )
            except Exception:
                data = b""
            
            writer.close()
            await writer.wait_closed()
            
            return data.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_mysql(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe MySQL/MariaDB service.
        
        Reads MySQL greeting packet.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read MySQL greeting
            try:
                greeting = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout
                )
            except Exception:
                greeting = b""
            
            writer.close()
            await writer.wait_closed()
            
            return greeting.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_postgresql(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe PostgreSQL service.
        
        Reads PostgreSQL startup message.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read PostgreSQL startup
            try:
                startup = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout
                )
            except Exception:
                startup = b""
            
            writer.close()
            await writer.wait_closed()
            
            return startup.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_redis(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe Redis service.
        
        Sends PING command and reads PONG response.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Send PING
            try:
                writer.write(b"*1\r\n$4\r\nPING\r\n")
                await writer.drain()
                response = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout
                )
            except Exception:
                response = b""
            
            # Send INFO for version
            try:
                writer.write(b"*2\r\n$4\r\nINFO\r\n$11\r\nserver\r\n")
                await writer.drain()
                info_response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=timeout
                )
                response += info_response
            except Exception:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_dns(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe DNS service.
        
        Sends A query for localhost.
        """
        try:
            # Create DNS query
            transaction_id = b'\x00\x01'
            flags = b'\x01\x00'
            questions = b'\x00\x01'
            answer_rrs = b'\x00\x00'
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'
            
            # Query for localhost
            query_name = b'\x09localhost\x00\x00\x01\x00\x01'
            
            dns_header = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
            dns_query = dns_header + query_name
            
            # Connect and send
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            writer.write(dns_query)
            await writer.drain()
            
            # Read response
            try:
                response = await asyncio.wait_for(
                    reader.read(512),
                    timeout=timeout
                )
            except Exception:
                response = b""
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_memcached(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe Memcached service.
        
        Sends stats command.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Send stats command
            try:
                writer.write(b"stats\r\n")
                await writer.drain()
                response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=timeout
                )
            except Exception:
                response = b""
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_elasticsearch(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Probe Elasticsearch service.
        
        Sends HTTP request to get cluster info.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Send HTTP request
            try:
                writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                response = await asyncio.wait_for(
                    reader.read(4096),
                    timeout=timeout
                )
            except Exception:
                response = b""
            
            writer.close()
            await writer.wait_closed()
            
            return response.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None
    
    @staticmethod
    async def probe_default(host: str, port: int, timeout: float) -> Optional[str]:
        """
        Default probe - just reads whatever is available.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Read whatever is sent
            try:
                data = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=timeout
                )
            except Exception:
                data = b""
            
            writer.close()
            await writer.wait_closed()
            
            return data.decode('utf-8', errors='ignore')
        
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, Exception):
            return None


class ServiceDetector:
    """
    Service detection class for banner grabbing and version detection.
    
    Args:
        intensity: Detection intensity (1-10). Higher = more thorough probes.
        timeout: Connection timeout in seconds.
    """
    
    def __init__(self, intensity: int = 7, timeout: float = 3.0):
        """
        Initialize the service detector.
        
        Args:
            intensity: Detection intensity (1-10)
            timeout: Connection timeout in seconds
        """
        self.intensity = max(1, min(10, intensity))
        self.timeout = timeout
        
        # Build port-to-probe-type mapping
        self._port_probe_map: Dict[int, ProbeType] = {}
        for pattern in SERVICE_PATTERNS:
            if pattern.port not in self._port_probe_map:
                self._port_probe_map[pattern.port] = pattern.probe_type
    
    async def detect_service(self, host: str, port: int) -> Dict[str, Any]:
        """
        Detect service and version on a port.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Dictionary with service, version, banner, and confidence
        """
        result = {
            "host": host,
            "port": port,
            "service": "unknown",
            "version": None,
            "banner": None,
            "confidence": 0.0,
            "probe_type": "unknown",
            "product": None,
            "error": None
        }
        
        # Get probe type for this port
        probe_type = self._port_probe_map.get(port, ProbeType.UNKNOWN)
        result["probe_type"] = probe_type.value
        
        # Probe based on service type
        banner = await self._probe_service(host, port, probe_type)
        
        if banner:
            result["banner"] = banner
            
            # Extract version and product
            version, product = BannerExtractor.extract_version(banner)
            result["version"] = version
            result["product"] = product
            
            # Match against fingerprints
            fingerprint = self._match_fingerprint(port, banner)
            
            if fingerprint:
                result["service"] = fingerprint.service
                result["confidence"] = min(1.0, fingerprint.priority / 10.0)
                if fingerprint.name:
                    result["product"] = fingerprint.name
        
        return result
    
    async def _probe_service(
        self, host: str, port: int, probe_type: ProbeType
    ) -> Optional[str]:
        """
        Probe a service based on its type.
        
        Args:
            host: Target host
            port: Target port
            probe_type: Type of probe to use
            
        Returns:
            Banner string or None
        """
        probe_map = {
            ProbeType.HTTP: ProbeFunctions.probe_http,
            ProbeType.HTTPS: ProbeFunctions.probe_https,
            ProbeType.SSH: ProbeFunctions.probe_ssh,
            ProbeType.FTP: ProbeFunctions.probe_ftp,
            ProbeType.SMTP: ProbeFunctions.probe_smtp,
            ProbeType.TELNET: ProbeFunctions.probe_telnet,
            ProbeType.MYSQL: ProbeFunctions.probe_mysql,
            ProbeType.POSTGRESQL: ProbeFunctions.probe_postgresql,
            ProbeType.REDIS: ProbeFunctions.probe_redis,
            ProbeType.DNS: ProbeFunctions.probe_dns,
            ProbeType.MEMCACHED: ProbeFunctions.probe_memcached,
            ProbeType.ELASTICSEARCH: ProbeFunctions.probe_elasticsearch,
        }
        
        probe_func = probe_map.get(probe_type, ProbeFunctions.probe_default)
        
        try:
            banner = await probe_func(host, port, self.timeout)
            return banner
        except Exception:
            return None
    
    def _match_fingerprint(
        self, port: int, banner: str
    ) -> Optional[ServiceFingerprint]:
        """
        Match banner against known fingerprints.
        
        Args:
            port: Target port
            banner: Service banner
            
        Returns:
            Matching fingerprint or None
        """
        if not banner:
            return None
        
        # Get patterns for this port, sorted by priority
        patterns = [
            p for p in SERVICE_PATTERNS if p.port == port
        ]
        patterns.sort(key=lambda x: x.priority, reverse=True)
        
        for pattern in patterns:
            if pattern.regex:
                try:
                    if re.search(pattern.regex, banner, re.IGNORECASE):
                        return pattern
                except re.error:
                    continue
        
        # Return first pattern for this port if no regex match
        if patterns:
            return patterns[0]
        
        return None
    
    async def detect_multiple(
        self, host: str, ports: List[int]
    ) -> List[Dict[str, Any]]:
        """
        Detect services on multiple ports.
        
        Args:
            host: Target host
            ports: List of ports to scan
            
        Returns:
            List of detection results
        """
        tasks = [
            self.detect_service(host, port) for port in ports
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
        
        return valid_results
    
    def get_probe_type_for_port(self, port: int) -> ProbeType:
        """
        Get the expected probe type for a port.
        
        Args:
            port: Port number
            
        Returns:
            ProbeType enum value
        """
        return self._port_probe_map.get(port, ProbeType.UNKNOWN)


async def detect_service_async(
    host: str, port: int, timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Convenience function to detect a single service.
    
    Args:
        host: Target host
        port: Target port
        timeout: Connection timeout in seconds
        
    Returns:
        Detection result dictionary
    """
    detector = ServiceDetector(timeout=timeout)
    return await detector.detect_service(host, port)


# Convenience function for common services
async def detect_ssh(host: str, port: int = 22, timeout: float = 3.0) -> Dict[str, Any]:
    """Detect SSH service on a port."""
    return await detect_service_async(host, port, timeout)


async def detect_http(host: str, port: int = 80, timeout: float = 3.0) -> Dict[str, Any]:
    """Detect HTTP service on a port."""
    return await detect_service_async(host, port, timeout)


async def detect_https(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """Detect HTTPS service on a port."""
    return await detect_service_async(host, port, timeout)


async def detect_ftp(host: str, port: int = 21, timeout: float = 3.0) -> Dict[str, Any]:
    """Detect FTP service on a port."""
    return await detect_service_async(host, port, timeout)


# Example usage and testing
if __name__ == "__main__":
    import json
    
    async def test_detector():
        """Test the service detector."""
        detector = ServiceDetector(intensity=7, timeout=3.0)
        
        # Test detection (replace with actual hosts)
        test_cases = [
            ("localhost", 22),   # SSH
            ("localhost", 80),   # HTTP
            ("localhost", 443),  # HTTPS
        ]
        
        for host, port in test_cases:
            print(f"\nDetecting service on {host}:{port}...")
            result = await detector.detect_service(host, port)
            print(json.dumps(result, indent=2))
    
    # Run tests
    asyncio.run(test_detector())
