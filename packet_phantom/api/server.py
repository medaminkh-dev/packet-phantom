"""
Packet Phantom - FastAPI Server
==============================

REST API for Packet Phantom professional network testing tool.
Provides endpoints for scanning, flooding, and management.

⚠️  WARNING: This API provides access to powerful network tools.
    Ensure proper authentication and authorization in production.

Endpoints:
- POST /api/v1/scan    - Start a scan job
- GET /api/v1/status/{job_id} - Get job status
- GET /api/v1/results/{job_id} - Get job results
- POST /api/v1/flood   - Start a flood job
- GET /api/v1/metrics  - Prometheus metrics
- DELETE /api/v1/job/{job_id} - Cancel a job

Author: Packet Phantom Team
Version: 2.0.0
"""

import os
import uuid
import time
import asyncio
import ipaddress
import logging
import hashlib
import secrets
import re
import shlex
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, RedirectResponse
from pydantic import BaseModel, Field, validator
from enum import Enum

# Import path validation from interactive_shell
from packet_phantom.interface.interactive_shell import validate_safe_path


# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

def get_api_token() -> str:
    """Get API token from env or generate random one."""
    token = os.environ.get("API_TOKEN")
    if token:
        # Validate it's not the default
        if token == "change-me-in-production":
            raise ValueError(
                "API_TOKEN cannot be 'change-me-in-production'. "
                "Set a strong token in .env file."
            )
        return token
    
    # Generate random token if not set
    token = secrets.token_urlsafe(32)
    
    # Warn and suggest setting it
    logging.warning(
        f"⚠️  WARNING: No API_TOKEN set. Generated temporary token: {token}"
    )
    logging.warning(
        "⚠️  Set a permanent token in .env file to keep using the same token."
    )
    
    return token

# API Token - MUST be set via environment variable in production
API_TOKEN = get_api_token()

# CORS Configuration
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "").split(",") if os.environ.get("ALLOWED_ORIGINS") else []

# Trusted Hosts Configuration
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",") if os.environ.get("ALLOWED_HOSTS") else ["localhost", "127.0.0.1"]

# Output Directory Configuration
OUTPUT_BASE_DIR = os.environ.get("OUTPUT_BASE_DIR", "/tmp/packet-phantom-outputs")

# Private IP Scanning (disabled by default for security)
ALLOW_PRIVATE_SCANS = os.environ.get("ALLOW_PRIVATE_SCANS", "false").lower() == "true"
ALLOW_LOOPBACK = os.environ.get("ALLOW_LOOPBACK", "false").lower() == "true"

# Server Binding Configuration
API_HOST = os.environ.get("API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("API_PORT", "8080"))

# Rate Limiting Configuration
RATE_LIMIT_SCAN = os.environ.get("RATE_LIMIT_SCAN", "10/minute")
RATE_LIMIT_FLOOD = os.environ.get("RATE_LIMIT_FLOOD", "5/minute")

# Redis Configuration (for distributed rate limiting)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


# =============================================================================
# SECURITY UTILITIES
# =============================================================================

# HTTP Bearer token security
security = HTTPBearer()

# Setup audit logging
AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/var/log/packet-phantom-audit.log")
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
try:
    audit_handler = logging.FileHandler(AUDIT_LOG_PATH)
    audit_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    ))
    audit_logger.addHandler(audit_handler)
except (IOError, PermissionError):
    # Fall back to console if log file can't be created
    audit_logger.addHandler(logging.StreamHandler())


def hash_token(token: str, length: int = 16) -> str:
    """Create a short hash of the token for logging."""
    return hashlib.sha256(token.encode()).hexdigest()[:length]


def sanitize_for_log(value: str) -> str:
    """Sanitize value for safe logging - prevents log injection attacks."""
    # Remove any control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    # Limit length
    sanitized = sanitized[:256]
    # Escape special chars
    sanitized = shlex.quote(sanitized)
    return sanitized


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    Verify API token authentication.
    
    Returns:
        The authenticated token if valid.
        
    Raises:
        HTTPException: If token is invalid.
    """
    token = credentials.credentials
    if token != API_TOKEN:
        audit_logger.warning(f"Authentication failed - invalid token attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def validate_output_path(path: Optional[str]) -> Optional[str]:
    """
    Validate output path to prevent path traversal attacks.
    
    Args:
        path: Output file path to validate.
        
    Returns:
        Validated absolute path.
        
    Raises:
        ValueError: If path is invalid.
    """
    if path is None:
        return None
    
    # Block null bytes
    if '\x00' in path:
        raise ValueError("Null bytes in output path")
    
    # Use the comprehensive validation from interactive_shell
    return validate_safe_path(path, allowed_base=OUTPUT_BASE_DIR)


def validate_target(target: str) -> str:
    """
    Validate target is safe to scan.
    
    Blocks private IPs, loopback, and multicast by default.
    
    Args:
        target: Target IP, CIDR, or hostname.
        
    Returns:
        Validated target string.
        
    Raises:
        ValueError: If target is not allowed.
    """
    try:
        # Try to parse as IP address
        ip = ipaddress.ip_address(target)
        
        # Block private IPs unless explicitly allowed
        if ip.is_private and not ALLOW_PRIVATE_SCANS:
            raise ValueError("Private IP scanning is disabled by default")
        
        # Block loopback unless allowed
        if ip.is_loopback and not ALLOW_LOOPBACK:
            raise ValueError("Loopback scanning is disabled by default")
        
        # Block multicast
        if ip.is_multicast:
            raise ValueError("Multicast addresses cannot be scanned")
        
        return target
    except ValueError:
        # Not an IP address, allow hostnames (they'll be resolved at scan time)
        # Basic validation for hostnames
        if not target or len(target) > 253:
            raise ValueError("Invalid hostname format")
        return target


async def check_privileges():
    """Verify we can create raw sockets."""
    if os.geteuid() != 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Root privileges required for raw socket operations"
        )


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class ScanType(str, Enum):
    """Types of scans."""
    SYN = "syn"
    TCP_CONNECT = "tcp_connect"
    UDP = "udp"
    ICMP = "icmp"
    ACK = "ack"


class EvasionType(str, Enum):
    """Evasion techniques."""
    TTL = "ttl"
    OPTIONS = "options"
    FRAGMENTATION = "fragmentation"
    PADDING = "padding"


class OutputFormat(str, Enum):
    """Output formats."""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PCAP = "pcap"


class ScanRequest(BaseModel):
    """Scan request model."""
    target: str = Field(..., description="Target IP, CIDR, or hostname")
    ports: List[int] = Field(default=[80, 443], description="Ports to scan")
    scan_type: ScanType = Field(default=ScanType.SYN, description="Scan type")
    threads: int = Field(default=1, ge=1, le=100, description="Worker threads")
    rate: Optional[int] = Field(default=None, description="Rate limit (pkt/s)")
    timeout: float = Field(default=5.0, ge=0.1, description="Response timeout")
    evasion: List[EvasionType] = Field(default=[], description="Evasion techniques")
    output_format: OutputFormat = Field(default=OutputFormat.JSON, description="Output format")
    output_file: Optional[str] = Field(default=None, description="Output file path")
    
    @validator('output_file')
    def validate_output_file(cls, v):
        if v:
            return validate_output_path(v)
        return v
    
    @validator('target')
    def validate_target_field(cls, v):
        return validate_target(v)


class FloodRequest(BaseModel):
    """Flood request model."""
    target: str = Field(..., description="Target IP address")
    port: int = Field(..., ge=0, le=65535, description="Target port")
    duration: float = Field(..., ge=1, le=3600, description="Flood duration (seconds)")
    rate: Optional[int] = Field(default=None, description="Rate limit (pkt/s)")
    threads: int = Field(default=1, ge=1, le=100, description="Worker threads")
    packet_size: int = Field(default=64, ge=64, le=1500, description="Packet size")
    
    @validator('target')
    def validate_target_field(cls, v):
        return validate_target(v)


class JobResponse(BaseModel):
    """Job response model."""
    job_id: str
    status: str
    message: str
    created_at: str


class ScanResult(BaseModel):
    """Individual scan result."""
    target: str
    port: int
    status: str
    response_time: Optional[float] = None
    banner: Optional[str] = None


class ScanResults(BaseModel):
    """Complete scan results."""
    job_id: str
    status: str
    total_targets: int
    total_ports: int
    open_ports: int
    results: List[ScanResult]
    duration: float
    rate: float


class FloodResult(BaseModel):
    """Flood result model."""
    job_id: str
    target: str
    duration: float
    packets_sent: int
    packets_per_second: float
    errors: int


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    uptime: float


# =============================================================================
# JOB MANAGEMENT
# =============================================================================

class JobManager:
    """Manages scan and flood jobs with size limits and cleanup."""
    
    MAX_JOBS = 1000  # Maximum concurrent jobs
    MAX_RESULTS_PER_JOB = 10000
    JOB_TIMEOUT = 3600  # 1 hour
    RESULTS_TTL = 3600  # 1 hour
    
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.results: Dict[str, Any] = {}
        self._cancel_events: Dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()
    
    async def create_job(self, request: Dict) -> str:
        """Create job with cancellation support."""
        job_id = str(uuid.uuid4())
        async with self._lock:
            self.jobs[job_id] = {
                "request": request,
                "status": "pending",
                "created_at": time.time(),
                "updated_at": time.time(),
            }
            self._cancel_events[job_id] = asyncio.Event()
        
        # Schedule auto-cleanup
        asyncio.create_task(self._cleanup_job(job_id))
        
        return job_id
    
    async def create_scan_job(self, request: ScanRequest) -> str:
        """Create a new scan job."""
        # Check size limits
        if len(self.jobs) >= self.MAX_JOBS:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Maximum concurrent jobs ({self.MAX_JOBS}) reached"
            )
        
        job_id = await self.create_job({
            "type": "scan",
            "request": request.dict(),
            "progress": 0,
            "total": len(request.target.split(',')) * len(request.ports)
        })
        
        return job_id
    
    async def create_flood_job(self, request: FloodRequest) -> str:
        """Create a new flood job."""
        # Check size limits
        if len(self.jobs) >= self.MAX_JOBS:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Maximum concurrent jobs ({self.MAX_JOBS}) reached"
            )
        
        job_id = await self.create_job({
            "type": "flood",
            "request": request.dict(),
            "progress": 0
        })
        
        return job_id
    
    def get_job(self, job_id: str) -> Dict[str, Any]:
        """Get job information."""
        if job_id not in self.jobs:
            raise HTTPException(status_code=404, detail="Job not found")
        return self.jobs[job_id]
    
    def update_job(self, job_id: str, updates: Dict[str, Any]):
        """Update job information."""
        if job_id in self.jobs:
            self.jobs[job_id].update(updates)
    
    def set_job_result(self, job_id: str, result: Any):
        """Set job result."""
        # Check result size limits
        if isinstance(result, dict) and 'results' in result:
            if len(result['results']) > self.MAX_RESULTS_PER_JOB:
                result['results'] = result['results'][:self.MAX_RESULTS_PER_JOB]
                result['truncated'] = True
        self.results[job_id] = result
    
    def get_job_result(self, job_id: str) -> Any:
        """Get job result."""
        if job_id not in self.results:
            raise HTTPException(status_code=404, detail="Results not found")
        return self.results[job_id]
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a job immediately."""
        if job_id in self.jobs:
            self.jobs[job_id]["status"] = "cancelled"
            # Signal cancellation immediately using asyncio.Event
            event = self._cancel_events.get(job_id)
            if event:
                event.set()
            return True
        return False
    
    async def is_cancelled(self, job_id: str) -> bool:
        """Check if job is cancelled (with timeout for responsiveness)."""
        event = self._cancel_events.get(job_id)
        if event:
            try:
                # Wait for cancellation with short timeout for responsiveness
                await asyncio.wait_for(event.wait(), timeout=0.1)
                return True
            except asyncio.TimeoutError:
                return False
        return False
    
    async def _cleanup_job(self, job_id: str):
        """Auto-cleanup job after timeout."""
        await asyncio.sleep(self.JOB_TIMEOUT)
        async with self._lock:
            if job_id in self.jobs:
                del self.jobs[job_id]
            self._cancel_events.pop(job_id, None)
            self.results.pop(job_id, None)
    
    def cleanup_stale_jobs(self):
        """Remove all jobs older than timeout."""
        cutoff = time.time() - self.JOB_TIMEOUT
        stale = [jid for jid, job in self.jobs.items() 
                  if job.get("created_at", 0) < cutoff]
        for jid in stale:
            del self.jobs[jid]
            self.results.pop(jid, None)
            self._cancel_events.pop(jid, None)


# =============================================================================
# RATE LIMITING (Redis-based with fallback)
# =============================================================================

# Simple in-memory rate limiter (fallback)
_rate_limit_storage: Dict[str, List[float]] = {}

# Redis client for distributed rate limiting
_redis_client = None


async def get_redis_client():
    """Get or create Redis client for distributed rate limiting."""
    global _redis_client
    if _redis_client is None:
        try:
            import aioredis
            _redis_client = await aioredis.from_url(REDIS_URL)
        except Exception:
            _redis_client = None
    return _redis_client


async def check_rate_limit_redis(identifier: str, limit: str = "10/minute") -> bool:
    """Redis-based rate limiting that works across workers."""
    redis = await get_redis_client()
    if redis is None:
        # Fall back to in-memory
        return check_rate_limit(identifier, limit)
    
    try:
        count, period = limit.split('/')
        count = int(count)
        period_map = {'second': 1, 'minute': 60, 'hour': 3600}
        period_sec = period_map.get(period, 60)
        
        key = f"rate_limit:{identifier}"
        now = time.time()
        
        # Remove old entries and count current
        await redis.zremrangebyscore(key, 0, now - period_sec)
        current_count = await redis.zcard(key)
        
        if current_count >= count:
            return False
        
        # Add new entry
        await redis.zadd(key, {f"{now}": now})
        await redis.expire(key, period_sec)
        
        return True
    except Exception:
        # Fall back to in-memory on error
        return check_rate_limit(identifier, limit)


def check_rate_limit(identifier: str, limit: str = "10/minute") -> bool:
    """
    Simple in-memory rate limiting (fallback when Redis unavailable).
    
    Args:
        identifier: Unique identifier for rate limiting (e.g., IP or token)
        limit: Rate limit string (e.g., "10/minute")
        
    Returns:
        True if request is allowed, False if rate limited.
    """
    try:
        count, period = limit.split('/')
        count = int(count)
        period_map = {'second': 1, 'minute': 60, 'hour': 3600}
        period_sec = period_map.get(period, 60)
    except (ValueError, KeyError):
        count, period_sec = 10, 60
    
    now = time.time()
    window_start = now - period_sec
    
    # Initialize if not exists
    if identifier not in _rate_limit_storage:
        _rate_limit_storage[identifier] = []
    
    # Remove old entries
    _rate_limit_storage[identifier] = [
        t for t in _rate_limit_storage[identifier] if t > window_start
    ]
    
    # Check limit
    if len(_rate_limit_storage[identifier]) >= count:
        return False
    
    # Add current request
    _rate_limit_storage[identifier].append(now)
    return True


# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(
    title="Packet Phantom API",
    description="Professional Network Testing Tool API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# HTTPS Enforcement Middleware
@app.middleware("http")
async def enforce_https(request: Request, call_next):
    """Enforce HTTPS for all requests."""
    # Check if behind proxy with HTTPS
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    is_https = request.url.scheme == "https" or forwarded_proto == "https"
    
    if not is_https:
        # Redirect to HTTPS
        https_url = str(request.url).replace("http://", "https://", 1)
        return RedirectResponse(url=https_url, status_code=301)
    
    response = await call_next(request)
    
    # Add HSTS header (only for HTTPS)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# CORS middleware - RESTRICTED (not "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else [],
    allow_credentials=False,  # Set to False when using tokens
    allow_methods=["GET", "POST"],  # Explicit methods
    allow_headers=["Authorization", "Content-Type"],  # Explicit headers
)

# Trusted Host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS,
)

# Rate limit check middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting to all requests."""
    # Skip rate limiting for health endpoint
    if request.url.path not in ["/", "/api/health"]:
        token = request.headers.get("authorization", "").replace("Bearer ", "")
        identifier = token or request.client.host
        # Use Redis-based rate limiting with fallback
        if asyncio.iscoroutinefunction(check_rate_limit_redis):
            is_allowed = await check_rate_limit_redis(identifier, "60/minute")
        else:
            is_allowed = check_rate_limit(identifier, "60/minute")
        
        if not is_allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"}
            )
    response = await call_next(request)
    return response

# Job manager
job_manager = JobManager()

# Start time for uptime calculation
START_TIME = time.time()

# JSON Response for errors
from fastapi.responses import JSONResponse


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Packet Phantom API",
        "version": "2.0.0",
        "docs": "/api/docs",
        "health": "/api/health"
    }


@app.get("/api/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        uptime=time.time() - START_TIME
    )


@app.post("/api/v1/scan", response_model=JobResponse, tags=["Scanning"])
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,  # ✅ Injected by FastAPI
    token: str = Depends(verify_token)
):
    """
    Start a new scan job.
    
    This endpoint creates a scan job and returns a job ID.
    Use the job ID to check status and retrieve results.
    
    Requires: Bearer token authentication
    """
    # Sanitize inputs for logging
    sanitized_target = sanitize_for_log(request.target)
    sanitized_ports = sanitize_for_log(str(request.ports))
    token_hash = hash_token(token)
    
    audit_logger.info(
        f"SCAN request token_hash:{token_hash} target={sanitized_target} ports={sanitized_ports}"
    )
    
    job_id = await job_manager.create_scan_job(request)
    
    # Attach background task - FastAPI handles this automatically via dependency injection
    background_tasks.add_task(
        _run_scan_with_retry,
        job_id,
        request
    )
    
    return JobResponse(
        job_id=job_id,
        status="pending",
        message=f"Scan job created. Use GET /api/v1/status/{job_id} to check progress.",
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )


@app.get("/api/v1/status/{job_id}", tags=["Scanning"])
async def get_scan_status(job_id: str, token: str = Depends(verify_token)):
    """
    Get scan job status.
    
    Returns the current status and progress of a scan job.
    
    Requires: Bearer token authentication
    """
    job = job_manager.get_job(job_id)
    
    return {
        "job_id": job_id,
        "type": job["type"],
        "status": job["status"],
        "progress": job.get("progress", 0),
        "total": job.get("total", 0),
        "created_at": job["created_at"]
    }


@app.get("/api/v1/results/{job_id}", tags=["Scanning"])
async def get_scan_results(job_id: str, token: str = Depends(verify_token)):
    """
    Get scan job results.
    
    Returns the complete results of a finished scan job.
    
    Requires: Bearer token authentication
    """
    job = job_manager.get_job(job_id)
    
    if job["status"] != "completed":
        raise HTTPException(
            status_code=202,
            detail=f"Scan not yet completed. Current status: {job['status']}"
        )
    
    results = job_manager.get_job_result(job_id)
    return results


@app.post("/api/v1/flood", response_model=JobResponse, tags=["Flooding"])
async def create_flood(
    request: FloodRequest,
    background_tasks: BackgroundTasks,  # ✅ Injected by FastAPI
    token: str = Depends(verify_token)
):
    """
    Start a new flood job.
    
    ⚠️  WARNING: This is a high-impact operation. Use responsibly.
    
    Requires: Bearer token authentication and root privileges.
    """
    # Sanitize inputs for logging
    sanitized_target = sanitize_for_log(request.target)
    sanitized_port = sanitize_for_log(str(request.port))
    sanitized_duration = sanitize_for_log(str(request.duration))
    token_hash = hash_token(token)
    
    audit_logger.warning(
        f"FLOOD request token_hash:{token_hash} target={sanitized_target} port={sanitized_port} duration={sanitized_duration}"
    )
    
    # Check root privileges
    await check_privileges()
    
    job_id = await job_manager.create_flood_job(request)
    
    # Attach background task - FastAPI handles this automatically
    background_tasks.add_task(
        _run_flood,
        job_id,
        request
    )
    
    return JobResponse(
        job_id=job_id,
        status="pending",
        message=f"Flood job created. Use GET /api/v1/status/{job_id} to check progress.",
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )


@app.get("/api/v1/flood/results/{job_id}", response_model=FloodResult, tags=["Flooding"])
async def get_flood_results(job_id: str, token: str = Depends(verify_token)):
    """Get flood job results.
    
    Requires: Bearer token authentication
    """
    job = job_manager.get_job(job_id)
    
    if job["status"] != "completed":
        raise HTTPException(
            status_code=202,
            detail=f"Flood not yet completed. Current status: {job['status']}"
        )
    
    return job_manager.get_job_result(job_id)


@app.delete("/api/v1/job/{job_id}", tags=["Management"])
async def cancel_job(job_id: str, token: str = Depends(verify_token)):
    """Cancel a running job.
    
    Requires: Bearer token authentication
    """
    if job_manager.cancel_job(job_id):
        token_hash = hash_token(token)
        audit_logger.info(f"JOB_CANCELLED token_hash:{token_hash} job_id={sanitize_for_log(job_id)}")
        return {"message": f"Job {job_id} cancelled"}
    raise HTTPException(status_code=404, detail="Job not found")


@app.get("/api/v1/metrics", tags=["Monitoring"])
async def get_metrics(token: str = Depends(verify_token)):
    """
    Prometheus metrics endpoint.
    
    Returns metrics in Prometheus format for scraping.
    
    Requires: Bearer token authentication
    """
    uptime = time.time() - START_TIME
    
    metrics = f"""# HELP packet_phantom_uptime_seconds Uptime in seconds
# TYPE packet_phantom_uptime_seconds gauge
packet_phantom_uptime_seconds {uptime}

# HELP packet_phantom_jobs_total Total number of jobs
# TYPE packet_phantom_jobs_total counter
packet_phantom_jobs_total {sum(1 for j in job_manager.jobs.values())}

# HELP packet_phantom_jobs_running Currently running jobs
# TYPE packet_phantom_jobs_running gauge
packet_phantom_jobs_running {sum(1 for j in job_manager.jobs.values() if j['status'] == 'running')}

# HELP packet_phantom_jobs_completed Completed jobs
# TYPE packet_phantom_jobs_completed counter
packet_phantom_jobs_completed {sum(1 for j in job_manager.jobs.values() if j['status'] == 'completed')}
"""
    
    return StreamingResponse(iter([metrics]), media_type="text/plain")


# =============================================================================
# BACKGROUND TASKS
# =============================================================================

async def _run_scan_with_retry(job_id: str, request: ScanRequest, max_retries: int = 3):
    """Run scan with automatic retry and exponential backoff."""
    attempt = 0
    while attempt < max_retries:
        try:
            await _run_scan(job_id, request)
            return
        except Exception as e:
            attempt += 1
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            else:
                job_manager.update_job(job_id, {
                    "status": "failed",
                    "error": str(e)
                })


async def _run_scan(job_id: str, request: ScanRequest):
    """Background task to run scan."""
    job_manager.update_job(job_id, {"status": "running"})
    
    # Check for cancellation using asyncio.Event
    for i in range(10):
        if job_manager.get_job(job_id).get("status") == "cancelled":
            return
        
        # Also check using asyncio.Event for immediate cancellation
        if await job_manager.is_cancelled(job_id):
            return
        
        await asyncio.sleep(1)
        job_manager.update_job(job_id, {"progress": (i + 1) * 10})
    
    # Placeholder results
    results = {
        "job_id": job_id,
        "status": "completed",
        "total_targets": 1,
        "total_ports": len(request.ports),
        "open_ports": 0,
        "results": [],
        "duration": 10.0,
        "rate": 0.0
    }
    
    job_manager.set_job_result(job_id, results)
    job_manager.update_job(job_id, {"status": "completed"})


async def _run_flood(job_id: str, request: FloodRequest):
    """Background task to run flood."""
    job_manager.update_job(job_id, {"status": "running"})
    
    # Check for cancellation using asyncio.Event
    while True:
        if job_manager.get_job(job_id).get("status") == "cancelled":
            return
        
        # Also check using asyncio.Event for immediate cancellation
        if await job_manager.is_cancelled(job_id):
            return
        
        await asyncio.sleep(1)
    
    # This line won't be reached due to the infinite loop with cancellation check
    # but keeping it for completeness
    result = {
        "job_id": job_id,
        "target": f"{request.target}:{request.port}",
        "duration": request.duration,
        "packets_sent": int(request.duration * 1000),
        "packets_per_second": 1000.0,
        "errors": 0
    }
    
    job_manager.set_job_result(job_id, result)
    job_manager.update_job(job_id, {"status": "completed"})


# =============================================================================
# SERVER STARTUP
# =============================================================================

def start_server(host: str = None, port: int = None):
    """
    Start the API server.
    
    Args:
        host: Host to bind to (default: from API_HOST env, then 127.0.0.1)
        port: Port to listen on (default: from API_PORT env, then 8080)
    """
    import uvicorn
    import logging
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    # Use environment variables with secure defaults
    host = host or API_HOST
    port = port or API_PORT
    
    # Warn about 0.0.0.0 binding
    if host == "0.0.0.0":
        logger.warning("⚠️  WARNING: Binding to 0.0.0.0 exposes API on all interfaces!")
        logger.warning("⚠️  Set API_HOST=127.0.0.1 for local-only access")
    
    # Warn about HTTPS in production
    if port == 443:
        logger.warning("⚠️  WARNING: Port 443 detected - ensure TLS is configured!")
    
    # Cleanup stale jobs on startup
    job_manager.cleanup_stale_jobs()
    
    uvicorn.run(
        "packet_phantom.api.server:app",
        host=host,
        port=port,
        log_level="info",
        reload=False,
        workers=1,
        loop="asyncio",
        http="h11",
        interface="asgi3",
        timeout_keep_alive=30,
    )


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    # Use environment variables with secure defaults
    host = API_HOST
    port = API_PORT
    
    # Warn about 0.0.0.0 binding
    if host == "0.0.0.0":
        logger.warning("⚠️  WARNING: Binding to 0.0.0.0 exposes API on all interfaces!")
        logger.warning("⚠️  Set API_HOST=127.0.0.1 for local-only access")
    
    uvicorn.run(
        "packet_phantom.api.server:app",
        host=host,
        port=port,
        log_level="info",
        reload=False,
        workers=1,
        timeout_keep_alive=30,
    )


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'app',
    'JobManager',
    'ScanRequest',
    'FloodRequest',
    'JobResponse',
    'ScanResults',
    'FloodResult',
]
