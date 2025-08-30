from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict, List, Tuple
import time
import re
import logging
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Security middleware to protect against common attacks and suspicious requests.
    """
    
    def __init__(self, app, 
                 rate_limit_per_minute: int = 60,
                 rate_limit_per_hour: int = 600,
                 block_duration_minutes: int = 30):
        super().__init__(app)
        self.rate_limit_per_minute = rate_limit_per_minute
        self.rate_limit_per_hour = rate_limit_per_hour
        self.block_duration_minutes = block_duration_minutes
        
        # Request tracking
        self.request_counts: Dict[str, List[float]] = defaultdict(list)
        self.blocked_ips: Dict[str, datetime] = {}
        
        # Suspicious patterns to block
        self.suspicious_patterns = [
            r'\.env',
            r'\.git/',
            r'\.aws/',
            r'\.ssh/',
            r'\.config/',
            r'wp-admin',
            r'wp-login',
            r'phpMyAdmin',
            r'\.php$',
            r'\.asp$',
            r'\.cgi$',
            r'\.\./\.\.',  # Directory traversal
            r'<script',     # XSS attempts
            r'SELECT.*FROM',  # SQL injection
            r'UNION.*SELECT', # SQL injection
            r'INSERT.*INTO',  # SQL injection
            r'UPDATE.*SET',   # SQL injection
            r'DELETE.*FROM',  # SQL injection
            r'DROP.*TABLE',   # SQL injection
            r'eval\(',        # Code injection
            r'exec\(',        # Code injection
            r'system\(',      # Command injection
            r'cmd=',          # Command injection
            r'passwd',        # Sensitive files
            r'shadow',        # Sensitive files
            r'htpasswd',      # Sensitive files
            r'id_rsa',        # SSH keys
            r'id_dsa',        # SSH keys
            r'authorized_keys', # SSH keys
            r'\.pem$',        # Certificates
            r'\.key$',        # Private keys
            r'\.sqlite',      # Database files
            r'\.db$',         # Database files
            r'backup',        # Backup files
            r'\.bak$',        # Backup files
            r'\.old$',        # Old files
            r'\.swp$',        # Vim swap files
            r'~$',            # Editor backup files
        ]
        
        # Compile patterns for efficiency
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                 for pattern in self.suspicious_patterns]
    
    def get_client_ip(self, request: Request) -> str:
        """Extract client IP from request headers."""
        # Check for proxy headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
            
        # Fallback to direct connection
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        if ip in self.blocked_ips:
            block_time = self.blocked_ips[ip]
            if datetime.now() < block_time + timedelta(minutes=self.block_duration_minutes):
                return True
            else:
                # Unblock if duration has passed
                del self.blocked_ips[ip]
        return False
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, str]:
        """Check if IP has exceeded rate limits."""
        now = time.time()
        
        # Clean old requests
        self.request_counts[ip] = [
            timestamp for timestamp in self.request_counts[ip]
            if now - timestamp < 3600  # Keep last hour
        ]
        
        # Add current request
        self.request_counts[ip].append(now)
        
        # Check per-minute limit
        recent_minute = [t for t in self.request_counts[ip] if now - t < 60]
        if len(recent_minute) > self.rate_limit_per_minute:
            return False, f"Rate limit exceeded: {len(recent_minute)} requests per minute"
        
        # Check per-hour limit
        if len(self.request_counts[ip]) > self.rate_limit_per_hour:
            return False, f"Rate limit exceeded: {len(self.request_counts[ip])} requests per hour"
        
        return True, ""
    
    def is_suspicious_request(self, request: Request) -> Tuple[bool, str]:
        """Check if request contains suspicious patterns."""
        # Check URL path
        path = request.url.path
        query = str(request.url.query) if request.url.query else ""
        full_url = path + "?" + query if query else path
        
        for pattern in self.compiled_patterns:
            if pattern.search(full_url):
                return True, f"Suspicious pattern detected: {pattern.pattern}"
        
        # Check headers for suspicious content
        suspicious_headers = ['X-Forwarded-Host', 'X-Original-URL', 'X-Rewrite-URL']
        for header in suspicious_headers:
            if header in request.headers:
                value = request.headers[header]
                for pattern in self.compiled_patterns:
                    if pattern.search(value):
                        return True, f"Suspicious header {header}: {pattern.pattern}"
        
        # Check user agent
        user_agent = request.headers.get("User-Agent", "")
        suspicious_agents = ['sqlmap', 'nikto', 'scanner', 'nessus', 'vulnerability']
        for agent in suspicious_agents:
            if agent.lower() in user_agent.lower():
                return True, f"Suspicious user agent: {agent}"
        
        return False, ""
    
    async def dispatch(self, request: Request, call_next):
        """Process each request through security checks."""
        ip = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip):
            logger.warning(f"Blocked IP attempted access: {ip} to {request.url.path}")
            return JSONResponse(
                status_code=403,
                content={"detail": "Access forbidden"}
            )
        
        # Check for suspicious patterns
        is_suspicious, reason = self.is_suspicious_request(request)
        if is_suspicious:
            logger.warning(f"Suspicious request from {ip}: {reason} - Path: {request.url.path}")
            self.blocked_ips[ip] = datetime.now()
            return JSONResponse(
                status_code=403,
                content={"detail": "Suspicious request detected"}
            )
        
        # Check rate limits
        within_limit, message = self.check_rate_limit(ip)
        if not within_limit:
            logger.warning(f"Rate limit exceeded for {ip}: {message}")
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"}
            )
        
        # Process legitimate request
        response = await call_next(request)
        return response