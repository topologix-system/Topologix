"""
In-memory rate limiting for API endpoints
- Simple time-window based rate limiting (no Redis dependency)
- Three-tier limits: burst (per second), per-minute, per-hour
- IP-based tracking with X-Forwarded-For support for reverse proxies
- Endpoint-specific limits with defaults
- Default limits: 60/min, 600/hour, 10 burst
- Login endpoint: 5/min, 20/hour, 2 burst (stricter)
- @limit() decorator for applying custom limits to endpoints
- Automatic cleanup of old entries every 5 minutes
- Whitelist support for trusted IPs
- 429 responses with Retry-After header
- Manual reset functionality for debugging
- Maximum tracked IPs limit to prevent memory growth
"""
import logging
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Optional, Callable
from flask import request, jsonify

logger = logging.getLogger(__name__)

# Maximum number of unique IPs to track to prevent memory bloat
MAX_TRACKED_IPS = 10000


class RateLimiter:
    """Simple in-memory rate limiter for API endpoints"""

    def __init__(self, app=None):
        """Initialize Rate Limiter

        Args:
            app: Flask application instance
        """
        # Store request timestamps per IP and endpoint
        self.requests = defaultdict(lambda: defaultdict(deque))

        # Thread management for graceful shutdown
        self._shutdown_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None

        # Default rate limits
        self.default_limits = {
            'per_minute': 60,
            'per_hour': 600,
            'burst': 10  # Max requests in 1 second
        }

        # Endpoint-specific limits
        self.endpoint_limits = {
            '/api/auth/login': {
                'per_minute': 5,
                'per_hour': 20,
                'burst': 2
            },
            '/api/network/initialize': {
                'per_minute': 10,
                'per_hour': 50,
                'burst': 2
            },
            '/api/snapshots': {
                'per_minute': 30,
                'per_hour': 200,
                'burst': 5
            }
        }

        # Whitelist for trusted IPs (e.g., internal monitoring)
        self.whitelist = set()

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask application for rate limiting"""
        app.rate_limiter = self

        # Add cleanup task for old entries
        self._schedule_cleanup()

    def _get_client_ip(self) -> str:
        """Get client IP address, considering proxies

        Returns:
            Client IP address
        """
        # Check for X-Forwarded-For header (reverse proxy)
        if request.headers.get('X-Forwarded-For'):
            # Take the first IP in the chain
            return request.headers['X-Forwarded-For'].split(',')[0].strip()

        # Check for X-Real-IP header (nginx)
        if request.headers.get('X-Real-IP'):
            return request.headers['X-Real-IP']

        # Fall back to remote_addr
        return request.remote_addr or 'unknown'

    def _is_rate_limited(self, ip: str, endpoint: str) -> tuple[bool, Optional[str]]:
        """Check if a request should be rate limited

        Args:
            ip: Client IP address
            endpoint: API endpoint

        Returns:
            Tuple of (is_limited, reason)
        """
        # Skip rate limiting for whitelisted IPs
        if ip in self.whitelist:
            return False, None

        current_time = time.time()

        # Get limits for this endpoint
        limits = self.endpoint_limits.get(endpoint, self.default_limits)

        # Get request history for this IP and endpoint
        request_times = self.requests[ip][endpoint]

        # Remove old entries (older than 1 hour)
        cutoff_time = current_time - 3600
        while request_times and request_times[0] < cutoff_time:
            request_times.popleft()

        # Check burst limit (requests in last second)
        burst_cutoff = current_time - 1
        burst_count = sum(1 for t in request_times if t > burst_cutoff)
        if burst_count >= limits['burst']:
            return True, f"Burst limit exceeded ({limits['burst']} req/sec)"

        # Check per-minute limit
        minute_cutoff = current_time - 60
        minute_count = sum(1 for t in request_times if t > minute_cutoff)
        if minute_count >= limits['per_minute']:
            return True, f"Minute limit exceeded ({limits['per_minute']} req/min)"

        # Check per-hour limit
        hour_cutoff = current_time - 3600
        hour_count = sum(1 for t in request_times if t > hour_cutoff)
        if hour_count >= limits['per_hour']:
            return True, f"Hour limit exceeded ({limits['per_hour']} req/hour)"

        # Add current request
        request_times.append(current_time)

        return False, None

    def limit(self, per_minute: Optional[int] = None,
             per_hour: Optional[int] = None,
             burst: Optional[int] = None):
        """Decorator to apply rate limiting to an endpoint

        Args:
            per_minute: Requests per minute limit
            per_hour: Requests per hour limit
            burst: Max requests per second

        Returns:
            Decorator function
        """
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated_function(*args, **kwargs):
                ip = self._get_client_ip()
                endpoint = request.path

                # Override limits if specified
                if any([per_minute, per_hour, burst]):
                    original_limits = self.endpoint_limits.get(endpoint)
                    self.endpoint_limits[endpoint] = {
                        'per_minute': per_minute or self.default_limits['per_minute'],
                        'per_hour': per_hour or self.default_limits['per_hour'],
                        'burst': burst or self.default_limits['burst']
                    }

                # Check rate limit
                is_limited, reason = self._is_rate_limited(ip, endpoint)

                if is_limited:
                    logger.warning(
                        f"Rate limit exceeded for {ip} on {endpoint}: {reason}"
                    )

                    # Get retry time
                    retry_after = self._get_retry_after(ip, endpoint)

                    response = jsonify({
                        "status": "error",
                        "message": "Rate limit exceeded",
                        "detail": reason,
                        "retry_after": retry_after
                    })
                    response.status_code = 429
                    response.headers['Retry-After'] = str(retry_after)
                    response.headers['X-RateLimit-Limit'] = str(
                        self.endpoint_limits.get(endpoint, self.default_limits)['per_minute']
                    )

                    return response

                # Restore original limits if they were temporarily overridden
                if any([per_minute, per_hour, burst]) and original_limits:
                    self.endpoint_limits[endpoint] = original_limits

                return f(*args, **kwargs)

            return decorated_function

        return decorator

    def _get_retry_after(self, ip: str, endpoint: str) -> int:
        """Calculate when client can retry

        Args:
            ip: Client IP address
            endpoint: API endpoint

        Returns:
            Seconds until retry is allowed
        """
        current_time = time.time()
        request_times = self.requests[ip][endpoint]
        limits = self.endpoint_limits.get(endpoint, self.default_limits)

        # Check burst window (1 second)
        burst_cutoff = current_time - 1
        burst_requests = [t for t in request_times if t > burst_cutoff]
        if len(burst_requests) >= limits['burst']:
            return 1

        # Check minute window
        minute_cutoff = current_time - 60
        minute_requests = [t for t in request_times if t > minute_cutoff]
        if len(minute_requests) >= limits['per_minute']:
            # Find when the oldest request in the minute window expires
            oldest_in_minute = min(minute_requests)
            return int(60 - (current_time - oldest_in_minute)) + 1

        # Default retry after
        return 60

    def _schedule_cleanup(self):
        """Schedule periodic cleanup of old request data"""
        def cleanup():
            while not self._shutdown_event.is_set():
                # Use wait with timeout instead of sleep for responsive shutdown
                if self._shutdown_event.wait(timeout=300):
                    break
                try:
                    self._cleanup_old_entries()
                except Exception as e:
                    logger.error(f"Error during rate limiter cleanup: {e}")

        self._cleanup_thread = threading.Thread(target=cleanup, daemon=True, name="rate-limiter-cleanup")
        self._cleanup_thread.start()

    def shutdown(self):
        """Gracefully shutdown the cleanup thread"""
        self._shutdown_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
            logger.info("Rate limiter cleanup thread stopped")

    def _cleanup_old_entries(self):
        """Remove old request entries to prevent memory growth"""
        current_time = time.time()
        cutoff_time = current_time - 3600  # 1 hour
        cleaned_ips = 0
        cleaned_endpoints = 0

        # Clean up old requests
        for ip in list(self.requests.keys()):
            for endpoint in list(self.requests[ip].keys()):
                request_times = self.requests[ip][endpoint]

                # Remove old timestamps
                while request_times and request_times[0] < cutoff_time:
                    request_times.popleft()

                # Remove empty endpoint entries
                if not request_times:
                    del self.requests[ip][endpoint]
                    cleaned_endpoints += 1

            # Remove empty IP entries
            if not self.requests[ip]:
                del self.requests[ip]
                cleaned_ips += 1

        # Enforce MAX_TRACKED_IPS limit by removing oldest entries
        current_ip_count = len(self.requests)
        if current_ip_count > MAX_TRACKED_IPS:
            # Get IPs sorted by their oldest request time
            ip_oldest_times = []
            for ip, endpoints in self.requests.items():
                oldest_time = float('inf')
                for deq in endpoints.values():
                    if deq and deq[0] < oldest_time:
                        oldest_time = deq[0]
                ip_oldest_times.append((ip, oldest_time))

            # Sort by oldest time and remove excess
            ip_oldest_times.sort(key=lambda x: x[1])
            excess_count = current_ip_count - MAX_TRACKED_IPS
            for ip, _ in ip_oldest_times[:excess_count]:
                del self.requests[ip]
                cleaned_ips += 1

            logger.warning(f"Rate limiter exceeded MAX_TRACKED_IPS, removed {excess_count} oldest entries")

        if cleaned_ips > 0 or cleaned_endpoints > 0:
            logger.debug(f"Rate limiter cleanup: removed {cleaned_ips} IPs, {cleaned_endpoints} endpoints")

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist

        Args:
            ip: IP address to whitelist
        """
        self.whitelist.add(ip)
        logger.info(f"Added {ip} to rate limiter whitelist")

    def remove_from_whitelist(self, ip: str):
        """Remove IP from whitelist

        Args:
            ip: IP address to remove from whitelist
        """
        self.whitelist.discard(ip)
        logger.info(f"Removed {ip} from rate limiter whitelist")

    def reset_limits(self, ip: Optional[str] = None, endpoint: Optional[str] = None):
        """Reset rate limit counters

        Args:
            ip: Specific IP to reset (None for all)
            endpoint: Specific endpoint to reset (None for all)
        """
        if ip and endpoint:
            if ip in self.requests and endpoint in self.requests[ip]:
                self.requests[ip][endpoint].clear()
        elif ip:
            if ip in self.requests:
                self.requests[ip].clear()
        elif endpoint:
            for ip_requests in self.requests.values():
                if endpoint in ip_requests:
                    ip_requests[endpoint].clear()
        else:
            self.requests.clear()

        logger.info(f"Reset rate limits for IP={ip}, endpoint={endpoint}")