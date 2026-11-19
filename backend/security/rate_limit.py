"""In-memory rate limiting for API endpoints"""
import logging
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Optional, Callable
from flask import request, jsonify

logger = logging.getLogger(__name__)

# Maximum number of unique IPs to track
MAX_TRACKED_IPS = 10000


class RateLimiter:
    """Simple in-memory rate limiter for API endpoints"""

    _SENTINEL = object()

    def __init__(self, app=None):
        """Initialize Rate Limiter"""
        # Store request timestamps per IP and endpoint
        self.requests = defaultdict(lambda: defaultdict(deque))

        # Thread management for graceful shutdown
        self._shutdown_event = threading.Event()
        self._cleanup_thread: Optional[threading.Thread] = None

        # Lock for thread-safe limit overrides
        self._limits_lock = threading.RLock()

        self.default_limits = {
            'per_minute': 60,
            'per_hour': 600,
            'burst': 10  # Max requests in 1 second
        }

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

        self._schedule_cleanup()

    def _get_client_ip(self) -> str:
        """Get client IP address, considering proxies"""
        if request.headers.get('X-Forwarded-For'):
            return request.headers['X-Forwarded-For'].split(',')[0].strip()

        if request.headers.get('X-Real-IP'):
            return request.headers['X-Real-IP']

        return request.remote_addr or 'unknown'

    def _is_rate_limited(self, ip: str, endpoint: str) -> tuple[bool, Optional[str]]:
        """Check if a request should be rate limited"""
        if ip in self.whitelist:
            return False, None

        current_time = time.time()

        limits = self.endpoint_limits.get(endpoint, self.default_limits)

        request_times = self.requests[ip][endpoint]

        cutoff_time = current_time - 3600
        while request_times and request_times[0] < cutoff_time:
            request_times.popleft()

        burst_cutoff = current_time - 1
        burst_count = sum(1 for t in request_times if t > burst_cutoff)
        if burst_count >= limits['burst']:
            return True, f"Burst limit exceeded ({limits['burst']} req/sec)"

        minute_cutoff = current_time - 60
        minute_count = sum(1 for t in request_times if t > minute_cutoff)
        if minute_count >= limits['per_minute']:
            return True, f"Minute limit exceeded ({limits['per_minute']} req/min)"

        hour_cutoff = current_time - 3600
        hour_count = sum(1 for t in request_times if t > hour_cutoff)
        if hour_count >= limits['per_hour']:
            return True, f"Hour limit exceeded ({limits['per_hour']} req/hour)"

        request_times.append(current_time)

        return False, None

    def limit(self, per_minute: Optional[int] = None,
             per_hour: Optional[int] = None,
             burst: Optional[int] = None):
        """Decorator to apply rate limiting to an endpoint"""
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def decorated_function(*args, **kwargs):
                ip = self._get_client_ip()
                endpoint = request.path
                original_limits = self._SENTINEL

                with self._limits_lock:
                    try:
                        if any([per_minute, per_hour, burst]):
                            original_limits = self.endpoint_limits.get(endpoint, self._SENTINEL)
                            self.endpoint_limits[endpoint] = {
                                'per_minute': per_minute or self.default_limits['per_minute'],
                                'per_hour': per_hour or self.default_limits['per_hour'],
                                'burst': burst or self.default_limits['burst']
                            }

                        is_limited, reason = self._is_rate_limited(ip, endpoint)
                    finally:
                        if original_limits is not self._SENTINEL:
                            self.endpoint_limits[endpoint] = original_limits
                        elif any([per_minute, per_hour, burst]):
                            self.endpoint_limits.pop(endpoint, None)

                if is_limited:
                    logger.warning(
                        f"Rate limit exceeded for {ip} on {endpoint}: {reason}"
                    )

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

                return f(*args, **kwargs)

            return decorated_function

        return decorator

    def _get_retry_after(self, ip: str, endpoint: str) -> int:
        """Calculate when client can retry"""
        current_time = time.time()
        request_times = self.requests[ip][endpoint]
        limits = self.endpoint_limits.get(endpoint, self.default_limits)

        burst_cutoff = current_time - 1
        burst_requests = [t for t in request_times if t > burst_cutoff]
        if len(burst_requests) >= limits['burst']:
            return 1

        minute_cutoff = current_time - 60
        minute_requests = [t for t in request_times if t > minute_cutoff]
        if len(minute_requests) >= limits['per_minute']:
            oldest_in_minute = min(minute_requests)
            return int(60 - (current_time - oldest_in_minute)) + 1

        return 60

    def _schedule_cleanup(self):
        """Schedule periodic cleanup of old request data"""
        def cleanup():
            while not self._shutdown_event.is_set():
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

        for ip in list(self.requests.keys()):
            for endpoint in list(self.requests[ip].keys()):
                request_times = self.requests[ip][endpoint]

                while request_times and request_times[0] < cutoff_time:
                    request_times.popleft()

                if not request_times:
                    del self.requests[ip][endpoint]
                    cleaned_endpoints += 1

            if not self.requests[ip]:
                del self.requests[ip]
                cleaned_ips += 1

        current_ip_count = len(self.requests)
        if current_ip_count > MAX_TRACKED_IPS:
            ip_oldest_times = []
            for ip, endpoints in self.requests.items():
                oldest_time = float('inf')
                for deq in endpoints.values():
                    if deq and deq[0] < oldest_time:
                        oldest_time = deq[0]
                ip_oldest_times.append((ip, oldest_time))

            ip_oldest_times.sort(key=lambda x: x[1])
            excess_count = current_ip_count - MAX_TRACKED_IPS
            for ip, _ in ip_oldest_times[:excess_count]:
                del self.requests[ip]
                cleaned_ips += 1

            logger.warning(f"Rate limiter exceeded MAX_TRACKED_IPS, removed {excess_count} oldest entries")

        if cleaned_ips > 0 or cleaned_endpoints > 0:
            logger.debug(f"Rate limiter cleanup: removed {cleaned_ips} IPs, {cleaned_endpoints} endpoints")

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist"""
        self.whitelist.add(ip)
        logger.info(f"Added {ip} to rate limiter whitelist")

    def remove_from_whitelist(self, ip: str):
        """Remove IP from whitelist"""
        self.whitelist.discard(ip)
        logger.info(f"Removed {ip} from rate limiter whitelist")

    def reset_limits(self, ip: Optional[str] = None, endpoint: Optional[str] = None):
        """Reset rate limit counters"""
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