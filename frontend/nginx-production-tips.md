# Nginx Reverse Proxy Production Deployment Guide

## Environment Variable Configuration

### Using envsubst for Dynamic Configuration
```bash
# Template file: nginx.conf.template
upstream backend_service {
    server ${BACKEND_HOST}:${BACKEND_PORT};
}

# Deployment script
export BACKEND_HOST=backend.example.com
export BACKEND_PORT=5000
envsubst '$BACKEND_HOST $BACKEND_PORT' < nginx.conf.template > /etc/nginx/nginx.conf
nginx -s reload
```

### Docker Environment Variables
```dockerfile
# Dockerfile
FROM nginx:alpine
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
# Nginx Docker image automatically processes templates with envsubst
```

## Common Pitfalls to Avoid

### 1. Header Duplication
```nginx
# WRONG - Headers get duplicated
location /api/ {
    proxy_pass http://backend;
    add_header Access-Control-Allow-Origin *;  # Backend also adds this
}

# CORRECT - Let backend handle CORS
location /api/ {
    proxy_pass http://backend;
    # Backend handles CORS headers
}
```

### 2. Trailing Slash Issues
```nginx
# These behave differently:
proxy_pass http://backend;      # Preserves /api/ prefix
proxy_pass http://backend/;     # Removes /api/ prefix

# Example with /api/users request:
proxy_pass http://backend;      # → http://backend/api/users
proxy_pass http://backend/;     # → http://backend/users
```

### 3. Buffer Size Misconfigurations
```nginx
# WRONG - Too small buffers cause issues
proxy_buffer_size 1k;           # Too small for headers
proxy_buffers 4 1k;             # Too small for response

# CORRECT - Reasonable defaults
proxy_buffer_size 4k;
proxy_buffers 8 4k;
proxy_busy_buffers_size 8k;
```

### 4. Timeout Misalignment
```nginx
# WRONG - Frontend timeout shorter than backend
proxy_read_timeout 30s;         # Nginx times out
# Backend process takes 60s     # Backend still processing

# CORRECT - Align timeouts
proxy_read_timeout 65s;         # Slightly longer than backend
# Backend timeout at 60s
```

### 5. WebSocket Connection Issues
```nginx
# WRONG - Missing upgrade headers
location /ws/ {
    proxy_pass http://backend;
}

# CORRECT - Proper WebSocket configuration
location /ws/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

## Security Best Practices

### 1. Rate Limiting Implementation
```nginx
# At http level
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

# In location block
location /api/ {
    limit_req zone=api burst=20 nodelay;
    limit_req_status 429;
    # Return JSON error for API endpoints
    error_page 429 @rate_limit_error;
}

location @rate_limit_error {
    default_type application/json;
    return 429 '{"error":"Too many requests","retry_after":60}';
}
```

### 2. IP Whitelisting for Admin Endpoints
```nginx
location /api/admin/ {
    # Only allow specific IPs
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;

    proxy_pass http://backend;
    # ... other proxy settings
}
```

### 3. Request Method Restrictions
```nginx
location /api/ {
    # Only allow specific methods
    limit_except GET POST PUT DELETE {
        deny all;
    }
    proxy_pass http://backend;
}
```

### 4. Preventing Common Attacks
```nginx
# Block SQL injection attempts
if ($request_uri ~* "(.*)(\.|%2e)(\.|%2e)(.*)") {
    return 403;
}

if ($request_uri ~* "union.*select|select.*from|insert.*into") {
    return 403;
}

# Block script injections
if ($request_uri ~* "(<|%3C).*script.*(>|%3E)") {
    return 403;
}

# Block access to hidden files
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}
```

### 5. SSL/TLS Configuration (Production)
```nginx
server {
    listen 443 ssl http2;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # SSL session caching
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Redirect HTTP to HTTPS
    if ($scheme != "https") {
        return 301 https://$server_name$request_uri;
    }
}
```

## Monitoring and Logging

### Access Log Format for Analytics
```nginx
log_format api_analytics '$remote_addr - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent" '
                         'rt=$request_time uct="$upstream_connect_time" '
                         'uht="$upstream_header_time" urt="$upstream_response_time"';

access_log /var/log/nginx/api_access.log api_analytics buffer=32k;
```

### Error Detection
```nginx
# Log upstream errors
location /api/ {
    proxy_pass http://backend;
    proxy_intercept_errors on;

    # Custom error handling
    error_page 502 503 504 @backend_error;
}

location @backend_error {
    default_type application/json;
    return 503 '{"error":"Service temporarily unavailable","details":"Backend service error"}';
}
```

## Performance Optimizations

### 1. Connection Pooling
```nginx
upstream backend_service {
    server backend1:5000;
    server backend2:5000;

    # Keep connections alive
    keepalive 32;
    keepalive_timeout 60s;
    keepalive_requests 100;
}

location /api/ {
    proxy_pass http://backend_service;
    proxy_http_version 1.1;
    proxy_set_header Connection "";  # Required for keepalive
}
```

### 2. Caching Strategy
```nginx
# Cache GET requests
location /api/ {
    proxy_pass http://backend;

    # Cache configuration
    proxy_cache api_cache;
    proxy_cache_valid 200 10m;
    proxy_cache_valid 404 1m;
    proxy_cache_key "$scheme$request_method$host$request_uri";

    # Don't cache authenticated requests
    proxy_cache_bypass $http_authorization;
    proxy_no_cache $http_authorization;

    # Add cache status header
    add_header X-Cache-Status $upstream_cache_status;
}
```

### 3. Compression
```nginx
# Enable gzip for API responses
location /api/ {
    proxy_pass http://backend;

    # Compress JSON responses
    gzip on;
    gzip_types application/json;
    gzip_min_length 1000;
    gzip_proxied any;
}
```

## Health Checks and Monitoring

### Active Health Checks (Nginx Plus)
```nginx
upstream backend_service {
    zone backend 64k;
    server backend1:5000;
    server backend2:5000;
}

# Health check configuration
location @health_check {
    internal;
    proxy_pass http://backend_service/health;
    health_check interval=5s fails=3 passes=2;
}
```

### Passive Health Checks (Open Source Nginx)
```nginx
upstream backend_service {
    server backend1:5000 max_fails=3 fail_timeout=30s;
    server backend2:5000 max_fails=3 fail_timeout=30s;
}
```

## Testing Configuration

### Configuration Validation
```bash
# Test configuration before applying
nginx -t

# Test with specific config file
nginx -t -c /etc/nginx/nginx.conf

# Reload without downtime
nginx -s reload
```

### Load Testing Considerations
```nginx
# Increase limits for load testing
events {
    worker_connections 4096;  # Default is often 1024
}

http {
    # Increase keepalive for persistent connections
    keepalive_timeout 65;
    keepalive_requests 1000;

    # Increase buffer sizes
    client_body_buffer_size 128k;
    client_max_body_size 10m;
}
```