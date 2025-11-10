# Fixed Python 3.11.11 for build reproducibility
FROM python:3.11.11-slim

WORKDIR /app

# Install system dependencies (libmagic for python-magic, gosu for privilege dropping)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 gosu && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies (leverage layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
# Note: Development mode uses volume mount to override this
COPY . .

# Create non-root user (security)
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Pre-create writable directories with proper ownership
# This ensures directories exist with correct permissions
RUN mkdir -p /app/flask_session /app/data /app/logs /tmp/topologix_uploads && \
    chown appuser:appuser /app/flask_session /app/data /app/logs /tmp/topologix_uploads && \
    chmod 755 /app/flask_session /app/data /app/logs /tmp/topologix_uploads

# Create entrypoint script to handle volume permissions
# Runs as root initially to fix permissions, then drops to appuser
RUN echo '#!/bin/sh\n\
set -e\n\
\n\
# Ensure all writable directories exist with proper ownership\n\
# Required when using named volumes or bind mounts\n\
\n\
# Session directory (named volume)\n\
if [ ! -d "/app/flask_session" ]; then\n\
    mkdir -p /app/flask_session\n\
fi\n\
chown -R appuser:appuser /app/flask_session\n\
chmod 755 /app/flask_session\n\
\n\
# Database directory (named volume)\n\
if [ ! -d "/app/data" ]; then\n\
    mkdir -p /app/data\n\
fi\n\
chown -R appuser:appuser /app/data\n\
chmod 755 /app/data\n\
\n\
# Log directory\n\
if [ ! -d "/app/logs" ]; then\n\
    mkdir -p /app/logs\n\
fi\n\
chown -R appuser:appuser /app/logs\n\
chmod 755 /app/logs\n\
\n\
# Upload directory\n\
if [ ! -d "/tmp/topologix_uploads" ]; then\n\
    mkdir -p /tmp/topologix_uploads\n\
fi\n\
chown -R appuser:appuser /tmp/topologix_uploads\n\
chmod 755 /tmp/topologix_uploads\n\
\n\
# Drop privileges and execute command as appuser\n\
exec gosu appuser "$@"\n' > /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

EXPOSE 5000

# Use entrypoint script to handle permissions before running app
ENTRYPOINT ["/docker-entrypoint.sh"]

# Development: Flask dev server
# Production: gunicorn (can be overridden in docker-compose.yaml)
CMD ["python", "app.py"]