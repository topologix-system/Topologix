# Multi-stage build for production-ready frontend
# Stage 1: Build the application
# Fixed Node.js 20.11 and Alpine 3.19 to ensure build reproducibility
# and QEMU ARM64 compatibility (resolves illegal instruction error)
FROM node:20.11-alpine3.19 AS builder

WORKDIR /app

# Copy dependency files
COPY package*.json ./

# Install dependencies
# Temporarily using npm install instead of npm ci due to lock file sync issue
RUN npm install

# Copy application code
COPY . .

# Accept build arguments for Vite environment variables
# These will be embedded into the build at compile time
# Default to empty string for environment-independent builds (uses nginx proxy)
ARG VITE_API_BASE_URL=""
ARG VITE_AUTH_ENABLED="true"
ARG VITE_TIMEZONE="Asia/Tokyo"

# Set as environment variables for Vite build process
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_AUTH_ENABLED=${VITE_AUTH_ENABLED}
ENV VITE_TIMEZONE=${VITE_TIMEZONE}

# Build for production
# This removes console.log, optimizes code, and generates static files
# Note: TypeScript type checking is skipped (use build:check for full validation)
RUN npm run build

# Stage 2: Serve with nginx
# Fixed nginx 1.25 for stability and security
FROM nginx:1.25-alpine

# Copy built static files from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration with security headers
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf.dpkg-dist 2>/dev/null || true

# Copy entrypoint script that injects runtime configuration
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Run as root in container (safe in container environment)
# nginx:alpine base image handles user permissions internally

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1

# Start nginx in foreground via entrypoint (after runtime config injection)
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
