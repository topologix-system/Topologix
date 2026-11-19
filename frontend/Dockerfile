# check=skip=SecretsUsedInArgOrEnv
# Multi-stage build for production-ready frontend
# Stage 1: Build the application
FROM node:20.20.2-alpine3.23 AS builder

WORKDIR /app

COPY package.json package-lock.json ./

# Install all dependencies (devDependencies needed for build step)
RUN npm ci

COPY . .

# Accept build arguments for Vite environment variables
ARG VITE_API_BASE_URL=""
ARG VITE_AUTH_ENABLED="false"
ARG VITE_TIMEZONE="Asia/Tokyo"

ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_AUTH_ENABLED=${VITE_AUTH_ENABLED}
ENV VITE_TIMEZONE=${VITE_TIMEZONE}

# Build for production without TypeScript type checking
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:1.30.6-alpine
# Pull the Alpine security fix for libxslt not yet in the nginx image
RUN apk upgrade --no-cache libxslt

COPY --from=builder /app/dist /usr/share/nginx/html

COPY nginx.conf /etc/nginx/conf.d/default.conf

RUN rm /etc/nginx/conf.d/default.conf.dpkg-dist 2>/dev/null || true

# Copy entrypoint script that injects runtime configuration
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh


EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1

# Start nginx in foreground via entrypoint (after runtime config injection)
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
