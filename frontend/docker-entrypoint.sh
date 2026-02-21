#!/bin/sh

set -e

escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

API_BASE_URL_ESC=$(escape_json "${VITE_API_BASE_URL:-}")
TIMEZONE_ESC=$(escape_json "${VITE_TIMEZONE:-Asia/Tokyo}")

AUTH_FLAG=${VITE_AUTH_ENABLED:-true}
AUTH_NORMALIZED=$(printf '%s' "$AUTH_FLAG" | tr '[:upper:]' '[:lower:]')
case "$AUTH_NORMALIZED" in
  true|1|yes)
    AUTH_VALUE=true
    ;;
  false|0|no)
    AUTH_VALUE=false
    ;;
  *)
    AUTH_VALUE=true
    ;;
esac

cat <<EOF > /usr/share/nginx/html/runtime-config.js
window.__TOPOLOGIX_CONFIG__ = {
  apiBaseUrl: "${API_BASE_URL_ESC}",
  authEnabled: ${AUTH_VALUE},
  timezone: "${TIMEZONE_ESC}",
};
EOF

# Expand CSP connect-src if external API host is configured
CSP_CONNECT_SRC="${CSP_CONNECT_SRC:-}"
if [ -n "$CSP_CONNECT_SRC" ]; then
  sed -i "s|connect-src 'self'|connect-src 'self' ${CSP_CONNECT_SRC}|g" /etc/nginx/conf.d/*.conf
fi

exec "$@"
