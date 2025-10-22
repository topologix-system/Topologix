# Topologix

Network Topology Visualization Tool powered by Batfish

## What You Can Do

- **Auto-generate network topology diagrams** - Just upload your config files and visualize your entire network
- **Config-based traceroute** - Simulate packet flows without touching live devices
- **Multi-vendor support** - Cisco, Juniper, Arista, and more
- **Network validation** - Check OSPF/BGP configuration, detect routing issues
- **Interactive visualization** - Explore nodes, interfaces, routes, VLANs with an intuitive UI

## Quick Start

### 1. Prepare Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` if needed (see Environment Variables below).

### 2. Start Services

```bash
docker compose up -d
```

On first startup, Topologix automatically initializes the database and creates Docker volumes. To reset to a clean state, run `docker compose down -v`.

### 3. Access Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000/api
- **Health Check**: http://localhost:5000/api/health

## Environment Variables

Edit `.env` to configure the application. Key settings:

### Backend

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Flask environment mode | `development` |
| `FLASK_DEBUG` | Enable Flask debug mode | `True` |
| `BATFISH_HOST` | Batfish service hostname | `batfish` |
| `BATFISH_PORT` | Batfish service port | `9996` |
| `CORS_ORIGINS` | Allowed frontend URLs (comma-separated) | `http://localhost:3000` |

### Authentication (Optional)

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_ENABLED` | Enable JWT authentication | `true` |
| `AUTH_DEFAULT_ADMIN_USER` | Default admin username | `admin` |
| `AUTH_DEFAULT_ADMIN_PASS` | Default admin password | _(empty)_ |
| `JWT_SECRET_KEY` | JWT secret (auto-generated if empty) | _(empty)_ |
| `CSRF_SECRET_KEY` | CSRF secret (auto-generated if empty) | _(empty)_ |

### Database (when AUTH_ENABLED=true)

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection URL | `sqlite:////app/data/topologix.db` |

Supported databases:
- SQLite: `sqlite:////app/data/topologix.db`
- PostgreSQL: `postgresql://user:password@postgres:5432/topologix`
- MySQL: `mysql+pymysql://user:password@mysql:3306/topologix`

### Frontend

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_BASE_URL` | Backend API URL | `http://localhost:5000` |
| `VITE_AUTH_ENABLED` | Enable authentication (must match backend) | `true` |
| `VITE_TIMEZONE` | Display timezone (IANA format) | `Asia/Tokyo` |

## Network Configuration Files

Place your network configuration files in the `snapshots` directory:

```bash
mkdir -p snapshots/my-network
# Copy your config files (.cfg, .conf) to snapshots/my-network/
```

## Basic Commands

```bash
# Start services
docker compose up -d

# View logs
docker compose logs -f

# Stop services
docker compose down

# Rebuild (after code changes)
docker compose build
docker compose up -d
```

## License

Apache License 2.0