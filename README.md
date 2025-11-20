# Topologix

Network Topology Visualization Tool powered by Batfish


https://github.com/user-attachments/assets/7b45560a-ab6e-4245-8f22-57b41e195bb5


## What You Can Do

- **Auto-generate network topology diagrams** - Just upload your config files and visualize your entire network
- **Config-based traceroute** - Simulate packet flows without touching live devices
- **Multi-vendor support** - Cisco, Juniper, Arista, and more
- **Network validation** - Check OSPF/BGP configuration, detect routing issues
- **Interactive visualization** - Explore nodes, interfaces, routes, VLANs with an intuitive UI

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/topologix-system/topologix.git
cd topologix
cp .env.example .env
```

**Optional:** Edit `.env` to customize settings (see [Environment Variables](#environment-variables))

### 2. Start Services

```bash
docker compose up -d
```

**Note:** First startup takes 2-3 minutes to build images and initialize services.

On first startup, Topologix automatically initializes the database and creates Docker volumes. To reset to a clean state, run `docker compose down -v`.

### 3. Access Application

Open http://localhost:3000 in your browser.

**First-time setup:**
- If `AUTH_ENABLED=true` (default): You'll see a setup wizard to create admin account
- If `AUTH_ENABLED=false`: Direct access to the topology viewer

**Additional endpoints:**
- **Backend API**: http://localhost:5000/api
- **Health Check**: http://localhost:5000/api/health

### 4. Upload Network Configs

See [Network Configuration Files](#network-configuration-files) section below.

## Environment Variables

Configure Topologix by editing `.env`. See [.env.example](.env.example) for complete documentation.

### Key Configuration Variables

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

### Quick Configuration Examples

**Development (default):**
```bash
cp .env.example .env
# No changes needed for basic testing
```

**Production deployment:**
```bash
cp .env.example .env
# Edit .env and set:
# - FLASK_ENV=production
# - JWT_SECRET_KEY=<generate strong secret>
# - CORS_ORIGINS=https://yourdomain.com
# - DATABASE_URL=postgresql://... (recommended over SQLite)
```

**Disable authentication (testing only):**
```bash
# In .env:
AUTH_ENABLED=false
VITE_AUTH_ENABLED=false
```

For all variables and detailed explanations, see [.env.example](.env.example).

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
