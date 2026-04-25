# Topologix

Network topology visualization and validation tool powered by Batfish.

https://github.com/user-attachments/assets/7b45560a-ab6e-4245-8f22-57b41e195bb5

> [!IMPORTANT]
> This project is currently under development. Bugs and incomplete features may be present.
>
> このプロジェクトは現在開発中です。不具合や未完成の機能が含まれる可能性があります。


- [English](#english)
- [日本語](#日本語)
- [References](#references)

## English

### What You Can Do

- Generate topology diagrams from uploaded network configuration snapshots.
- Inspect nodes, interfaces, VLANs, routes, edges, ACLs, and validation findings from one web UI.
- Run config-based traceroute and reachability analysis without touching live devices.
- Compare snapshots to review network changes.
- Manage snapshots with optional authentication, creator-only access, folder labels, and collapsible folder groups.
- Upload text-based network artifacts with `.cfg`, `.conf`, `.txt`, and `.log` extensions.

### Architecture

Topologix runs as Docker services:

| Service | Role | Default local endpoint |
| --- | --- | --- |
| `frontend` | React + Vite build served by nginx, with `/api/*` reverse-proxied to backend | http://localhost:3000 |
| `backend` | Flask API, authentication, snapshot management, Batfish orchestration | http://localhost:5000/api |
| `batfish` | Batfish all-in-one analysis service | `9996` inside/outside Docker |

For repository development, use `docker-compose.dev.yaml`. Do not install frontend dependencies on the host; container builds run `npm ci` inside Docker.

### Quick Start

1. Create local configuration.

```bash
cp .env.example .env
```

2. Start the development stack from this repository.

```bash
docker compose -f docker-compose.dev.yaml up -d --build
```

The first build can take a few minutes because Docker builds the backend and frontend images and starts Batfish.

3. Open the application.

```text
http://localhost:3000
```

4. Check backend health.

```text
http://localhost:5000/api/health
```

To run the packaged-image compose file instead of building local source, use:

```bash
docker compose up -d
```

For production-style packaged-image deployments, set `FLASK_ENV=production`, `FLASK_DEBUG=False`, and provide `SECRET_KEY`, `JWT_SECRET_KEY`, and `CSRF_SECRET_KEY` in your local `.env` before starting the stack.

### Basic Commands

```bash
# Start or rebuild the development stack
docker compose -f docker-compose.dev.yaml up -d --build

# Show service status
docker compose -f docker-compose.dev.yaml ps

# Follow logs
docker compose -f docker-compose.dev.yaml logs -f

# Stop services without removing volumes
docker compose -f docker-compose.dev.yaml down
```

### Authentication and Snapshot Access

Authentication is optional and controlled by matching backend/frontend flags:

| Mode | Required settings | Snapshot behavior |
| --- | --- | --- |
| Open access | `AUTH_ENABLED=false` and `VITE_AUTH_ENABLED=false` | Single shared workspace. Existing sample and legacy snapshots remain visible. |
| Authenticated access | `AUTH_ENABLED=true` and `VITE_AUTH_ENABLED=true` | Users must log in. Snapshots created in this mode are private to their creator and checked server-side on list, files, update, upload, activate, delete, compare, Layer1, and interface routes. |

When authentication is enabled, newly created snapshots and metadata-bearing snapshots store owner and folder metadata in a sidecar file named `.topologix-snapshot.json`.

Important migration note: snapshots created before owner metadata existed are treated as legacy/unowned. They are not automatically assigned to a user when switching from `AUTH_ENABLED=false` to `AUTH_ENABLED=true`; plan an explicit owner migration before relying on authenticated production use.

### Snapshot Folders and Uploads

Snapshot folders are labels stored in metadata, not real filesystem directories. This keeps the Batfish snapshot layout stable while allowing the UI to group snapshots.

Current UI behavior:

- New snapshot creation has a folder combobox.
- Existing snapshot folder editing has the same combobox.
- Existing folders can be selected from the dropdown.
- Typing a new folder name creates a new folder label when saved.
- Snapshot lists are grouped by folder and can be collapsed.
- The current or selected snapshot group stays open so the active context remains visible.

Allowed upload extensions are:

```text
.cfg, .conf, .txt, .log
```

Each uploaded file is limited to 10 MB. Uploaded files are validated with an extension allowlist, filename sanitization, size checks, and text-content validation. `.log` files are accepted as text artifacts; Batfish device modeling still depends on supported network configuration files under `configs`.

### Network Snapshot Layout

For manual placement, keep the Batfish-compatible layout:

```bash
mkdir -p snapshots/my-network/configs
# Copy text-based network artifacts to snapshots/my-network/configs/
# Supported by Topologix upload/listing: .cfg, .conf, .txt, .log
```

Batfish expects network device configuration files under the `configs` directory below the top-level snapshot directory.

### Environment Variables

See [.env.example](.env.example) for the full template. Key variables:

| Variable | Purpose | Notes |
| --- | --- | --- |
| `AUTH_ENABLED` | Enables backend authentication | Must match `VITE_AUTH_ENABLED`. Default is `false`. |
| `VITE_AUTH_ENABLED` | Enables frontend auth behavior | Must match `AUTH_ENABLED`. Default is `false`. |
| `AUTH_DEFAULT_ADMIN_USER` | Default admin username | Used only when auth is enabled. |
| `AUTH_DEFAULT_ADMIN_PASS` | Default admin password | Leave empty for first-time setup, or set via local `.env`. Do not commit real values. |
| `SECRET_KEY`, `JWT_SECRET_KEY`, `CSRF_SECRET_KEY` | Flask/JWT/CSRF secrets | Generate strong production values. Do not commit real values. |
| `DATABASE_URL` | Auth database URL | Default Docker value is SQLite at `/app/data/topologix.db`; PostgreSQL/MySQL can be configured. |
| `VITE_API_BASE_URL` | Frontend API base URL | Empty value uses nginx `/api` reverse proxy in the Docker frontend. |
| `BEHIND_REVERSE_PROXY` | Enables proxy-aware request handling | Must match actual infrastructure to avoid trusting spoofed proxy headers. |
| `TRUSTED_PROXY_COUNT` | Number of trusted proxy layers | Set according to the real proxy chain. |
| `VITE_TIMEZONE` | UI timestamp timezone | Default is `Asia/Tokyo`. |

### Security and Maintenance Notes

- Use Docker/container workflows for dependency checks and builds.
- The current frontend dependency set includes Vite 6.x. A GitHub-reviewed 2026 Vite advisory affects the dev server when exposed to a network. Topologix Docker serves the production build with nginx, but do not expose the Vite dev server externally until dependencies and configuration have been reviewed.
- Production deployments should set explicit secrets, restrict CORS origins, configure reverse proxy settings correctly, and review authentication defaults before going live.

## 日本語

### 概要

Topologix は Batfish を利用して、ネットワーク機器の設定ファイルからトポロジ、経路、インターフェース、VLAN、ACL、検証結果を確認するための Web アプリケーションです。実機にアクセスせず、設定ファイルベースで traceroute、到達性確認、snapshot 比較を行えます。

### 主な機能

- 設定ファイルからネットワークトポロジを可視化
- node / edge / analysis / traceroute / validation の各画面でネットワーク状態を確認
- interface、VLAN、route、ACL、validation 結果の確認
- snapshot の作成、アップロード、activate、比較
- 認証有効時の「作成者のみアクセス可能」な snapshot 管理
- snapshot folder ラベルによる分類、既存 folder のプルダウン選択、新規 folder 名の入力
- folder ごとの折りたたみ表示
- `.cfg`, `.conf`, `.txt`, `.log` のアップロード

### 起動方法

このリポジトリで開発・確認する場合は `docker-compose.dev.yaml` を使います。ホストマシンで `npm install` は不要です。

```bash
cp .env.example .env
docker compose -f docker-compose.dev.yaml up -d --build
```

起動後、ブラウザで次にアクセスします。

```text
http://localhost:3000
```

Backend health check:

```text
http://localhost:5000/api/health
```

停止する場合:

```bash
docker compose -f docker-compose.dev.yaml down
```

### 認証と snapshot のアクセス制御

`AUTH_ENABLED=false` かつ `VITE_AUTH_ENABLED=false` の場合、Topologix は単一の共有 workspace として動作します。この場合、既存の sample / legacy snapshot は表示対象です。

`AUTH_ENABLED=true` かつ `VITE_AUTH_ENABLED=true` の場合、ログインが必要です。このモードで作成された snapshot と owner metadata を持つ snapshot は作成者のみ参照・更新・アップロード・activate・削除・比較できます。権限確認は UI 表示だけではなく、backend の API route 側で行われます。

注意: `AUTH_ENABLED=false` の時代に作成された owner 情報なしの snapshot は、`AUTH_ENABLED=true` に切り替えても自動的には owner 付与されません。認証付き運用へ切り替える前に、明示的な owner migration を計画してください。

### snapshot folder とアップロード

folder は実ディレクトリではなく metadata label です。Batfish が前提とする `snapshots/<snapshot-name>/configs` の構造は維持されます。

現在の UI では、新規 snapshot 作成時と既存 snapshot の folder 変更時に folder combobox を使えます。既存 folder はプルダウンから選択でき、候補にない folder 名を入力して保存すると新しい folder label として扱われます。snapshot 一覧は folder ごとに折りたたみ表示できます。

アップロード可能な拡張子:

```text
.cfg, .conf, .txt, .log
```

1ファイルあたりの上限は 10 MB です。`.log` はテキスト artifact としてアップロードできますが、Batfish の機器モデル生成には対応ベンダーの設定ファイルが必要です。

### 運用上の注意

- `AUTH_ENABLED` と `VITE_AUTH_ENABLED` は必ず一致させてください。
- 本番運用では `SECRET_KEY`, `JWT_SECRET_KEY`, `CSRF_SECRET_KEY` を明示的に設定してください。
- reverse proxy を使う場合、`BEHIND_REVERSE_PROXY` と `TRUSTED_PROXY_COUNT` を実際の構成に合わせてください。

## License

Apache License 2.0
