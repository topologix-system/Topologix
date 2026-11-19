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
- Optionally upload advanced Batfish artifacts for AWS, Azure, SONiC, Check Point management, host models, Layer-1 topology, ISP modeling, runtime data, and external BGP announcements.

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

If the frontend and backend flags do not match, Topologix shows an authentication configuration mismatch warning in the header or login page based on the backend `/api/health` response. Set both flags to the same value and restart the stack before relying on snapshot access behavior.

When authentication is enabled, newly created snapshots and metadata-bearing snapshots store owner and folder metadata in a sidecar file named `.topologix-snapshot.json`.

Important migration note: snapshots created before owner metadata existed are treated as legacy/unowned. They are not automatically assigned to a user when switching from `AUTH_ENABLED=false` to `AUTH_ENABLED=true`. After enabling authentication, an admin can open **Snapshot Owner Migration** from the user menu and explicitly assign each unowned snapshot to an active user. Until assigned, those legacy snapshots remain hidden from normal authenticated snapshot access.

### Snapshot Folders and Uploads

Snapshot folders are labels stored in metadata, not real filesystem directories. This keeps the Batfish snapshot layout stable while allowing the UI to group snapshots.

Current UI behavior:

- New snapshot creation has a folder combobox.
- Existing snapshot folder editing has the same combobox.
- Existing folders can be selected from the dropdown.
- Typing a new folder name creates a new folder label when saved.
- Snapshot lists are grouped by folder and can be collapsed.
- The current or selected snapshot group stays open so the active context remains visible.
- The selected snapshot file list includes a format dropdown next to each filename. Use it to keep Batfish auto-detection or to write a first-line `!RANCID-CONTENT-TYPE: <vendor>` override for `.cfg`, `.conf`, `.txt`, and `.log` files.
- Current explicit format choices are A10 (`a10`), Arista, F5 BIG-IP, Cisco IOS / IOS-XE (`ios`), Cisco NX-OS, Cisco IOS-XR, Dell Force10, Fortinet / FortiOS (`fortigate`), Foundry, Juniper, MRV, and Palo Alto. Cisco ASA / FPR ASA mode and Cumulus Linux remain Batfish auto-detection targets because no supported explicit RANCID override token has been confirmed for them.
- Choosing auto-detection removes the override header from the file.
- The trash button beside each file timestamp opens a confirmation dialog before deleting the uploaded file. If the changed snapshot is active, Topologix re-activates it so Batfish reads the updated file set.
- When authentication is enabled, only the snapshot owner can update file format overrides or delete uploaded files.
- Advanced artifact data is available as an optional collapsed panel. Use it only when you need Batfish-specific layouts such as `aws_configs`, `azure_configs`, `checkpoint_management`, `sonic_configs`, `hosts`, `iptables`, `batfish/layer1_topology.json`, `batfish/isp_config.json`, `batfish/runtime_data.json`, or `external_bgp_announcements.json`.
- Advanced artifacts can be previewed before upload, listed by artifact type, metadata-edited with a safe destination preview, replaced, deleted, and lightly validated. Upload, metadata update, replace, and delete operations require the preview token issued by the backend. Metadata update, replace, and delete tokens are bound to the current artifact fingerprint, so stale tokens are rejected after concurrent changes. Final parsing and semantic validation still happens when Batfish activates the snapshot.
- When files are uploaded to the currently active snapshot, Topologix re-activates that snapshot after the upload batch so Batfish analysis does not continue using stale data.

Allowed upload extensions are:

```text
.cfg, .conf, .txt, .log
```

Each uploaded file is limited to 10 MB. Uploaded files are validated with an extension allowlist, filename sanitization, size checks, and text-content validation. `.log` files are accepted as text artifacts and can receive a format override, but Batfish device modeling still depends on supported network configuration content under `configs`.

### Network Snapshot Layout

For manual placement, keep the Batfish-compatible layout:

```bash
mkdir -p snapshots/my-network/configs
# Copy text-based network artifacts to snapshots/my-network/configs/
# Supported by Topologix upload/listing: .cfg, .conf, .txt, .log
```

Batfish expects network device configuration files under the `configs` directory below the top-level snapshot directory.

### Snapshot History and Result Cache

Topologix records the content of every snapshot as versions. After an edit it re-parses the snapshot in Batfish only when its content changed; selecting a snapshot and the reload buttons (Header and Overview) always parse it. Results of the read-only query endpoints that take no parameters (topology, nodes, interfaces, routes, protocol, configuration and validation tables) are stored on the server per content and served without Batfish, also after a backend restart. Analyses that take parameters (traceroute, reachability, ACL tests, route policies, snapshot comparison) are not cached.

#### How it works

- The backend computes a content hash over the files of a snapshot that it versions and sends to Batfish (the consumable files, see below). The Overview panel shows the current version (`v<seq>`, short hash, message, kind) and the states "Uncommitted changes", "External change pending: commit to record (Manage snapshots → History)", "External change settling" and "Working files restored from vN"; the Header snapshot selector appends `v<seq>` and `*` for uncommitted changes. The UI polls `GET /api/snapshots/<name>/version-state` every 15 seconds.
- Each snapshot is identified by a `snapshot_id` stored in its `.topologix-snapshot.json`. When the backend first evaluates a snapshot whose file is missing or has no `snapshot_id`, it writes the id; a missing file is created marked as legacy and unowned so that its access stays as before (under `AUTH_ENABLED=true` a snapshot without this file cannot be accessed through the API and is therefore not evaluated). A snapshot folder moved outside the API keeps its history; a copied folder receives a new id and starts its own history. When a snapshot's `snapshot_id` cannot be written because its directory is read-only, versioning is unavailable for that snapshot (reason `sidecar`).
- When the backend first evaluates a snapshot (for example when it is selected), it records a `baseline` version of its current files. Uploads, editor saves and deletions made through the UI stay uncommitted until a user commits them with a message in the **History** panel of Snapshot Management.
- Changes made directly in the snapshot directory, outside the API, are recorded as an `external` version once no file has changed for `EXTERNAL_CHANGE_SETTLE_SECONDS`. While the working files have uncommitted changes, an external change is not versioned on its own: it is flagged as pending and recorded by the next commit. When the working files have no uncommitted changes, an API write or a commit made while an external change is still settling records that change as an `external` version at once, without waiting for the settle time.
- The History panel lists the versions (newest first, 50 per page), shows a diff between two versions or against the working files, restores a version into the working files, deletes one version, the oldest or newest N versions or all versions, and clears the cached results of the snapshot. A restore overwrites changed files and removes files that the version does not contain, so uncommitted changes are permanently lost; unless they equal the head version, the restored files stay uncommitted until they are committed (kind `restore`). Deleted versions cannot be recovered; file objects that no remaining version uses are garbage-collected.
- A per-file diff is reported as too large when a side exceeds `SNAPSHOT_DIFF_MAX_BYTES` or when comparing the two sides exceeds a fixed internal work budget, as binary when a side contains a NUL byte or invalid UTF-8, and as truncated after `SNAPSHOT_DIFF_MAX_LINES` diff lines. At most two per-file diffs are computed at a time; further requests wait.
- Cached results are keyed by content hash, Batfish version, pybatfish version, backend build id, `RESULT_CACHE_SCHEMA_VERSION`, endpoint and, under `AUTH_ENABLED=true`, the snapshot owner. A result is stored only when none of its Batfish queries failed. A changed Batfish version is detected by a probe of the Batfish coordinator and causes a re-parse on the next request; while the version is unknown the cache is bypassed. The Header reload button still forces a re-parse, and **Clear cached results** drops the snapshot's cached results and re-parses it on the next request. When it clears nothing, the History panel says why: "Nothing was cleared: the result cache is turned off on the server. To re-parse the snapshot, go back to Topology and use "Reload current snapshot" in its header." (`RESULT_CACHE_ENABLED=false`; for a snapshot that is not the current one the last sentence is "The snapshot is parsed when it is next activated."), or "Nothing was cleared yet: the files are still being scanned. The snapshot is re-parsed on its next use." (the content hash is not settled yet; the backend re-parses the snapshot on its next use).
- Cached endpoints answer with `X-Topologix-Snapshot-Id`, `X-Topologix-Content-Hash` and `X-Topologix-Cache` (`hit`, `stored`, `unstored` or `bypass`), exposed through CORS in both auth modes. Under `AUTH_ENABLED=false` a stored result carries an `ETag` and `Cache-Control: private, no-cache`, so a browser reload can be answered with `304`. Under `AUTH_ENABLED=true` every response keeps `Cache-Control: no-store` and has no `ETag`.
- Under `AUTH_ENABLED=false` the backend stores the last activated snapshot in `<DATA_DIR>/<namespace>/active_snapshot.json` and selects it again at start; with the result cache on and a valid namespace, a start without that file, such as the first start after the upgrade, logs the WARNING "No stored active snapshot name; no snapshot is selected at start". Batfish then parses the snapshot on the first request whose result is not cached. A cached request that waited for Batfish while another snapshot was activated is answered for the snapshot that is current when it runs; it never switches the selection back.
- `/api/health` reports `result_cache.enabled`.

#### Behavior change: files that reach Batfish

Batfish receives a staged copy of the consumable files from `<DATA_DIR>/<namespace>/staging/` instead of the snapshot directory itself. The consumable files are the regular files below the snapshot directory, excluding:

- symlinks of every kind inside the snapshot directory (one WARNING per snapshot). The targets of these symlinks never reach Batfish in any mode: the live-directory fallback below is refused while the snapshot contains a symlink anywhere. A snapshot directory that is itself a symlink in the snapshot store is followed, and the files of its target are versioned and parsed;
- dotfiles and every path with a dot-prefixed component (including `.topologix-snapshot.json`), and editor temp files (`*~`, `*.swp`, `*.swo`, `#*#`);
- paths whose names are not valid UTF-8 (one WARNING per snapshot).

These files are also excluded from versioning and restore never writes or removes them. When the staged copy cannot be written (usually a full `DATA_DIR`), the snapshot is parsed once from the live directory: dotfiles, editor temp files and non-UTF-8 names can then reach Batfish, results are not cached, version-state reports `loaded_live: true` and the Overview shows "Staging unavailable: results are not cached". With the result cache on, staging is retried on the next request once 60 seconds have passed; with `RESULT_CACHE_ENABLED=false`, or while versioning is unavailable, the snapshot stays loaded from the live directory until it is activated again (the Header reload button) or its files are changed through the UI.

#### Configuration

Both compose files pass every variable below to the backend as `- VAR=${VAR:-}`, and the backend treats an empty value as unset. `docker-compose.dev.yaml` reads `DEPLOYMENT_ID` from `DEV_DEPLOYMENT_ID` and `APP_BUILD_ID` from `DEV_APP_BUILD_ID`: both compose files read the same repository `.env` and use the same `backend-db` volume but different snapshot stores, so one shared value would merge the two stacks' history namespaces and cached results. `DEPLOYMENT_ID` and `APP_BUILD_ID` in `.env` therefore apply to the packaged stack only. `EXTERNAL_CHANGE_SETTLE_SECONDS` accepts a decimal number; the other numeric variables in the table accept only whole numbers. A value that cannot be parsed, such as `1.5` for a whole-number variable, any non-numeric text or a number that is not finite (`1e999`), stops backend startup, and a negative value is treated as `0` without a warning (for example, `HISTORY_GC_GRACE_SECONDS=-1` removes the garbage-collection grace). `0` is a literal limit and never means unlimited: with `RESULT_CACHE_MAX_BYTES=0` or `RESULT_CACHE_MAX_ENTRIES=0` every cached result is evicted right after it is stored, with `SNAPSHOT_DIFF_MAX_BYTES=0` every non-empty file is reported as too large, and with `SNAPSHOT_DIFF_MAX_LINES=0` no diff lines are shown and every changed text file with at least one differing line is reported as truncated (binary and too-large files keep those flags).

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATA_DIR` | `/app/data` when that directory exists | Persistent data directory (Docker: the `backend-db` volume). Without it the backend uses a temporary directory, logs a WARNING and disables versioning and the result cache, so runs outside Docker must set `DATA_DIR`. |
| `RESULT_CACHE_DIR` | `<DATA_DIR>/result_cache` | Result cache directory. |
| `SNAPSHOT_HISTORY_DIR` | `<DATA_DIR>/snapshot_history` | History object store. |
| `DEPLOYMENT_ID` | UUID in `<SNAPSHOTS_DIR>/.topologix-store.json` | History namespace of this stack; see [Namespaces](#namespaces-and-deployment_id). Dev stack: `DEV_DEPLOYMENT_ID`. |
| `APP_BUILD_ID` | derived from the backend sources | Backend build id in the cache key. Normally left empty; the derived id covers `app.py`, `config.py`, `requirements.txt` and the Python files below `services/`, `security/`, `database/`, `utils/` and `models/`. A set value must be unique per backend build, because a constant value makes an upgraded backend serve results computed by the old code. Dev stack: `DEV_APP_BUILD_ID`. |
| `RESULT_CACHE_ENABLED` | `true` | Kill switch: empty or `true` in any letter case (`TRUE`, `True`) turns the cache on, any other value turns it off (see below). The cache is also off with the temporary-directory `DATA_DIR` or overlapping storage directories. |
| `RESULT_CACHE_MAX_BYTES` | `536870912` (512 MiB) | Size limit of the whole cache directory. |
| `RESULT_CACHE_MAX_ENTRIES` | `4000` | Entry limit of the whole cache directory. |
| `RESULT_CACHE_PROTECT_SECONDS` | `900` | Results stored or served within this window are evicted last. |
| `HISTORY_GC_GRACE_SECONDS` | `600` | Unreferenced history objects younger than this are kept by the garbage collection, which runs at startup, hourly and after history deletions; a snapshot deletion and the admin purges skip the grace. |
| `HISTORY_ACCEPT_STORE_LOSS` | empty | Accepts a lost object store; see [Recovery](#recovery). |
| `EXTERNAL_CHANGE_SETTLE_SECONDS` | `10` | Quiet time before a change made outside the API is versioned. |
| `BATFISH_VERSION_PROBE_TTL_SECONDS` | `300` | Seconds a probed Batfish version is reused. |
| `BATFISH_VERSION_GRACE_SECONDS` | `3600` | Seconds after the last successful version probe or snapshot activation during which the last known Batfish version keeps serving cached results while Batfish cannot be reached. |
| `SNAPSHOT_DIFF_MAX_BYTES` | `524288` (512 KiB) | Per-file diff size limit. |
| `SNAPSHOT_DIFF_MAX_LINES` | `2000` | Per-file diff line limit. |

Storage-directory overlap rule: `SNAPSHOTS_DIR`, `RESULT_CACHE_DIR`, `SNAPSHOT_HISTORY_DIR` and `<DATA_DIR>/_invalid-namespace` must not equal or contain one another, and `DATA_DIR` must not equal or lie inside `SNAPSHOTS_DIR`. A violation logs one ERROR at startup, turns the result cache off and makes versioning unavailable (reason `storage`).

Kill switch: with `RESULT_CACHE_ENABLED=false` requests behave as without the result cache. Cached endpoints answer with `Cache-Control: no-store` and without identity headers, Batfish is loaded by snapshot name as before, and the AUTH OFF active snapshot is not selected again at start. **Clear cached results** clears nothing; the Header reload button re-parses the snapshot. Snapshot versioning and the staged Batfish copy stay on.

The database is initialized in both auth modes because it stores the version history. Under `AUTH_ENABLED=false` a database failure makes versioning unavailable instead of stopping the backend. The default `DATABASE_URL` outside the compose files stays `sqlite:///<backend directory>/topologix.db` and moves to `<DATA_DIR>/topologix.db` only when `DATA_DIR` is set explicitly and no legacy `<backend directory>/topologix.db` exists (a legacy file is kept with a WARNING); both compose files set `sqlite:////app/data/topologix.db`.

#### Namespaces and DEPLOYMENT_ID

History rows are keyed by a namespace: `DEPLOYMENT_ID` when it is set, otherwise a UUID that the backend writes on first start to `.topologix-store.json` in the snapshot store root. Writing that marker needs a store filesystem with hard-link support; without it versioning is unavailable (reason `namespace`) and the ERROR names `DEPLOYMENT_ID` as the remedy. `DEPLOYMENT_ID` must match `^[A-Za-z0-9_-]{1,64}$`, must not be `result_cache`, `snapshot_history` or `_invalid-namespace`, and `<DATA_DIR>/<DEPLOYMENT_ID>` must not overlap the directories of the overlap rule; an invalid value, or a marker that cannot be read, makes versioning unavailable (reason `namespace`) with one ERROR, and the application keeps running.

- `DEPLOYMENT_ID` is recommended when several stacks share one database or `backend-db` volume, as the two compose files do.
- An existing deployment that adopts `DEPLOYMENT_ID` must set it to the UUID in its `.topologix-store.json`; any other value detaches its history.
- Keep `.topologix-store.json` when moving a snapshot store. Delete it from a store duplicated for another stack that shares the database (or give the stacks distinct `DEPLOYMENT_ID` values); otherwise both stores share one history per snapshot.
- The first start under a new namespace logs one WARNING when snapshots of the current store have history under other namespaces (it lists those namespaces with their last-seen time and row counts). It has two causes: the same deployment changed its namespace (`DEPLOYMENT_ID` introduced or changed, or the store moved without its marker) — restore the previous `DEPLOYMENT_ID` or marker value, which reattaches the history unchanged, or purge the detached namespace after checking the admin namespace list; or the snapshot folders were copied from another stack that shares the database — no action is needed, the copies start their own history.
- Detached history is removed only through the admin purge with `namespace` and `confirm` (see [Recovery](#recovery)), after checking `GET /api/admin/snapshot-history/namespaces`. This purge destroys that namespace's history whichever stack owns it: a stopped sibling stack's namespace looks the same as a detached one.

#### Storage, sizing and backups

| Path below `DATA_DIR` | Content |
| --- | --- |
| `topologix.db` | Default SQLite database: version rows and, under `AUTH_ENABLED=true`, users. |
| `snapshot_history/<db_id>/objects/<aa>/<sha256>` | File contents of all versions, stored once per content (`snapshot_history/` is the default `SNAPSHOT_HISTORY_DIR`). `<db_id>` is the database identity stored in the database. |
| `snapshot_history/<db_id>/tmp/`, `snapshot_history/<db_id>/trash/` | Transient: objects being written, and objects the garbage collection is removing. |
| `result_cache/<content_hash>/<key_hash>.json.gz`, `result_cache/tmp/` | Cached Batfish results per content hash (a Topologix header followed by the gzip-compressed body; not plain gzip files), and entries being written (`result_cache/` is the default `RESULT_CACHE_DIR`). |
| `<namespace>/staging/<snapshot_id>/<snapshot name>/` | Transient copy of the files Batfish parses (a random directory name replaces `<snapshot_id>` while the snapshot has none). While the namespace is invalid, `_invalid-namespace/staging/` takes its place; while `DATA_DIR` lies inside `SNAPSHOTS_DIR` (or an invalid namespace's `_invalid-namespace` overlaps another storage directory), a directory in the system temporary directory does. |
| `<namespace>/active_snapshot.json` | `AUTH_ENABLED=false`: the last activated snapshot; not written while the namespace is invalid. |

History objects and cached results contain configuration text; they are written with mode `0600` in `0700` directories. Objects are deduplicated, so a version costs only its changed files; the first `baseline` stores one copy of each existing snapshot. 130 snapshots of about 170 text configuration files each, most shared across versions, stay well under 1 GB. The cache defaults to 512 MiB and 4000 entries (about 1 MB per 170-node all-data result). The backend container changes the ownership of `/app/data` recursively at every start, so a very large history slows startup.

- Back up and restore the database, `SNAPSHOT_HISTORY_DIR` and the snapshot store together while the backend is stopped. A database restored without the matching object store reports the affected snapshots as `missing_objects`, or the whole store as `storage` when none of its objects is left.
- Switching `DATABASE_URL` to a new, empty database starts an empty history; the objects of the previous database stay on disk under `snapshot_history/<old db_id>/` until removed by hand.
- A copy of the database (backup restore, clone) keeps its `db_id`. Never run it, not even temporarily, against the `SNAPSHOT_HISTORY_DIR` the original uses: its garbage collection removes objects that only the original's later versions reference. Copy the object store together with the database, point `SNAPSHOT_HISTORY_DIR` at that copy and give the copy its own `RESULT_CACHE_DIR` (or `DATA_DIR`), because cache owner scopes and clear stamps derive from the same `db_id`.

#### Recovery

When versioning is unavailable, the version routes, version-state and `cache/clear` answer `503` with `code: versioning_unavailable` and `details.reason`, cached endpoints bypass the cache, and uploads and edits keep working; changes written while versioning was unavailable are recorded once it returns: as external changes, except that a write made during a transient database failure is recorded as an uncommitted change (unless the backend restarts first).

| Reason | Cause |
| --- | --- |
| `storage` | Temporary-directory `DATA_DIR`, a storage-directory overlap, an object store that is missing, unreadable (for example wrong ownership or a broken mount) or holds none of the objects the current namespace references, or a startup object check that failed for a reason other than a database error. |
| `database` | Database initialization or runtime failure. |
| `namespace` | Invalid `DEPLOYMENT_ID`, or a store marker that cannot be created, read or parsed or that holds an invalid value. |
| `sidecar` | The snapshot directory is read-only, so its `snapshot_id` cannot be stored. |
| `missing_objects` | Per snapshot: objects of its versions were missing or of the wrong size at startup. |

- `missing_objects`: the startup logs one ERROR per affected snapshot, and its History panel offers only **Delete history (all)** (`DELETE /api/snapshots/<name>/versions` with `{"mode": "all", "expected_unavailable": "missing_objects"}`), which resets the history; the snapshot then shows "No versions yet" until it is committed. Deleting the snapshot through the API also purges its history. Whenever several snapshots report `missing_objects` after a storage or compose change, check the object-store mount first: the startup check looks only at the current namespace's references, so when the store is lost entirely and a sibling stack without history starts first and re-creates objects with the same hashes, the loss shows up per snapshot instead of as `storage`.
- Lost object store: when version rows reference objects and the object store is missing or holds none of them, the startup logs the ERROR "Snapshot history object store `<SNAPSHOT_HISTORY_DIR>/<db_id>/objects` is missing ..." and versioning is unavailable for the whole deployment (reason `storage`). Restore the store (check `DATA_DIR`, `SNAPSHOT_HISTORY_DIR` and the volume mount), or accept the loss: set `HISTORY_ACCEPT_STORE_LOSS` to the `<db_id>` in that path, restart, reset each affected snapshot's history with **Delete history (all)**, and remove the variable once the startup WARNING reports `0 snapshots are marked missing_objects`. Any other value is ignored with a WARNING.
- Orphans: snapshot directories removed outside the API, and snapshots deleted through the API while the database or the snapshot's `snapshot_id` was unavailable, leave orphan history rows and objects. The hourly scan (part of the hourly maintenance run, which is started by the first request that arrives at least an hour after the previous run) marks them, every start logs a WARNING listing them, and nothing is purged automatically, because a moved or temporarily unmounted store must not lose its history. Purge them with `DELETE /api/admin/snapshot-history/orphans` and `{"older_than_days": N}` (rows missing for at least N days).
- Detached namespace: `DELETE /api/admin/snapshot-history/orphans` with `{"namespace": "<ns>", "confirm": "<ns>"}` removes every history row of that non-current namespace and its staging directory.

#### API routes

| Route | Request | Response |
| --- | --- | --- |
| `GET /api/snapshots/<name>/version-state` | — | Working content hash, head version, uncommitted and external-change state, loaded Batfish state. |
| `GET /api/snapshots/<name>/versions` | Query `limit` (1-200, default 50) and `offset` (0 or more), both optional. | `{"items", "total"}`, newest first. |
| `POST /api/snapshots/<name>/versions` | `{"message", "expected_head"?}`; `message` has 1-500 characters after trimming. | `201` with the new version; `409` `version_unchanged` when the working files equal the head version. |
| `GET /api/snapshots/<name>/versions/<version_id>` | — | The version with its `files`. |
| `DELETE /api/snapshots/<name>/versions/<version_id>` | Optional `{"expected_head"?}`. | `{"deleted", "head"}`. |
| `DELETE /api/snapshots/<name>/versions` | `{"mode": "all"}` or `{"mode": "oldest" \| "newest", "count"}` (`count` is required for `oldest` and `newest`), each with the optional `"expected_head"`, `"expected_total"` (not compared with `all`) and `"expected_unavailable"`. | `{"deleted", "head"}`. |
| `POST /api/snapshots/<name>/versions/<version_id>/restore` | Optional `{"expected_working_hash"?}`. | `{"requires_reinitialize", "restored_from"}`; `409` `version_conflict` with `details.reason: "path_clash"` and `details.path` when a version path clashes with the working files; `500` `restore_failed` when the working files cannot be settled before the restore, the snapshot's identity cannot be resolved or changes meanwhile (for example when it is deleted and re-created), a version object is missing or corrupt, an unexpected error occurs while the version's objects and paths are checked, or removing or writing a working file fails. Only in the last case can working files already have changed: every object and path of the version is checked before anything is removed or written. |
| `GET /api/snapshots/<name>/versions/<version_id>/diff` | Query `against` (a version id or `working`), required. | `{"from", "against", "files"}`, plus `"working_content_hash"` for `against=working`. |
| `GET /api/snapshots/<name>/versions/<version_id>/diff/file` | Query `against` and `path` (a file of either side), both required. | `{"path", "binary", "too_large", "truncated", "hunks"}`. |
| `POST /api/snapshots/<name>/cache/clear` | No body or a JSON object. | `{"cleared": true}`, and the snapshot is re-parsed on its next use; `{"cleared": false}` when `RESULT_CACHE_ENABLED` turns the cache off (nothing happens) or the content hash is not settled yet (the snapshot is re-parsed on its next use). With a temporary-directory `DATA_DIR` or overlapping storage directories, which also turn the cache off, it answers `503` `versioning_unavailable` (`storage`), as it does for every other reason that makes versioning unavailable. |
| `GET /api/cache/stats` | — | `{"entries", "bytes", "max_bytes", "max_entries"}`. |
| `GET /api/admin/snapshot-history/namespaces` | — | `{"items": [{"namespace", "current", "first_seen_at", "last_seen_at", "rows"}]}`. |
| `DELETE /api/admin/snapshot-history/orphans` | `{"older_than_days"}` (orphans of the current namespace missing for at least that many days) or `{"namespace", "confirm"}` (a non-current namespace; `confirm` repeats `namespace`). | `{"purged", "last_seen_at"}` (`last_seen_at` is `null` for orphans); `400` for the current namespace or a mismatched `confirm`, `404` `namespace_not_found` for an unknown namespace. |

Common errors: `400` `invalid_json` for a body that is not a JSON object (a body is required by `POST .../versions`, `DELETE .../versions` and the orphan purge), `400` `validation_error` for an invalid field or query parameter, `400` for an invalid snapshot name, `403` and `404` `snapshot_not_found` from the snapshot authorization, `404` `version_not_found` for a version id that does not belong to the snapshot, `409` `version_conflict` when `expected_head`, `expected_total`, `expected_working_hash` or `expected_unavailable` does not match, an API write to the snapshot is in progress, the working files keep changing while a commit is being prepared, or the working files change while a restore is being prepared, and `503` `versioning_unavailable` with `details.reason` (see [Recovery](#recovery)).

Under `AUTH_ENABLED=true` the snapshot routes are owner-only, and `cache/stats` and the `admin` routes require the admin role; under `AUTH_ENABLED=false` they are open like every other route.

#### Upgrading

- Update the frontend and backend images together, after the backend image of the release has been published. A new frontend on an older backend can show a pre-edit topology from the browser cache for up to five minutes under `AUTH_ENABLED=false`.
- After the upgrade from a backend without this feature, wait five minutes or clear the site's cached data in the browser before editing: responses that the browser cached from the older backend can still be served for that long.

#### Development notes

- The dev compose file bind-mounts `./snapshots` into the backend. Saving a file there with a host editor is a change outside the API and is versioned automatically as `external` after the settle time (or flagged as pending while uncommitted changes exist).
- The result cache stores the output of the backend getters. When a fix changes the body a cached endpoint returns, bump `RESULT_CACHE_SCHEMA_VERSION` in `backend/config.py` so stored results are recomputed. The derived build id changes with every edit of the hashed backend sources, but not when `APP_BUILD_ID` is set to an unchanged value.

### Environment Variables

See [.env.example](.env.example) for the full template. Snapshot history and result cache variables are listed in [Snapshot History and Result Cache](#snapshot-history-and-result-cache). Key variables:

| Variable | Purpose | Notes |
| --- | --- | --- |
| `AUTH_ENABLED` | Enables backend authentication | Must match `VITE_AUTH_ENABLED`. Default is `false`. |
| `VITE_AUTH_ENABLED` | Enables frontend auth behavior | Must match `AUTH_ENABLED`. Default is `false`. |
| `AUTH_DEFAULT_ADMIN_USER` | Default admin username | Used only when auth is enabled. |
| `AUTH_DEFAULT_ADMIN_PASS` | Default admin password | Leave empty for first-time setup, or set via local `.env`. Do not commit real values. |
| `SECRET_KEY`, `JWT_SECRET_KEY`, `CSRF_SECRET_KEY` | Flask/JWT/CSRF secrets | Generate strong production values. Do not commit real values. |
| `DATABASE_URL` | Database URL for the snapshot version history (both auth modes) and authentication data (`AUTH_ENABLED=true`) | Default Docker value is SQLite at `/app/data/topologix.db`; PostgreSQL/MySQL can be configured. Switching to a new, empty database starts an empty history; see [Snapshot History and Result Cache](#snapshot-history-and-result-cache). |
| `SQLALCHEMY_ECHO` | SQL statement logging | Default is `false`. Keep disabled because SQL values can include password hashes and sensitive operational data. |
| `VITE_API_BASE_URL` | Frontend API base URL | Empty value uses nginx `/api` reverse proxy in the Docker frontend. |
| `BATFISH_IMAGE` | Batfish container image | Compose defaults to a digest validated with the pinned pybatfish version. Override to test another Batfish release. The `/api/health` response reports the pybatfish version and, after the first snapshot initialization, the running Batfish server version. |
| `BATFISH_QUERY_TIMEOUT_SECONDS` | Upper bound for one Batfish query | Default is `120`. The value must be an integer; values below 10 are raised to 10, and a non-integer stops backend startup. It prevents a stuck query from blocking other Batfish-backed requests, and both maintained Compose files explicitly pass it to the backend container. |
| `BEHIND_REVERSE_PROXY` | Enables proxy-aware request handling | Must match actual infrastructure to avoid trusting spoofed proxy headers. |
| `TRUSTED_PROXY_COUNT` | Number of trusted proxy layers | Set according to the real proxy chain. |
| `VITE_TIMEZONE` | UI timestamp timezone | Default is `Asia/Tokyo`. |

### Security and Maintenance Notes

- Use Docker/container workflows for dependency checks and builds.
- The current frontend dependency set includes Vite 6.x. A GitHub-reviewed 2026 Vite advisory affects the dev server when exposed to a network. Topologix Docker serves the production build with nginx, but do not expose the Vite dev server externally until dependencies and configuration have been reviewed.
- Production deployments should set explicit secrets, restrict CORS origins, configure reverse proxy settings correctly, and review authentication defaults before going live.
- Run the backend with a single gunicorn worker (the image default and the compose files already do). Batfish session state, the request lock, and auto-generated secrets are process-local, so multiple workers split the active snapshot state between requests.
- Snapshot storage differs between the stacks: the dev compose binds the repository `./snapshots` directory, while the packaged compose stores snapshots in the `snapshots-data` named volume. Snapshots created under one stack are not visible after switching to the other on the same host.

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
- AWS、Azure、SONiC、Check Point management、host model、Layer-1 topology、ISP modeling、runtime data、external BGP announcements 用の高度な Batfish artifact upload

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

frontend と backend の flag が一致していない場合、Topologix は backend の `/api/health` response をもとに Header または Login page で認証設定の不一致を警告します。snapshot access の挙動を信頼する前に、両方の flag を同じ値にして stack を再起動してください。

注意: `AUTH_ENABLED=false` の時代に作成された owner 情報なしの snapshot は、`AUTH_ENABLED=true` に切り替えても自動的には owner 付与されません。認証有効後、管理者はユーザーメニューの **スナップショット所有者移行** から、所有者未設定 snapshot を有効ユーザーへ明示的に割り当てられます。割り当てが完了するまで、それらの旧 snapshot は通常の認証付き snapshot 一覧には表示されません。

### snapshot folder とアップロード

folder は実ディレクトリではなく metadata label です。Batfish が前提とする `snapshots/<snapshot-name>/configs` の構造は維持されます。

現在の UI では、新規 snapshot 作成時と既存 snapshot の folder 変更時に folder combobox を使えます。既存 folder はプルダウンから選択でき、候補にない folder 名を入力して保存すると新しい folder label として扱われます。snapshot 一覧は folder ごとに折りたたみ表示できます。

snapshot を選択すると、file list のファイル名横に format dropdown が表示されます。`.cfg`, `.conf`, `.txt`, `.log` に対して Batfish の自動判別を使うか、先頭行の `!RANCID-CONTENT-TYPE: <vendor>` override を書き込むかを選択できます。自動判別に戻すと override header は削除されます。

現在の明示フォーマット候補は A10 (`a10`)、Arista、F5 BIG-IP、Cisco IOS / IOS-XE (`ios`)、Cisco NX-OS、Cisco IOS-XR、Dell Force10、Fortinet / FortiOS (`fortigate`)、Foundry、Juniper、MRV、Palo Alto です。Cisco ASA / FPR ASA mode と Cumulus Linux は、対応する明示 RANCID override token が確認できていないため、Batfish の自動判別を利用します。

各 file の更新日時横にある trash button を押すと確認 dialog が表示され、承認後にアップロード済み file を削除できます。変更対象の snapshot が active の場合、Topologix は Batfish が更新後の file set を読むように snapshot を再アクティブ化します。認証が有効な場合、format override 更新と file 削除は snapshot owner のみ実行できます。

高度な Batfish アーティファクトは、折りたたみ式の「高度なアーティファクトデータ」パネルから任意で利用できます。`aws_configs`、`azure_configs`、`checkpoint_management`、`sonic_configs`、`hosts`、`iptables`、`batfish/layer1_topology.json`、`batfish/isp_config.json`、`batfish/runtime_data.json`、`external_bgp_announcements.json` のような Batfish 固有レイアウトが必要な場合に使います。保存先プレビュー、アーティファクト種別ごとの表示、メタデータ編集と安全な保存先変更、置換、削除、軽量検証ができます。upload、metadata update、replace、delete は backend が発行する preview token を必要とします。metadata update / replace / delete token は現在の artifact fingerprint に結び付くため、同時変更後の古い token は拒否されます。最終的な parse / semantic validation は Batfish activate 時に確認してください。

現在 active な snapshot に通常の config / log file を upload した場合、Topologix は upload batch 完了後にその snapshot を再 activate し、Batfish 解析結果が古いまま残らないようにします。

アップロード可能な拡張子:

```text
.cfg, .conf, .txt, .log
```

1ファイルあたりの上限は 10 MB です。`.log` はテキスト artifact としてアップロードでき、format override の対象にもできます。ただし、Batfish の機器モデル生成には対応ベンダーの設定内容が必要です。

### snapshot 履歴と結果キャッシュ

Topologix は snapshot の内容を version として記録します。編集後は、内容が変わったときだけ Batfish で snapshot を再 parse します。snapshot の選択と再読み込み button(Header と Overview)は常に parse します。引数を取らない読み取り専用のクエリ endpoint(topology、node、interface、route、各 protocol、設定、validation の表)の結果は内容ごとに server 側へ保存され、backend の再起動後も Batfish を使わずに返されます。引数を取る解析(traceroute、reachability、ACL テスト、route policy、snapshot 比較)はキャッシュされません。

#### 動作

- backend は、version 管理の対象で Batfish へ送る file(後述の consumable file)の content hash を計算します。Overview panel は現在の version(`v<seq>`、短縮 hash、message、種別)と「未コミットの変更あり」「外部での変更が未記録です。「スナップショット管理」の「履歴」でコミットして記録してください」「外部での変更を確認中」「作業ファイルは vN から復元されています」の状態を表示し、Header の snapshot selector は `v<seq>` と未コミット時の `*` を表示します。UI は `GET /api/snapshots/<name>/version-state` を 15 秒ごとに取得します。
- 各 snapshot は `.topologix-snapshot.json` に保存された `snapshot_id` で識別されます。backend は snapshot を初めて評価したとき、この file がない、または `snapshot_id` を持たない場合に id を書き込みます。file がない場合は legacy かつ owner なしとして作成するため、アクセスの扱いは従来どおりです(`AUTH_ENABLED=true` では、この file がない snapshot は API からアクセスできないため評価されません)。API を通さず移動した snapshot folder は履歴を引き継ぎ、コピーした folder は新しい id を受け取って独自の履歴を開始します。snapshot directory が読み取り専用で `snapshot_id` を書き込めない場合、その snapshot の version 管理は利用不可(reason `sidecar`)になります。
- backend が snapshot を初めて評価したとき(選択したときなど)、その時点の file を `baseline` version として記録します。UI からの upload、editor での保存、file 削除は、**スナップショット管理** の **履歴** panel で message を付けて commit するまで未コミットのままです。
- API を通さず snapshot directory を直接変更した場合、`EXTERNAL_CHANGE_SETTLE_SECONDS` の間どの file も変化しなくなった時点で `external` version として記録します。作業 file に未コミットの変更がある間は単独の version にせず、保留として扱い、次の commit に含めます。作業 file に未コミットの変更がない状態で、外部変更の確認中に API 書き込みや commit を行うと、その外部変更は待ち時間を待たずにただちに `external` version として記録されます。
- 履歴 panel では version 一覧(新しい順、50 件ずつ)、version 間または作業 file との差分表示、version の復元、1 件・古い順 / 新しい順 N 件・全件の version 削除、snapshot のキャッシュ結果のクリアができます。復元は変更された file を上書きし、その version に含まれない file を削除するため、未コミットの変更は完全に失われます。復元した file は、head の version と同じ内容でない限り、commit するまで未コミットのままです(種別 `restore`)。削除した version は元に戻せず、残りのどの version も使っていない file object は garbage collection で削除されます。
- file 単位の差分は、どちらかの側が `SNAPSHOT_DIFF_MAX_BYTES` を超える場合、または両側の比較が固定の内部作業量上限を超える場合に too large、NUL byte や不正な UTF-8 を含む場合に binary となり、`SNAPSHOT_DIFF_MAX_LINES` 行を超えた部分は切り捨てられます(truncated)。file 単位の差分は同時に 2 件まで計算され、それ以上の要求は待機します。
- キャッシュ結果の key は content hash、Batfish version、pybatfish version、backend build id、`RESULT_CACHE_SCHEMA_VERSION`、endpoint、および `AUTH_ENABLED=true` では snapshot owner です。Batfish クエリが 1 件でも失敗した結果は保存しません。Batfish version は Batfish coordinator への probe で確認し、変化した場合は次の要求で再 parse します。version が不明な間はキャッシュを使いません。Header の「現在のスナップショットを再読込」button は従来どおり強制的に再 parse し、**キャッシュ結果をクリア** は snapshot のキャッシュ結果を削除して次の要求で再 parse します。何もクリアしなかった場合、履歴 panel はその理由として「何もクリアしていません。サーバーで結果キャッシュが無効になっています。スナップショットを再解析するには、トポロジーに戻り、そのヘッダーの「現在のスナップショットを再読込」ボタンを使用してください。」(`RESULT_CACHE_ENABLED=false`。現在の snapshot でない場合、最後の文は「スナップショットは次に有効化されたときに解析されます。」になります)または「まだ何もクリアしていません。作業ファイルを確認中のため、スナップショットは次回の利用時に再解析されます。」(content hash がまだ確定していない場合。backend は次回の利用時に snapshot を再 parse します)を表示します。
- キャッシュ対象の endpoint は `X-Topologix-Snapshot-Id`、`X-Topologix-Content-Hash`、`X-Topologix-Cache`(`hit`、`stored`、`unstored`、`bypass`)を返し、どちらの認証モードでも CORS で公開されます。`AUTH_ENABLED=false` では保存済みの結果に `ETag` と `Cache-Control: private, no-cache` が付き、browser の再読み込みに `304` で応答できます。`AUTH_ENABLED=true` ではすべての応答が `Cache-Control: no-store` のままで `ETag` は付きません。
- `AUTH_ENABLED=false` では、最後に activate した snapshot を `<DATA_DIR>/<namespace>/active_snapshot.json` に保存し、起動時に再び選択します。結果キャッシュが有効で namespace が正しい場合、この file がない起動(更新後の初回起動など)では WARNING "No stored active snapshot name; no snapshot is selected at start" が出力されます。Batfish は、結果がキャッシュにない最初の要求でその snapshot を parse します。Batfish を待っている間に別の snapshot が activate されたキャッシュ対象の要求は、実行時点で選択されている snapshot について応答し、選択を元に戻すことはありません。
- `/api/health` は `result_cache.enabled` を返します。

#### 動作の変更: Batfish に渡る file

Batfish には snapshot directory そのものではなく、`<DATA_DIR>/<namespace>/staging/` に作成した consumable file のコピーを渡します。consumable file は snapshot directory 以下の通常 file のうち、次を除いたものです。

- snapshot directory の中にあるあらゆる種類の symlink(snapshot ごとに WARNING 1 件)。これらの symlink の参照先はどのモードでも Batfish に渡りません。後述の live directory fallback は、snapshot 内のどこかに symlink がある間は拒否されます。snapshot store 内の snapshot directory 自体が symlink の場合はその参照先をたどり、参照先の file が version 管理と parse の対象になります。
- dotfile、`.` で始まる要素を含むすべての path(`.topologix-snapshot.json` を含む)、editor の一時 file(`*~`、`*.swp`、`*.swo`、`#*#`)。
- 名前が有効な UTF-8 でない path(snapshot ごとに WARNING 1 件)。

これらの file は version 管理の対象外でもあり、復元で書き込まれることも削除されることもありません。staging のコピーを書き込めない場合(多くは `DATA_DIR` の容量不足)は、snapshot を live directory から 1 回だけ parse します。このとき dotfile、editor の一時 file、UTF-8 でない名前の file も Batfish に渡り、結果はキャッシュされず、version-state は `loaded_live: true` を返し、Overview は「ステージングを利用できないため、結果はキャッシュされません」と表示します。結果キャッシュが有効な場合、staging は 60 秒経過後の次の要求で再試行されます。`RESULT_CACHE_ENABLED=false` の場合や version 管理を利用できない間は、snapshot を再度有効化する(Header の「現在のスナップショットを再読込」button)か UI から file を変更するまで、live directory から読み込んだ状態のままです。

#### 設定

両方の compose file は下表のすべての変数を `- VAR=${VAR:-}` として backend に渡し、backend は空の値を未設定として扱います。`docker-compose.dev.yaml` は `DEPLOYMENT_ID` を `DEV_DEPLOYMENT_ID` から、`APP_BUILD_ID` を `DEV_APP_BUILD_ID` から読みます。両 compose file は同じリポジトリの `.env` と同じ `backend-db` volume を使いますが snapshot store は異なるため、共通の値では 2 つの stack の履歴 namespace とキャッシュ結果が混ざるからです。したがって `.env` の `DEPLOYMENT_ID` と `APP_BUILD_ID` は配布用 stack にだけ適用されます。`EXTERNAL_CHANGE_SETTLE_SECONDS` は小数を指定でき、表の他の数値変数は整数のみを受け付けます。解釈できない値(整数の変数に対する `1.5`、数値でない文字列、有限でない数値 `1e999` など)を指定すると backend は起動を停止し、負の値は警告なしに `0` として扱われます(たとえば `HISTORY_GC_GRACE_SECONDS=-1` では garbage collection の猶予がなくなります)。`0` は文字どおりの上限で、無制限を意味しません。`RESULT_CACHE_MAX_BYTES=0` または `RESULT_CACHE_MAX_ENTRIES=0` ではキャッシュ結果は保存直後にすべて削除され、`SNAPSHOT_DIFF_MAX_BYTES=0` では空でない file がすべて too large となり、`SNAPSHOT_DIFF_MAX_LINES=0` では差分の行は表示されず、差分のある行を 1 行以上含む text file はすべて truncated となります(binary と too large の file はその表示のままです)。

| 変数 | 既定値 | 用途 |
| --- | --- | --- |
| `DATA_DIR` | `/app/data`(その directory が存在する場合) | 永続データ directory(Docker では `backend-db` volume)。存在しない場合は一時 directory を使って WARNING を出力し、version 管理と結果キャッシュを無効にします。Docker 外で実行する場合は `DATA_DIR` を設定してください。 |
| `RESULT_CACHE_DIR` | `<DATA_DIR>/result_cache` | 結果キャッシュの directory。 |
| `SNAPSHOT_HISTORY_DIR` | `<DATA_DIR>/snapshot_history` | 履歴 object store。 |
| `DEPLOYMENT_ID` | `<SNAPSHOTS_DIR>/.topologix-store.json` 内の UUID | この stack の履歴 namespace。後述の namespace の説明を参照してください。開発用 stack は `DEV_DEPLOYMENT_ID`。 |
| `APP_BUILD_ID` | backend の source から算出 | キャッシュ key に含まれる backend build id。通常は空のままにします。算出される id は `app.py`、`config.py`、`requirements.txt` と `services/`、`security/`、`database/`、`utils/`、`models/` 以下の Python file を対象にします。設定する場合は backend の build ごとに一意にしてください。固定値では、更新後の backend が古いコードで計算した結果を返します。開発用 stack は `DEV_APP_BUILD_ID`。 |
| `RESULT_CACHE_ENABLED` | `true` | kill switch。空、または大文字小文字を問わない `true`(`TRUE`、`True`)でキャッシュを有効にし、それ以外の値で無効にします(後述)。`DATA_DIR` が一時 directory の場合や保存先 directory が重複する場合も、キャッシュは無効です。 |
| `RESULT_CACHE_MAX_BYTES` | `536870912`(512 MiB) | キャッシュ directory 全体のサイズ上限。 |
| `RESULT_CACHE_MAX_ENTRIES` | `4000` | キャッシュ directory 全体の entry 数上限。 |
| `RESULT_CACHE_PROTECT_SECONDS` | `900` | この時間内に保存または返された結果は最後に削除されます。 |
| `HISTORY_GC_GRACE_SECONDS` | `600` | garbage collection(起動時、1 時間ごと、履歴削除後に実行)は、これより新しい未参照の履歴 object を残します。snapshot の削除と管理者向け purge はこの猶予を使いません。 |
| `HISTORY_ACCEPT_STORE_LOSS` | 空 | object store の喪失を受け入れます。後述の復旧手順を参照してください。 |
| `EXTERNAL_CHANGE_SETTLE_SECONDS` | `10` | API 外の変更を version にするまでの静止時間。 |
| `BATFISH_VERSION_PROBE_TTL_SECONDS` | `300` | probe で取得した Batfish version を再利用する秒数。 |
| `BATFISH_VERSION_GRACE_SECONDS` | `3600` | Batfish に接続できない間、最後に確認した version でキャッシュ結果を返し続ける秒数。最後に成功した version の probe または snapshot の有効化から数えます。 |
| `SNAPSHOT_DIFF_MAX_BYTES` | `524288`(512 KiB) | file 単位の差分のサイズ上限。 |
| `SNAPSHOT_DIFF_MAX_LINES` | `2000` | file 単位の差分の行数上限。 |

保存先 directory の重複禁止: `SNAPSHOTS_DIR`、`RESULT_CACHE_DIR`、`SNAPSHOT_HISTORY_DIR`、`<DATA_DIR>/_invalid-namespace` は互いに同一であっても、互いを含んでもいけません。また `DATA_DIR` は `SNAPSHOTS_DIR` と同一であっても、その内側にあってもいけません。違反すると起動時に ERROR を 1 件出力し、結果キャッシュを無効にし、version 管理を利用不可(reason `storage`)にします。

kill switch: `RESULT_CACHE_ENABLED=false` では、要求は結果キャッシュがない場合と同じように動作します。キャッシュ対象の endpoint は `Cache-Control: no-store` で識別 header なしに応答し、Batfish は従来どおり snapshot 名で読み込まれ、`AUTH_ENABLED=false` の active snapshot は起動時に再選択されません。**キャッシュ結果をクリア** は何もクリアせず、snapshot の再 parse には Header の「現在のスナップショットを再読込」button を使います。snapshot の version 管理と Batfish へのコピー送信は有効なままです。

database は version 履歴を保存するため、どちらの認証モードでも初期化されます。`AUTH_ENABLED=false` で database に障害が起きた場合、backend は停止せず version 管理が利用不可になります。compose file を使わない場合の `DATABASE_URL` の既定値は `sqlite:///<backend directory>/topologix.db` のままで、`DATA_DIR` を明示的に設定し、かつ従来の `<backend directory>/topologix.db` がない場合にだけ `<DATA_DIR>/topologix.db` になります(従来の file がある場合は WARNING を出力してそれを使います)。両 compose file は `sqlite:////app/data/topologix.db` を設定します。

#### namespace と DEPLOYMENT_ID

履歴の row は namespace で区別されます。`DEPLOYMENT_ID` を設定した場合はその値、設定しない場合は backend が初回起動時に snapshot store の root の `.topologix-store.json` に書き込む UUID です。この marker の書き込みには hard link に対応した filesystem が必要で、対応していない場合は version 管理が利用不可(reason `namespace`)になり、ERROR が対処方法として `DEPLOYMENT_ID` を示します。`DEPLOYMENT_ID` は `^[A-Za-z0-9_-]{1,64}$` に一致し、`result_cache`、`snapshot_history`、`_invalid-namespace` 以外で、`<DATA_DIR>/<DEPLOYMENT_ID>` が上記の重複禁止の directory と重ならない必要があります。不正な値や読めない marker では version 管理が利用不可(reason `namespace`)になり ERROR を 1 件出力しますが、application は動作を続けます。

- 複数の stack が 1 つの database または `backend-db` volume を共有する場合(2 つの compose file がそうです)は `DEPLOYMENT_ID` の設定を推奨します。
- 既存の環境で `DEPLOYMENT_ID` を使い始める場合は、その環境の `.topologix-store.json` 内の UUID を設定してください。それ以外の値では履歴が切り離されます。
- snapshot store を移動するときは `.topologix-store.json` も残してください。database を共有する別の stack 用に store を複製した場合は、複製側から削除してください(または stack ごとに異なる `DEPLOYMENT_ID` を設定してください)。そうしないと両方の store が snapshot ごとに 1 つの履歴を共有します。
- 新しい namespace での初回起動時、現在の store の snapshot が他の namespace に履歴を持っていると WARNING を 1 件出力します(その namespace と最終確認日時、row 数を表示)。原因は 2 つです。同じ環境の namespace が変わった場合(`DEPLOYMENT_ID` の導入・変更、または marker なしでの store の移動)は、以前の `DEPLOYMENT_ID` または marker の値に戻すと履歴がそのまま再び結び付きます。または管理者向け namespace 一覧を確認してから、切り離された namespace を purge します。database を共有する別の stack から snapshot folder をコピーした場合は対応不要で、コピーは独自の履歴を開始します。
- 切り離された履歴は、`GET /api/admin/snapshot-history/namespaces` を確認したうえで、`namespace` と `confirm` を指定する管理者向け purge(後述の復旧手順)でのみ削除できます。この purge は、どの stack のものであってもその namespace の履歴を削除します。停止中の別 stack の namespace は、切り離された namespace と区別できません。

#### 保存領域、容量、backup

| `DATA_DIR` 以下の path | 内容 |
| --- | --- |
| `topologix.db` | 既定の SQLite database。version の row と、`AUTH_ENABLED=true` では user 情報。 |
| `snapshot_history/<db_id>/objects/<aa>/<sha256>` | すべての version の file 内容(内容ごとに 1 つだけ保存。`snapshot_history/` は `SNAPSHOT_HISTORY_DIR` の既定値)。`<db_id>` は database に保存された database の識別子です。 |
| `snapshot_history/<db_id>/tmp/`、`snapshot_history/<db_id>/trash/` | 一時的なもの: 書き込み中の object と、garbage collection が削除中の object。 |
| `result_cache/<content_hash>/<key_hash>.json.gz`、`result_cache/tmp/` | content hash ごとのキャッシュされた Batfish の結果(Topologix の header に gzip 圧縮した body が続く形式で、単純な gzip file ではありません)と、書き込み中の entry(`result_cache/` は `RESULT_CACHE_DIR` の既定値)。 |
| `<namespace>/staging/<snapshot_id>/<snapshot 名>/` | Batfish が parse する file の一時的なコピー(snapshot に id がまだない間は `<snapshot_id>` の代わりにランダムな directory 名)。namespace が不正な間は `_invalid-namespace/staging/` を使い、`DATA_DIR` が `SNAPSHOTS_DIR` の内側にある間(または不正な namespace の `_invalid-namespace` が他の保存先 directory と重なる間)はシステムの一時 directory 内の directory を使います。 |
| `<namespace>/active_snapshot.json` | `AUTH_ENABLED=false` で最後に activate した snapshot。namespace が不正な間は書き込みません。 |

履歴 object とキャッシュ結果には設定ファイルの内容が含まれ、`0700` の directory 内に mode `0600` で書き込まれます。object は重複排除されるため、version ごとの容量は変更された file の分だけです。最初の `baseline` は既存の snapshot ごとに 1 回コピーを保存します。約 170 個のテキスト設定ファイルを持つ snapshot が 130 個あり、その大部分が version 間で共通であれば、1 GB を大きく下回ります。キャッシュの既定の上限は 512 MiB と 4000 entry です(170 node の all-data 結果で約 1 MB)。backend container は起動のたびに `/app/data` の所有者を再帰的に変更するため、履歴が非常に大きいと起動が遅くなります。

- database、`SNAPSHOT_HISTORY_DIR`、snapshot store は、backend を停止した状態でまとめて backup・restore してください。対応する object store なしで restore した database では、影響を受ける snapshot が `missing_objects` に、object が 1 つも残っていない場合は store 全体が `storage` になります。
- `DATABASE_URL` を新しい空の database に切り替えると、履歴は空から始まります。以前の database の object は、手動で削除するまで `snapshot_history/<old db_id>/` に残ります。
- database のコピー(backup からの restore、複製)は `db_id` を引き継ぎます。元の環境が使う `SNAPSHOT_HISTORY_DIR` に対して、一時的であってもコピーを実行しないでください。コピー側の garbage collection が、元の環境の新しい version だけが参照する object を削除します。object store を database と一緒にコピーし、`SNAPSHOT_HISTORY_DIR` をそのコピーに向け、コピー側には専用の `RESULT_CACHE_DIR`(または `DATA_DIR`)を設定してください。キャッシュの owner scope と clear の記録も同じ `db_id` から作られるためです。

#### 復旧手順

version 管理を利用できない場合、version の route、version-state、`cache/clear` は `503`(`code: versioning_unavailable`、`details.reason`)を返し、キャッシュ対象の endpoint はキャッシュを使わず、upload や編集は引き続き動作します。利用できない間に書き込まれた変更は、復旧後に記録されます。通常は外部での変更として記録されますが、一時的な database 障害の間の書き込みは(backend が再起動されない限り)未コミットの変更として記録されます。

| reason | 原因 |
| --- | --- |
| `storage` | 一時 directory の `DATA_DIR`、保存先 directory の重複、object store がない・読み取れない(所有者の誤りや mount の不備など)・現在の namespace が参照する object を 1 つも持たない、または起動時の object 確認が database 以外の理由で失敗した。 |
| `database` | database の初期化または実行時の障害。 |
| `namespace` | 不正な `DEPLOYMENT_ID`、または store marker を作成・読み込み・解析できない、もしくは marker の値が不正。 |
| `sidecar` | snapshot directory が読み取り専用で `snapshot_id` を保存できない。 |
| `missing_objects` | snapshot 単位: 起動時にその version の object が見つからない、またはサイズが異なる。 |

- `missing_objects`: 起動時に影響を受ける snapshot ごとに ERROR を 1 件出力し、その snapshot の履歴 panel では **履歴を削除（すべて）**(`DELETE /api/snapshots/<name>/versions` に `{"mode": "all", "expected_unavailable": "missing_objects"}`)だけが使えます。これで履歴がリセットされ、commit するまで「バージョンはまだありません」と表示されます。API で snapshot を削除した場合もその履歴は削除されます。storage や compose の変更後に複数の snapshot が `missing_objects` になった場合は、まず object store の mount を確認してください。起動時の確認は現在の namespace の参照だけを見るため、store 全体を失った後に履歴のない別 stack が先に起動して同じ hash の object を作り直すと、`storage` ではなく snapshot ごとの喪失として表示されます。
- object store の喪失: version の row が object を参照しているのに object store がない、またはそのいずれも持たない場合、起動時に ERROR "Snapshot history object store `<SNAPSHOT_HISTORY_DIR>/<db_id>/objects` is missing ..." を出力し、環境全体で version 管理が利用不可(reason `storage`)になります。store を復元する(`DATA_DIR`、`SNAPSHOT_HISTORY_DIR`、volume の mount を確認する)か、喪失を受け入れてください。受け入れる場合は、`HISTORY_ACCEPT_STORE_LOSS` にその path の `<db_id>` を設定して再起動し、影響を受ける各 snapshot の履歴を **履歴を削除（すべて）** でリセットし、起動時の WARNING が `0 snapshots are marked missing_objects` を示したら変数を削除します。それ以外の値は WARNING を出力して無視されます。
- orphan: API を通さずに削除された snapshot directory と、database または snapshot の `snapshot_id` を利用できない間に API で削除された snapshot は、orphan の履歴 row と object を残します。1 時間ごとの scan(1 時間ごとの保守処理の一部で、前回の実行から 1 時間以上たった後の最初の要求で開始されます)がそれらに印を付け、起動のたびに一覧の WARNING を出力しますが、移動中や一時的に unmount された store の履歴を失わないよう、自動では削除しません。`DELETE /api/admin/snapshot-history/orphans` に `{"older_than_days": N}`(N 日以上見つからない row)を指定して削除してください。
- 切り離された namespace: `DELETE /api/admin/snapshot-history/orphans` に `{"namespace": "<ns>", "confirm": "<ns>"}` を指定すると、現在のものではないその namespace の履歴 row と staging directory をすべて削除します。

#### API route

| Route | 要求 | 応答 |
| --- | --- | --- |
| `GET /api/snapshots/<name>/version-state` | — | 作業 file の content hash、head version、未コミット・外部変更の状態、Batfish の読み込み状態。 |
| `GET /api/snapshots/<name>/versions` | query `limit`(1-200、既定 50)と `offset`(0 以上)。どちらも省略可。 | `{"items", "total"}`(新しい順)。 |
| `POST /api/snapshots/<name>/versions` | `{"message", "expected_head"?}`。`message` は前後の空白を除いて 1-500 文字。 | 新しい version と `201`。作業 file が head version と同じ場合は `409` `version_unchanged`。 |
| `GET /api/snapshots/<name>/versions/<version_id>` | — | `files` 付きの version。 |
| `DELETE /api/snapshots/<name>/versions/<version_id>` | 省略可能な `{"expected_head"?}`。 | `{"deleted", "head"}`。 |
| `DELETE /api/snapshots/<name>/versions` | `{"mode": "all"}` または `{"mode": "oldest" \| "newest", "count"}`(`oldest` と `newest` では `count` が必須)。どちらにも省略可能な `"expected_head"`、`"expected_total"`(`all` では比較しない)、`"expected_unavailable"` を指定できます。 | `{"deleted", "head"}`。 |
| `POST /api/snapshots/<name>/versions/<version_id>/restore` | 省略可能な `{"expected_working_hash"?}`。 | `{"requires_reinitialize", "restored_from"}`。version の path が作業 file と衝突する場合は `details.reason: "path_clash"` と `details.path` 付きの `409` `version_conflict`。復元前に作業 file の変更を確定できない場合、snapshot の識別情報を解決できないか途中で変わった場合(削除と再作成など)、version の object が見つからないか壊れている場合、version の object と path の確認中に予期しないエラーが起きた場合、作業 file の削除や書き込みに失敗した場合は `500` `restore_failed`。作業 file がすでに変更されている可能性があるのは最後の場合だけです。削除や書き込みの前に、その version のすべての object と path を確認します。 |
| `GET /api/snapshots/<name>/versions/<version_id>/diff` | query `against`(version id または `working`)。必須。 | `{"from", "against", "files"}`。`against=working` では `"working_content_hash"` も含みます。 |
| `GET /api/snapshots/<name>/versions/<version_id>/diff/file` | query `against` と `path`(どちらかの側の file)。どちらも必須。 | `{"path", "binary", "too_large", "truncated", "hunks"}`。 |
| `POST /api/snapshots/<name>/cache/clear` | body なし、または JSON object。 | `{"cleared": true}`(snapshot は次回の利用時に再 parse されます)。`RESULT_CACHE_ENABLED` でキャッシュが無効な場合(何も行いません)と content hash がまだ確定していない場合(snapshot は次回の利用時に再 parse されます)は `{"cleared": false}`。一時 directory の `DATA_DIR` や保存先 directory の重複でもキャッシュは無効になりますが、この場合は version 管理を利用できない他の理由と同じく `503` `versioning_unavailable`(`storage`)を返します。 |
| `GET /api/cache/stats` | — | `{"entries", "bytes", "max_bytes", "max_entries"}`。 |
| `GET /api/admin/snapshot-history/namespaces` | — | `{"items": [{"namespace", "current", "first_seen_at", "last_seen_at", "rows"}]}`。 |
| `DELETE /api/admin/snapshot-history/orphans` | `{"older_than_days"}`(現在の namespace で、その日数以上見つからない orphan)または `{"namespace", "confirm"}`(現在のものではない namespace。`confirm` には `namespace` と同じ値を指定)。 | `{"purged", "last_seen_at"}`(orphan の場合 `last_seen_at` は `null`)。現在の namespace や一致しない `confirm` では `400`、存在しない namespace では `404` `namespace_not_found`。 |

共通のエラー: JSON object でない body には `400` `invalid_json`(body が必須なのは `POST .../versions`、`DELETE .../versions`、orphan の purge)、不正な field や query parameter には `400` `validation_error`、不正な snapshot 名には `400`、snapshot の認可では `403` と `404` `snapshot_not_found`、その snapshot に属さない version id には `404` `version_not_found`、`expected_head`、`expected_total`、`expected_working_hash`、`expected_unavailable` が一致しない場合、その snapshot への API 書き込み中、commit の準備中に作業 file が変わり続けた場合、復元の準備中に作業 file が変わった場合は `409` `version_conflict`、version 管理を利用できない場合は `details.reason` 付きの `503` `versioning_unavailable`(復旧手順を参照)を返します。

`AUTH_ENABLED=true` では snapshot の route は owner のみ、`cache/stats` と `admin` の route は admin role が必要です。`AUTH_ENABLED=false` では他の route と同じく制限なしで利用できます。

#### 更新時の注意

- frontend と backend の image は、その release の backend image が公開された後に一緒に更新してください。古い backend 上の新しい frontend は、`AUTH_ENABLED=false` では browser のキャッシュから編集前の topology を最大 5 分間表示することがあります。
- この機能を持たない backend から更新した後は、編集前に 5 分待つか、browser でサイトのキャッシュデータを削除してください。古い backend の応答が browser にキャッシュされ、その間は使われ続けるためです。

#### 開発時の注意

- 開発用 compose file は `./snapshots` を backend に bind mount します。host の editor でそこに保存した変更は API 外の変更であり、静止時間の経過後に自動で `external` version として記録されます(未コミットの変更がある間は保留になります)。
- 結果キャッシュは backend の getter の出力を保存します。キャッシュ対象の endpoint が返す内容を修正で変える場合は、保存済みの結果が再計算されるよう `backend/config.py` の `RESULT_CACHE_SCHEMA_VERSION` を上げてください。算出される build id は hash 対象の backend source を編集するたびに変わりますが、`APP_BUILD_ID` に同じ値を設定している場合は変わりません。

### 運用上の注意

- `AUTH_ENABLED` と `VITE_AUTH_ENABLED` は必ず一致させてください。
- 本番運用では `SECRET_KEY`, `JWT_SECRET_KEY`, `CSRF_SECRET_KEY` を明示的に設定してください。
- `SQLALCHEMY_ECHO` は既定の `false` のままにしてください。SQL 値には password hash などの機密性が高い運用情報が含まれる可能性があります。
- backend は gunicorn worker 1 で運用してください(image の既定値と compose は 1 に設定済みです)。Batfish session 状態・request lock・自動生成 secret は process-local のため、複数 worker では active snapshot の状態がリクエスト間で分裂します。
- snapshot の保存先はスタックごとに異なります: 開発用 compose はリポジトリの `./snapshots` をバインドし、配布用 compose は named volume(`snapshots-data`)に保存します。同一ホストで両者を切り替えると、もう一方で作成した snapshot は表示されません。
- reverse proxy を使う場合、`BEHIND_REVERSE_PROXY` と `TRUSTED_PROXY_COUNT` を実際の構成に合わせてください。
- Batfish container image は、固定した pybatfish バージョンで検証済みの digest を既定値としています。別バージョンを試す場合は `BATFISH_IMAGE` で上書きしてください。`/api/health` は pybatfish バージョンと、最初の snapshot 初期化後は稼働中の Batfish サーバーバージョンを返します。
- 1 つの Batfish クエリの実行上限は `BATFISH_QUERY_TIMEOUT_SECONDS`(既定 120 秒)で調整できます。値は整数で指定し、10 未満は 10 に引き上げられ、整数でない場合は backend が起動を停止します。両 Compose はこの値を backend コンテナへ明示的に渡します。

## License

Apache License 2.0
