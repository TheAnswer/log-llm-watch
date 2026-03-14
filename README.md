# Log LLM Watch

A FastAPI service that ingests infrastructure logs from multiple sources (Dozzle/Docker, Windows Event Logs, syslog), clusters them into incidents, and uses a local Ollama LLM to analyze root causes, generate suppression rules, and produce daily/weekly health reports — all delivered via ntfy notifications.

## Architecture

```
                  +-----------+    +---------+    +--------+
                  |  Dozzle   |    | Windows |    | syslog |
                  | (Docker)  |    |  nxlog  |    |        |
                  +-----+-----+    +----+----+    +---+----+
                        |               |             |
                   POST /dozzle    POST /windows  POST /syslog
                        |               |             |
                        +-------+-------+-------------+
                                |
                       +--------v--------+
                       |    FastAPI app   |
                       |   (app.py)      |
                       +--------+--------+
                                |
              +-----------------+-----------------+
              |                 |                 |
     +--------v------+  +------v------+  +-------v-------+
     |  Extraction   |  | Enrichment  |  |   Incident    |
     | (Dozzle/Win/  |  | (normalize, |  |  clustering   |
     |  Syslog)      |  |  classify,  |  |  & lifecycle  |
     +---------------+  |  fingerprint)|  +-------+-------+
                         +-----------+            |
                                           +------v------+
              +------------------+         |   Ollama     |
              | Background loop  +-------->|   LLM        |
              | (every 5 min)    |         | (analysis,   |
              +--------+---------+         |  reports,    |
                       |                   |  suppress)   |
          +------------+------------+      +------+-------+
          |            |            |             |
    +-----v----+ +----v-----+ +----v-----+  +----v-----+
    |  Daily   | |  Weekly  | |  Stale   |  |   ntfy   |
    |  report  | |  report  | | incident |  | notifs   |
    +----------+ +----------+ |  close   |  +----------+
                               +----------+
```

## Project Structure

```
/opt/log-llm-watch/
├── app.py                      # FastAPI entry point, middleware, router wiring
├── config.yaml                 # All runtime configuration
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Test runner configuration
├── events.sqlite3              # SQLite database (created at runtime)
│
├── core/                       # Pure logic, no external service calls
│   ├── config.py               # YAML config loader, utcnow(), global constants
│   ├── database.py             # Schema init, migrations, db() context manager
│   ├── extraction.py           # Parse Dozzle, Windows Event, and syslog payloads
│   └── normalize.py            # Fingerprinting, severity mapping, event classification
│
├── services/                   # Business logic with side effects
│   ├── ollama.py               # Ollama HTTP client (generate, chat), token tracking, context overflow detection
│   ├── notifications.py        # ntfy push notifications with DB logging
│   ├── suppression.py          # Rule caching, regex matching, LLM-assisted auto-suppress
│   ├── incidents.py            # Incident lifecycle, LLM analysis, false-positive auto-close
│   ├── ingestion.py            # Event storage pipeline, backfill, ignore filtering
│   ├── reports.py              # Daily/weekly report prompt building and delivery
│   ├── housekeeping.py         # Data retention, stale suppress rule pruning, vacuum
│   └── background.py           # Main analysis loop, health checks, scheduled tasks
│
├── routes/                     # FastAPI routers (thin HTTP layer)
│   ├── webhooks.py             # POST /dozzle, /windows, /syslog, GET /healthz
│   ├── incidents_api.py        # CRUD, analysis, suppression endpoints
│   ├── events_api.py           # Event search and timeline queries
│   ├── stats_api.py            # LLM stats, LLM call log, ntfy notification log
│   ├── suppress_api.py         # Suppression rule list and delete
│   ├── admin.py                # Config reload, backfill, manual report triggers, vacuum
│   ├── chat_api.py             # Multi-turn LLM chat for incident investigation
│   └── tools.py                # Simplified endpoints for external integrations (OpenWebUI)
│
└── tests/                      # pytest unit tests
    ├── conftest.py             # Shared fixtures (temporary SQLite DB)
    ├── test_config.py
    ├── test_database.py
    ├── test_normalize.py
    ├── test_extraction.py
    ├── test_suppression.py
    ├── test_ingestion.py
    ├── test_incidents.py
    ├── test_housekeeping.py
    ├── test_ollama.py
    └── test_reports.py
```

### Module dependency flow

```
core/  -->  services/  -->  routes/  -->  app.py
```

`core/` has no service dependencies. `services/` imports from `core/` and calls external systems (Ollama, ntfy). `routes/` are thin wrappers that import from `services/`. `app.py` wires everything together.

## Setup

### Prerequisites

- Python 3.12+
- A running [Ollama](https://ollama.ai) instance with a model pulled (default: `qwen3.5:9b`)
- [ntfy](https://ntfy.sh) for notifications (self-hosted or public)

### Installation

```bash
cd /opt/log-llm-watch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration

Edit `config.yaml` to match your environment. Key sections:

```yaml
ollama:
  url: "http://localhost:11434"
  model: "qwen3.5:9b"
  timeout_seconds: 300
  num_ctx: 131072               # Context window (tokens)

notify:
  ntfy_url: "http://localhost:2586/your_topic"
  title: "NAS log alert"

storage:
  db_path: "/opt/log-llm-watch/events.sqlite3"
```

Other configuration options:

| Section | Key | Default | Description |
|---|---|---|---|
| `analysis` | `batch_window_minutes` | `5` | How often the background loop runs |
| `analysis` | `min_events_before_analysis` | `1` | Minimum events to trigger LLM analysis |
| `analysis` | `max_examples_per_group` | `5` | Sample messages kept per fingerprint group |
| `analysis` | `ignore_if_older_than_hours` | `24` | Skip events older than this |
| `daily_report` | `enabled` | `true` | Enable automatic daily reports |
| `daily_report` | `hour` / `minute` | `9` / `0` | When to send the daily report |
| `weekly_report` | `enabled` | `true` | Enable automatic weekly reports |
| `weekly_report` | `weekday` | `0` | Day of week (0 = Monday) |
| `incidents` | `open_window_minutes` | `10` | Time window for grouping events into one incident |
| `incidents` | `close_after_minutes` | `30` | Auto-close incidents after inactivity |
| `retention` | `events_days` | `14` | How long to keep raw events |
| `retention` | `suppress_rules_stale_days` | `30` | Prune auto-created suppress rules with no hits |
| `filters` | `ignore_message_regex` | (list) | Regex patterns to silently drop on ingestion |

### Running

**Direct:**

```bash
source venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8088 --timeout-keep-alive 65
```

**Systemd service** (`/etc/systemd/system/log-llm-watch.service`):

```ini
[Unit]
Description=Homelab LLM Watch
After=network.target

[Service]
Type=simple
User=theanswer
WorkingDirectory=/opt/log-llm-watch
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/log-llm-watch/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8088 --timeout-keep-alive 65
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> The `--timeout-keep-alive 65` flag is important for nxlog clients that use HTTP keep-alive connections.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now log-llm-watch
```

## Webhook Ingestion

### Dozzle (Docker logs)

Configure Dozzle to send webhook notifications to `http://<host>:8088/dozzle`. The payload follows Dozzle's Slack-compatible block format.

### Windows Event Logs (nxlog)

Point nxlog `om_http` output to `http://<host>:8088/windows`. The service accepts standard Windows Event Log JSON fields (`Hostname`, `Channel`, `EventID`, `Message`, `SeverityValue`, etc.).

### Syslog

Forward syslog messages as JSON to `http://<host>:8088/syslog`. Expected fields: `host`, `program`/`appname`, `message`.

## Event Processing Pipeline

1. **Extraction** — Parse source-specific payload into a normalized event structure
2. **Ignore check** — Drop events matching `ignore_message_regex` patterns or active suppress rules
3. **Enrichment** — Classify event type, normalize severity, infer host type and service metadata, generate fingerprints
4. **Incident clustering** — Attach to an existing open incident with the same canonical fingerprint, or create a new one
5. **Storage** — Write to SQLite with full enrichment fields

### Background loop (every 5 minutes)

- Close incidents with no new events for 30 minutes
- Batch-analyze unprocessed events with LLM, notify via ntfy for actionable findings
- Auto-suppress groups the LLM classifies as "ignore" by generating regex rules
- Analyze incidents that lack LLM summaries, auto-close false positives
- Send daily/weekly reports at configured times
- Run data retention cleanup and stale suppress rule pruning
- Flush in-memory suppress rule hit counters to the database

## Event Classification

Events are automatically classified into types based on message content:

| Event Class | Dependency | Triggered By |
|---|---|---|
| `dns_failure` | dns | "temporary failure in name resolution", "no such host" |
| `connect_refused` | network | "connection refused" |
| `database_locked` | storage | "database is locked" |
| `oom_kill` | memory | "out of memory", "killed process" |
| `tls_or_cert_issue` | tls | "tls", "x509", "certificate" |
| `timeout` | network | "timeout" |
| `proxy_upstream_failure` | proxy | "bad gateway", "upstream failed" |
| `failed_logon` | auth | Windows Security EventID 4625 |
| `auth_failure` | auth | "failed password", "authentication failed" |
| `no_space_left` | storage | "no space left" |
| `ups_usb_comm_error` | ups | "usbhid-ups" + "input/output error" |

## Suppression Rules

Suppress rules prevent known-noisy events from creating incidents or triggering notifications. Four match types:

| Type | Matches On | Example Use |
|---|---|---|
| `fingerprint` | Canonical fingerprint hash | Suppress a specific normalized message pattern |
| `event_class` | Event classification | Suppress all `dns_failure` events globally |
| `event_class_host` | Class + host | Suppress `timeout` only on a specific host |
| `message_regex` | Regex against message | Flexible pattern matching |

Auto-created rules (`reason LIKE 'auto:%'`) are pruned after 30 days without hits.

## LLM Integration

The service calls a local Ollama instance for:

- **Event analysis** — Classify batched event groups as ignore/low/medium/high severity
- **Incident analysis** — Determine root cause, confidence level, and whether an incident is a false positive
- **Suppress regex generation** — Generate precise regex patterns for events classified as noise
- **Daily/weekly reports** — Natural language health summaries with actionable recommendations
- **Incident digest** — On-demand summary of all open incidents
- **Incident chat** — Multi-turn conversational investigation scoped to a specific incident

All LLM calls are tracked with:
- Duration, prompt/completion token counts, model name
- Caller function (auto-detected via stack inspection)
- Response preview (first 1000 chars)
- Context overflow warnings at 95% of `num_ctx`

## API Reference

### Ingestion

| Method | Path | Description |
|---|---|---|
| `POST` | `/dozzle` | Ingest Dozzle Docker log webhook |
| `POST` | `/windows` | Ingest Windows Event Log |
| `POST` | `/syslog` | Ingest syslog message |
| `GET` | `/healthz` | Health check |

### Events

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/events` | Search events (params: `q`, `host`, `container`, `hours`, `limit`, `offset`) |
| `GET` | `/api/timeline` | Get events around a timestamp (params: `ts`, `minutes_before`, `minutes_after`) |

### Incidents

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/incidents` | List incidents (params: `status`, `severity`, `limit`, `offset`) |
| `GET` | `/api/incidents/{id}` | Incident detail with events |
| `PATCH` | `/api/incidents/{id}` | Update status (open/closed) |
| `GET` | `/api/incidents/{id}/context` | Full context with timeline and similar incidents |
| `GET` | `/api/incidents/{id}/context-filtered` | Filtered context (excludes noise) |
| `GET` | `/api/incidents/{id}/llm-context` | Context formatted for LLM analysis |
| `POST` | `/api/incidents/{id}/analyze` | Trigger LLM root-cause analysis |
| `POST` | `/api/incidents/{id}/suppress` | Create suppress rule and close incident |
| `POST` | `/api/incidents/{id}/chat` | Multi-turn LLM chat for incident investigation |
| `POST` | `/api/incidents/analyze-missing` | Batch-analyze incidents without summaries |
| `GET` | `/api/incidents/open/llm-digest` | LLM-generated digest of open incidents (cached 5 min) |

### Suppression Rules

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/suppress-rules` | List all rules with hit counts |
| `DELETE` | `/api/suppress-rules/{id}` | Delete a rule |

### Statistics

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/llm-stats` | LLM usage stats (params: `days`) |
| `GET` | `/api/event-stats` | Event counts, severity/source breakdowns (params: `days`) |
| `GET` | `/api/llm-log` | Recent LLM call log (params: `limit`) |
| `GET` | `/api/ntfy-log` | Recent notification log (params: `limit`) |

### Admin

| Method | Path | Description |
|---|---|---|
| `POST` | `/admin/reload-config` | Hot-reload config.yaml |
| `POST` | `/admin/backfill-events` | Re-enrich historical events |
| `POST` | `/daily-report-now` | Manually trigger daily report |
| `POST` | `/weekly-report-now` | Manually trigger weekly report |
| `POST` | `/vacuum-now` | SQLite VACUUM |

### Tool Integration (OpenWebUI)

Simplified endpoints under `/tool/` for use with external AI tools:

| Method | Path | Description |
|---|---|---|
| `GET` | `/tool/health` | Open incidents digest |
| `GET` | `/tool/open-incidents` | List open incidents |
| `GET` | `/tool/incident/{id}` | Incident detail |
| `GET` | `/tool/incident/{id}/context` | LLM context |
| `POST` | `/tool/incident/{id}/analyze` | Analyze incident |

## Testing

Tests use pytest with a temporary SQLite database per test (no production data touched).

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

### Test coverage

| Test File | Module | What's Tested |
|---|---|---|
| `test_config.py` | `core.config` | UTC datetime, JSON parsing |
| `test_database.py` | `core.database` | Schema creation, migrations, context manager |
| `test_normalize.py` | `core.normalize` | Message normalization, fingerprinting, severity mapping, event classification, enrichment |
| `test_extraction.py` | `core.extraction` | Dozzle/Windows/syslog payload parsing, level normalization |
| `test_suppression.py` | `services.suppression` | Rule loading, ignore matching, hit flushing, regex validation |
| `test_ingestion.py` | `services.ingestion` | Event storage, incident creation, ignore filtering |
| `test_incidents.py` | `services.incidents` | Incident titles, root causes, attach/create, stale closing |
| `test_housekeeping.py` | `services.housekeeping` | Stale suppress rule pruning (auto vs manual, recent hits) |
| `test_ollama.py` | `services.ollama` | Token extraction, context limit warnings |
| `test_reports.py` | `services.reports` | Report text cleaning (thinking tags, markdown, tables) |

## Database

SQLite with WAL mode. Schema is auto-created and auto-migrated on startup via `add_column_if_missing()`.

**Tables:**

| Table | Purpose |
|---|---|
| `events` | Raw and enriched log events |
| `incidents` | Clustered incidents with LLM analysis |
| `suppress_rules` | Active suppression rules with hit tracking |
| `analysis_runs` | Audit log of LLM analysis prompts and responses |
| `llm_call_log` | LLM call performance tracking (duration, tokens, errors) |
| `ntfy_log` | Notification delivery log |
| `daily_runs` | Deduplication for daily reports |
| `weekly_runs` | Deduplication for weekly reports |
| `housekeeping_runs` | Deduplication for cleanup jobs |
| `ignored_daily` | Daily counts of pre-storage ignored events |
| `llm_noise_fingerprints` | Temporary noise suppression |

## Frontend

A separate React dashboard is available at [`homelab-incident-dashboard`](../homelab-incident-dashboard/) for visualizing incidents, events, LLM stats, and suppression rules.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
