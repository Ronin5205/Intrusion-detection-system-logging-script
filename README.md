# Snort Log Analysis

**Full step-by-step guide:** see [GUIDE.md](GUIDE.md) (Snort install → Nmap attacks → CSV reports).

Python log analysis for Snort **unified2** alert logs.

**Section 2.4 (initial):** read unified2 logs, extract fields, write CSV, flag likely scanners.

**Section 4.3 (advanced):** multi-stage rule-based classification with risk scoring — no machine learning.

## Features

- Parses unified2 binary logs via `idstools`
- Resolves alert messages from `sid-msg.map` / `gen-msg.map`
- Resolves classifications from `classification.config`
- Extracts timestamp, source/destination IP, ports, protocol, signature ID, priority
- Advanced classification rules:
  - Port Scan
  - ICMP Flood
  - Brute Force
  - High Risk Host
- Assigns risk levels: Low, Medium, High, Critical
- Writes `alerts.csv` and `summary.txt`
- **Real-time watch mode** — monitors unified2 logs for new data with inotify + polling fallback

## Project Structure

```
SnortIDS/
├── config/config.json
├── reports/
├── .state/               # read checkpoints (watch mode)
└── src/
    ├── main.py
    ├── parser.py
    ├── watcher.py
    ├── maps_loader.py
    ├── classifier.py
    ├── report.py
    └── utils.py
```

## Requirements

- Python 3.10+
- Snort writing **unified2** logs
- Snort map files (`sid-msg.map`, optional `gen-msg.map`, `classification.config`)

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Edit [`config/config.json`](config/config.json):

```json
{
  "log_directory": "/var/log/snort",
  "sid_msg_map": "/etc/snort/community-sid-msg.map",
  "extra_sid_msg_maps": ["./config/local-sid-msg.map"],
  "output_csv": "./reports/alerts.csv",
  "scan_threshold": 20,
  "time_window_seconds": 60
}
```

| Setting | Purpose |
|---------|---------|
| `log_directory` | Directory containing unified2 log files |
| `sid_msg_map` | Main Snort signature map (Ubuntu: `community-sid-msg.map`) |
| `extra_sid_msg_maps` | Additional maps for custom `local.rules` SIDs |
| `gen_msg_map` | Snort generator message map (optional) |
| `classification_config` | Snort classification.config |
| `scan_threshold` | Alerts per source IP to classify as Port Scan |
| `watch_mode` | `true` = real-time monitoring, `false` = one-shot batch |
| `poll_interval_seconds` | Fallback poll interval when file events are missed |
| `report_interval_seconds` | How often CSV/summary are refreshed in watch mode |
| `icmp_flood_threshold` | ICMP alerts in window to classify as ICMP Flood |
| `brute_force_threshold` | Login-related alerts to classify as Brute Force |

## Usage

**Real-time watch mode (default):**

```bash
python -m src.main
```

Watches `log_directory` for new unified2 data, updates reports every few seconds. Press `Ctrl+C` to stop.

**One-shot batch mode** — set `"watch_mode": false` in config, then:

```bash
python -m src.main
```

Optional custom config:

```bash
python -m src.main /path/to/config.json
```

If log files are not readable, copy them locally and update `log_directory`:

```bash
sudo cp /var/log/snort/snort.log* ./logs/
sudo chown -R $USER:$USER ./logs/
```

## Output

**`reports/alerts.csv`**

| Column | Description |
|--------|-------------|
| `timestamp` | Alert time (UTC ISO format) |
| `src_ip` / `dst_ip` | Source and destination addresses |
| `protocol` | TCP, UDP, ICMP, etc. |
| `message` | Resolved Snort rule message |
| `attack_type` | Port Scan, ICMP Flood, Brute Force, High Risk Host |
| `risk_level` | Low, Medium, High, Critical |
| `likely_scanner` | True when classified as Port Scan |

**`reports/summary.txt`** — totals, attack type counts, top source IPs.

## Dependencies

- `idstools` — unified2 parsing and map loading

Python standard library handles everything else.
