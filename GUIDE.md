# SnortIDS — Complete Usage Guide

End-to-end guide: install **Python**, **Snort**, and **Wireshark** on Ubuntu, run the Python analyzer, verify packets in Wireshark, generate test attacks with Nmap, and export CSV reports. Commands use `sudo` wherever log, capture, or config access requires it — no group or permission changes needed.

---

## 0. Live Preview

paste this file in a live markdown previewer like https://markdownlivepreview.com

---

## 1. Lab layout

| Machine | Role | Example IP |
|---------|------|------------|
| Ubuntu VM (Snort guest) | IDS + Python analyzer | `192.168.1.50` |
| Windows host or second VM | Attacker | `192.168.1.101` |

- VirtualBox: **Bridged Adapter** on the Ubuntu VM (same subnet as the attacker).
- Project folder on Ubuntu: `~/SnortIDS`
- Shared folder from Windows (optional): `/media/sf_SnortIDS`

**Example IPs used below** — replace with yours:

| Role | Variable | Example |
|------|----------|---------|
| Snort VM (HOME_NET) | `SNORT_IP` | `192.168.1.50` |
| Attacker | `ATTACKER_IP` | `192.168.1.101` |

---

## 2. Install software on Ubuntu VM

Install everything in one step, or section by section.

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv snort snort-rules-default wireshark tshark
```

### 2.1 Python

Required version: **Python 3.10+**.

```bash
python3 --version
which python3
```

If missing or too old:

```bash
sudo apt install -y python3 python3-pip python3-venv
```

Python is used for the log analyzer (`idstools`, `watchdog`). The venv is created in §4.2.

### 2.2 Snort

```bash
sudo apt install -y snort snort-rules-default
```

Verify:

```bash
snort -V
sudo ls /etc/snort/
sudo ls /etc/snort/rules/
```

### 2.3 Wireshark

Used to **capture and inspect raw packets** on the Snort VM and cross-check alerts against what actually crossed the wire (as described in the project plan).

```bash
sudo apt install -y wireshark tshark
wireshark --version
```

**Run Wireshark with sudo** so it can capture on the network interface without changing user groups:

```bash
# Find your interface name first
ip a
# Common names: enp0s3, eth0

sudo wireshark
```

Or start capture directly on the bridged interface:

```bash
sudo wireshark -i enp0s3 -k
```

(`-k` starts capturing immediately; replace `enp0s3` with your interface.)

Command-line alternative:

```bash
sudo tshark -i enp0s3
```

### 2.4 Nmap (attacker machine)

Install on the **attacker** (Windows: download from [nmap.org](https://nmap.org); Linux/Kali: `sudo apt install nmap`). Not required on the Snort VM unless you attack from the same box.

---

## 3. Configure Snort

### 3.1 Set HOME_NET (protect only the Snort VM)

```bash
ip a
```

Note your VM IP (e.g. `192.168.1.50`), then:

```bash
sudo nano /etc/snort/snort.conf
```

Set:

```text
ipvar HOME_NET 192.168.1.50/32
ipvar EXTERNAL_NET !$HOME_NET
```

Replace `192.168.1.50` with your actual IP. Alerts from other VMs/hosts will be **external → home**.

### 3.2 Confirm unified2 output

```bash
sudo grep -E "^output.*unified2" /etc/snort/snort.conf
```

You should see lines like:

```text
output alert_unified2: filename snort.log, ...
```

Unified2 logs appear as:

```text
/var/log/snort/snort.log*
/var/log/snort/unified2.log*
```

### 3.3 Custom test rules

```bash
sudo nano /etc/snort/rules/local.rules
```

Paste (single-line rules only):

```text
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"PROJECT ICMP ping detected"; itype:8; sid:1000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"PROJECT SSH connection attempt"; sid:1000002; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"PROJECT TCP SYN packet"; flags:S; sid:1000003; rev:1;)
```

Ensure `local.rules` is included:

```bash
sudo grep local.rules /etc/snort/snort.conf
```

### 3.4 Suppress noisy alerts (optional)

```bash
sudo nano /etc/snort/threshold.conf
```

Add at the bottom:

```text
suppress gen_id 1, sig_id 1917, track by_src, ip 192.168.1.1
suppress gen_id 1, sig_id 1917, track by_src, ip fe80::1
```

### 3.5 Test and start Snort

```bash
sudo snort -T -c /etc/snort/snort.conf
sudo systemctl enable snort
sudo systemctl restart snort
sudo systemctl status snort
```

Check logs exist:

```bash
sudo ls -la /var/log/snort/
sudo tail -5 /var/log/snort/snort.alert.fast
```

---

## 4. Install the Python analyzer

### 4.1 Copy project to Ubuntu

From shared folder:

```bash
cp -r /media/sf_SnortIDS ~/SnortIDS
cd ~/SnortIDS
```

Or keep working in `~/SnortIDS` and sync updates:

```bash
cp -r /media/sf_SnortIDS/src ~/SnortIDS/
cp -r /media/sf_SnortIDS/config ~/SnortIDS/
cp /media/sf_SnortIDS/requirements.txt ~/SnortIDS/
```

### 4.2 Python virtual environment

Confirm system Python first:

```bash
python3 --version
```

**Important:** create the venv on native disk (`~/SnortIDS`), not the VirtualBox shared folder:

```bash
cd ~/SnortIDS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Verify packages:

```bash
pip list | grep -E "idstools|watchdog"
```

Expected: `idstools` and `watchdog`.

### 4.3 Config check

Default `config/config.json` should include:

```json
{
  "log_directory": "/var/log/snort",
  "sid_msg_map": "/etc/snort/community-sid-msg.map",
  "extra_sid_msg_maps": ["config/local-sid-msg.map"],
  "classification_config": "/etc/snort/classification.config",
  "watch_mode": true
}
```

Custom rule messages are in `config/local-sid-msg.map` (SIDs 1000001–1000003).

---

## 5. Run the analyzer

Always run from the project directory with the venv active.

### 5.1 Real-time watch mode (default)

**Terminal 1** — start the analyzer (sudo for `/var/log/snort` access):

```bash
cd ~/SnortIDS
source .venv/bin/activate
sudo $(which python) -m src.main
```

Expected startup output:

```text
Loaded signature map from /etc/snort/community-sid-msg.map
Loaded signature map from .../config/local-sid-msg.map
Loaded classification map from /etc/snort/classification.config
Watching unified2 logs in /var/log/snort
Processed N new alerts from snort.log...
```

Stop with `Ctrl+C`.

### 5.2 Full reprocess (after code or config changes)

Clears checkpoints and re-reads all unified2 logs:

```bash
cd ~/SnortIDS
source .venv/bin/activate
sudo $(which python) -m src.main --reprocess
```

Run once, wait for processing to finish, then `Ctrl+C` or run in watch mode without `--reprocess`.

### 5.3 One-shot batch mode

Edit `config/config.json`:

```json
"watch_mode": false
```

Then:

```bash
sudo $(which python) -m src.main --reprocess
```

Exits automatically after writing reports.

---

## 6. Generate test attacks

Run these from the **attacker** (Windows host with Nmap, or a second VM). Replace `192.168.1.50` with your Snort VM IP.

### 6.1 ICMP smoke test

```bash
ping -c 10 192.168.1.50
```

### 6.2 TCP SYN / port scan (Nmap)

```bash
nmap -sS 192.168.1.50
```

Aggressive scan (more alerts):

```bash
nmap -sS -T4 -p- 192.168.1.50
```

### 6.3 SSH probe

```bash
nmap -p 22 192.168.1.50
```

### 6.4 Verify Snort saw traffic

On the Ubuntu VM:

```bash
sudo tail -f /var/log/snort/snort.alert.fast
```

---

## 7. Verify with Wireshark (cross-check analysis)

Use Wireshark to confirm that packets seen in captures **match** the `src_ip` / `dst_ip` values in `reports/alerts.csv`. This supports the project requirement for independent packet validation.

### 7.1 Start capture on the Snort VM

**Terminal 3** (while Snort and the analyzer are running):

```bash
ip a
sudo wireshark -i enp0s3 -k
```

Replace `enp0s3` with your bridged interface from `ip a`.

### 7.2 Wireshark display filters

Apply in the filter bar at the top of Wireshark. Replace IPs with your `SNORT_IP` and `ATTACKER_IP`.

**All traffic between attacker and Snort (both directions):**

```text
(ip.src == 192.168.1.101 && ip.dst == 192.168.1.50) || (ip.src == 192.168.1.50 && ip.dst == 192.168.1.101)
```

Shorter equivalent:

```text
ip.addr == 192.168.1.101 && ip.addr == 192.168.1.50
```

**Attack traffic only (external → HOME_NET, matches Snort rule direction):**

```text
ip.src == 192.168.1.101 && ip.dst == 192.168.1.50
```

**Response traffic only (Snort VM → attacker):**

```text
ip.src == 192.168.1.50 && ip.dst == 192.168.1.101
```

**All traffic involving the Snort VM (any peer):**

```text
ip.addr == 192.168.1.50
```

**ICMP ping test only:**

```text
icmp && ip.addr == 192.168.1.101 && ip.addr == 192.168.1.50
```

**TCP scan / SYN packets (typical Nmap -sS):**

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 192.168.1.101 && ip.dst == 192.168.1.50
```

### 7.3 Match Wireshark to CSV

1. Run Nmap or ping from the attacker.
2. In Wireshark, apply `ip.src == ATTACKER_IP && ip.dst == SNORT_IP`.
3. Note source/destination IPs and protocol in the packet list.
4. Compare with the same rows in `reports/alerts.csv`:

```bash
grep "192.168.1.101" ~/SnortIDS/reports/alerts.csv | head -5
```

The CSV `src_ip` should match Wireshark **Source**, and `dst_ip` should match **Destination** for inbound attack traffic.

### 7.4 Save a capture for your report

```bash
# Capture to file (run during attack, Ctrl+C to stop)
sudo tshark -i enp0s3 -f "host 192.168.1.50" -w ~/SnortIDS/reports/lab-capture.pcapng
```

Open later in Wireshark:

```bash
sudo wireshark ~/SnortIDS/reports/lab-capture.pcapng
```

Export to Windows:

```bash
sudo cp ~/SnortIDS/reports/lab-capture.pcapng /media/sf_SnortIDS/reports/
```

---

## 8. View reports

### 8.1 On Ubuntu (while analyzer runs)

**Terminal 2:**

```bash
watch -n 2 cat ~/SnortIDS/reports/summary.txt
```

Preview CSV:

```bash
head -5 ~/SnortIDS/reports/alerts.csv
column -t -s, ~/SnortIDS/reports/alerts.csv | head -5
```

### 8.2 CSV columns

| Column | Description |
|--------|-------------|
| `timestamp` | Alert time (UTC) |
| `src_ip` / `dst_ip` | Source and destination |
| `src_port` / `dst_port` | Ports |
| `protocol` | TCP, UDP, ICMP, etc. |
| `signature_id` | Snort rule SID |
| `priority` | Snort priority |
| `classification` | e.g. Attempted Recon |
| `message` | Rule message text |
| `attack_type` | Port Scan, ICMP Flood, Brute Force, High Risk Host |
| `risk_level` | Low, Medium, High, Critical |
| `likely_scanner` | True if classified as Port Scan |

### 8.3 Summary file

`reports/summary.txt` contains totals, attack type counts, and top source IPs.

---

## 9. Export CSV to Windows

```bash
sudo cp ~/SnortIDS/reports/alerts.csv /media/sf_SnortIDS/reports/
sudo cp ~/SnortIDS/reports/summary.txt /media/sf_SnortIDS/reports/
```

On Windows open:

```text
D:\Codes\SnortIDS\reports\alerts.csv
```

---

## 10. Quick command reference

| Task | Command |
|------|---------|
| Check Python version | `python3 --version` |
| Install Python + venv | `sudo apt install -y python3 python3-pip python3-venv` |
| Install Wireshark | `sudo apt install -y wireshark tshark` |
| Open Wireshark (capture) | `sudo wireshark -i enp0s3 -k` |
| Save capture to file | `sudo tshark -i enp0s3 -f "host SNORT_IP" -w ~/SnortIDS/reports/lab-capture.pcapng` |
| Snort config test | `sudo snort -T -c /etc/snort/snort.conf` |
| Restart Snort | `sudo systemctl restart snort` |
| Snort status | `sudo systemctl status snort` |
| Live Snort alerts | `sudo tail -f /var/log/snort/snort.alert.fast` |
| List unified2 logs | `sudo ls -la /var/log/snort/snort.log*` |
| Inspect unified2 | `sudo idstools-u2spewfoo /var/log/snort/snort.log.* \| head -5` |
| Edit Snort config | `sudo nano /etc/snort/snort.conf` |
| Edit custom rules | `sudo nano /etc/snort/rules/local.rules` |
| Edit suppressions | `sudo nano /etc/snort/threshold.conf` |
| Activate Python venv | `source ~/SnortIDS/.venv/bin/activate` |
| Run analyzer (live) | `sudo $(which python) -m src.main` |
| Reprocess all logs | `sudo $(which python) -m src.main --reprocess` |
| View summary | `cat ~/SnortIDS/reports/summary.txt` |
| View CSV header | `head -3 ~/SnortIDS/reports/alerts.csv` |
| ICMP test | `ping -c 10 <SNORT-VM-IP>` |
| Nmap scan | `nmap -sS <SNORT-VM-IP>` |

---

## 11. Typical workflow (exam / demo day)

```bash
# 1. Start Snort
sudo systemctl restart snort

# 2. Terminal 1 — Wireshark capture (optional, for report evidence)
sudo tshark -i enp0s3 -f "host 192.168.1.50" -w ~/SnortIDS/reports/lab-capture.pcapng

# 3. Terminal 2 — Python analyzer
cd ~/SnortIDS && source .venv/bin/activate
sudo $(which python) -m src.main --reprocess
# leave running, or restart without --reprocess for live mode

# 4. Terminal 3 — watch summary
watch -n 2 cat ~/SnortIDS/reports/summary.txt

# 5. From attacker machine
ping -c 10 192.168.1.50
nmap -sS 192.168.1.50

# 6. Stop tshark capture (Ctrl+C in Terminal 1)

# 7. Verify in Wireshark — filter:
#    ip.addr == 192.168.1.101 && ip.addr == 192.168.1.50
sudo wireshark ~/SnortIDS/reports/lab-capture.pcapng

# 8. Confirm CSV alerts
head -10 ~/SnortIDS/reports/alerts.csv

# 9. Export to Windows
sudo cp ~/SnortIDS/reports/alerts.csv /media/sf_SnortIDS/reports/
sudo cp ~/SnortIDS/reports/lab-capture.pcapng /media/sf_SnortIDS/reports/
```

---

## 12. Troubleshooting

| Problem | Fix |
|---------|-----|
| `Permission denied` on logs | Use `sudo $(which python) -m src.main` |
| `ImportError: ensure_directory` | Re-sync `src/utils.py` from shared folder |
| Messages show `SID 1:1000003` | Ensure `config/local-sid-msg.map` exists and config lists it under `extra_sid_msg_maps` |
| Classification `Unknown` | Confirm `classification_config` points to `/etc/snort/classification.config` |
| CSV not updating | Run with `--reprocess` or delete `.state/checkpoints.json` |
| venv error on shared folder | Use `~/SnortIDS` on native disk, not `/media/sf_SnortIDS` |
| Snort config error in local.rules | Use single-line rules; no orphan `)` on its own line |
| No alerts from other VM | Set `HOME_NET` to Snort VM IP `/32`, not whole subnet |
| `snort -T` fails | Run `sudo snort -T -c /etc/snort/snort.conf` and fix reported line |

| No packets in Wireshark | Use `sudo wireshark`; select correct interface (`enp0s3`); confirm bridged adapter |
| Wireshark filter shows nothing | Run attack first; check IPs match filter; try `ip.addr == SNORT_IP` only |

---

## 13. Project files (reference)

```text
SnortIDS/
├── config/
│   ├── config.json           # Analyzer settings
│   └── local-sid-msg.map     # Messages for custom SIDs 1000001–1000003
├── reports/
│   ├── alerts.csv            # Main output
│   ├── summary.txt           # Totals and top attackers
│   └── lab-capture.pcapng    # Optional Wireshark capture for report
├── .state/
│   └── checkpoints.json      # Read offsets (watch mode)
└── src/
    └── main.py               # Entry point
```

---

*SnortIDS — Intrusion Detection Using Snort with Python unified2 log analysis (MSc project).*
