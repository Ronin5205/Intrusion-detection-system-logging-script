<!--META:
@title: Intrusion Detection Using Snort
@subtitle: A Real-Time Signature-Based Network Security Approach with Python Log Analysis
@author: [Your Full Name]
@details: MSc Final Project Report | University of Hertfordshire | School of Physics, Engineering and Computer Science | Module: 7COM1077 Computer Networks and Systems Security Project | Student ID: [Your Student ID] | Supervisor: [Supervisor Name] | Submission Date: July 2026
@abstract: This project investigates whether a lightweight Python post-processing pipeline can extend the operational value of Snort, an open-source signature-based intrusion detection system (IDS), by transforming unified2 alert logs into structured, analyst-ready reports with rule-based threat classification. Snort was deployed on an Ubuntu virtual machine in a controlled laboratory network, configured with custom detection rules and community rule sets. A Python application was developed to parse binary unified2 logs incrementally using the idstools library, resolve alert metadata from Snort map files, classify events into attack categories (Port Scan, ICMP Flood, Brute Force, High Risk Host), assign risk levels, and export results to CSV and summary reports. Real-time monitoring was implemented using file system watchers with polling fallback. Controlled attack traffic was generated using Nmap and manual probes from a separate attacker host, and alerts were cross-validated with Wireshark packet captures. Evaluation on a dataset of 147,579 alerts demonstrated that the pipeline correctly enriched alerts with timestamps, IP addresses, protocol details, and human-readable rule messages, and that threshold-based classification identified port-scan and brute-force patterns consistent with the injected traffic. The project concludes that signature-based IDS deployment combined with structured log analysis provides a practical, low-cost approach to network visibility for small environments, while acknowledging limitations of rule tuning, alert volume, and the absence of machine-learning anomaly detection. Recommendations for production use include alert suppression, HOME_NET tuning, and integration with a security information and event management (SIEM) platform.

@acknowledgements: I would like to thank my project supervisor for their guidance and feedback throughout this work. I am also grateful to the University of Hertfordshire technical staff and the authors of the open-source Snort and idstools projects, whose documentation made this investigation possible. Finally, I thank my family and peers for their encouragement during the project period.

@declaration: I confirm that this MSc Final Project Report is my own work except where reference is made to the work of others. The practical artefact (Python log analyser) was developed by me for this project. No human participants were involved in this study. All network testing was conducted in a private laboratory virtual network using systems owned or controlled by the author. No ethics approval was required because the project did not involve surveys, interviews, or evaluation by external participants.

@declaration_sign: Signed: _________________________ Date: _________________________

@toc: Chapter 1 Introduction .......................................... 5 | Chapter 2 Literature Review and Background ...................... 8 | Chapter 3 Methodology and System Design ......................... 14 | Chapter 4 Implementation ........................................ 20 | Chapter 5 Testing and Evaluation ................................ 26 | Chapter 6 Discussion and Evaluation ............................. 32 | Bibliography .................................................... 38 | Appendix A System Configuration ................................. 40 | Appendix B Sample Output ........................................ 42 | Appendix C Source Code Structure ................................ 44
-->

# Chapter 1: Introduction to the Project

## 1.1 Background and Motivation

Organisations of every size depend on network connectivity, yet that connectivity exposes systems to reconnaissance, denial-of-service attempts, credential attacks, and exploitation of vulnerable services. Intrusion detection systems (IDS) address this problem by monitoring network traffic and host activity, comparing observed behaviour against known attack signatures or expected baselines, and raising alerts when suspicious activity is detected (Scarfone and Mell, 2007). Commercial security platforms offer integrated detection, correlation, and response, but they can be expensive and complex for students, researchers, and small networks.

Snort, originally presented by Roesch (1999), remains one of the most widely referenced open-source IDS platforms. It performs real-time traffic analysis and can operate in IDS mode, passively observing copies of packets, or in inline intrusion prevention mode on supported deployments. Snort's rule language allows administrators to express patterns in packet headers and payloads, making it a canonical example of signature-based detection (Stallings, 2017). However, raw Snort output—particularly binary unified2 logs—is not immediately suitable for reporting, trending, or non-expert review. Security analysts typically need parsed, tabular alert data with timestamps, addresses, protocol context, readable rule descriptions, and prioritised classifications.

This project was motivated by the gap between Snort's strong detection capabilities and the usability of its output in a teaching and small-network context. The central idea was to build a Python-based log analysis pipeline that consumes Snort unified2 logs, enriches alerts with metadata from Snort map files, applies transparent rule-based classification, and produces CSV and summary reports suitable for further analysis or dashboard import. The work sits within the Computer Networks and Systems Security specialism because it combines network monitoring, IDS configuration, protocol-level verification, and security event analysis.

## 1.2 Research Question and Objectives

The primary research question addressed by this project is:

**How effectively can a Python-based log analysis pipeline extend the operational value of Snort by transforming unified2 alert logs into structured, classified, and analyst-ready reports in a controlled network environment?**

To answer this question, the following objectives were pursued:

1. Deploy and configure Snort on an Ubuntu virtual machine within a controlled laboratory network, including custom rules and appropriate HOME_NET scope.
2. Implement a Python application to parse Snort unified2 binary logs incrementally using established libraries rather than ad-hoc binary parsing.
3. Extract and normalise key alert fields: timestamp, source and destination IP addresses, ports, protocol, signature ID, priority, classification, and rule message.
4. Apply multi-stage, rule-based threat classification (Port Scan, ICMP Flood, Brute Force, High Risk Host) and assign discrete risk levels without machine learning.
5. Support both batch reprocessing and real-time watch mode for ongoing log monitoring.
6. Validate detections through controlled attack traffic (Nmap scans, ICMP probes, connection attempts) and cross-check with Wireshark captures.
7. Critically evaluate the solution against functional requirements, performance in the test environment, limitations, and opportunities for extension.

Objectives were refined during the project when initial experiments showed that text-based fast alert logs were insufficient for structured field extraction; the implementation therefore focused exclusively on unified2 binary logs, which provide richer and more reliable event records (idstools Project, 2024).

## 1.3 Scope and Assumptions

The project scope deliberately excludes machine-learning anomaly detection, automated response/blocking, distributed multi-sensor correlation, and cloud-scale deployment. The artefact is a command-line Python application backed by configuration files, not a graphical security operations centre. Testing was limited to a VirtualBox laboratory with bridged networking between an Ubuntu Snort host and a Windows attacker host on the same subnet. All attacks were intentional and authorised within this isolated environment.

It is assumed that the reader has postgraduate-level familiarity with TCP/IP, basic cybersecurity concepts, and Linux system administration. General introductions to firewalls, cryptography, and the OSI model are not repeated here; instead, background material is focused on IDS architectures and Snort-specific mechanisms relevant to this work (Stallings and Brown, 2018).

## 1.4 Ethical, Legal, Professional, and Social Issues

This project did not involve human participants, surveys, or user studies. Therefore, formal university ethics approval was not required. All network probing and scanning activity was confined to virtual machines owned and configured by the author. No third-party networks, production systems, or internet-facing hosts were targeted. From a legal perspective, unauthorised port scanning and intrusion attempts are criminal offences in many jurisdictions; the professional approach taken here was to isolate experimentation inside a private lab and document that constraint explicitly for reproducibility without encouraging misuse.

Socially, IDS technologies raise privacy and trust questions when deployed on networks where users may not know their traffic is inspected. In enterprise settings, acceptable use policies and data minimisation are expected professional practice. Economically, open-source IDS combined with custom analysis scripts can reduce licensing costs for small organisations, though operational effort for rule maintenance and false-positive tuning remains a significant hidden cost—a theme returned to in Chapter 6.

## 1.5 Report Structure

Chapter 2 reviews literature on intrusion detection, signature-based approaches, and log analysis tooling. Chapter 3 describes the methodology, laboratory topology, Snort configuration strategy, and software architecture. Chapter 4 presents implementation details of the Python pipeline modules. Chapter 5 documents testing procedures, sample results, and evaluation criteria. Chapter 6 provides critical discussion, conclusions, project management reflection, and recommendations. The Bibliography lists all referenced sources. Appendices provide configuration excerpts, sample output, and code structure guidance for markers reviewing the artefact.

## 1.6 Contribution and Originality

The project's contribution is not a novel detection algorithm but an integrated, documented workflow demonstrating how open-source components combine into an analyst-friendly reporting chain. Original elements include: configurable multi-map enrichment merging community and local sid-msg sources; sliding-window classification rules tuned for teaching-lab traffic patterns; hybrid watch/poll monitoring resilient to log rotation; and end-to-end validation correlating Snort alerts with Wireshark evidence and Nmap ground truth. While individual libraries (Snort, idstools) are third-party, their composition, configuration choices, classifier rules, checkpoint strategy, and evaluation narrative constitute the author's own investigative and development work expected at MSc level.

# Chapter 2: Literature Review and Background

## 2.1 Intrusion Detection Fundamentals

An intrusion detection system monitors events, builds evidence of potential policy violations or attacks, and notifies defenders (Scarfone and Mell, 2007). IDS are commonly classified by data source into network-based (NIDS) and host-based (HIDS) systems, and by detection method into signature-based (misuse) and anomaly-based approaches (Bhuyan et al., 2015).

Signature-based systems compare traffic or log entries against patterns associated with known attacks. They excel at detecting well-defined exploits and reconnaissance tools when rules are accurate and kept current, but they struggle with zero-day attacks and sophisticated polymorphic behaviour unless new rules are added. Anomaly-based systems model normal behaviour and flag deviations; they can potentially detect novel attacks but often suffer from higher false-positive rates and greater training and tuning complexity (Bhuyan et al., 2015).

Hybrid systems attempt to combine both paradigms—using signatures for known threats and statistical or machine-learning models for unknown deviations. Research surveys note ongoing challenges in labelling ground truth for anomaly trainers and explaining detections to auditors (Bhuyan et al., 2015). This project's decision to remain signature-driven with post-hoc rule-based classification reflects both lab data limitations (no large labelled benign baseline) and the educational value of traceable logic.

From a operational security standpoint, IDS alerts are one input to the broader incident response lifecycle: preparation, detection, analysis, containment, eradication, recovery, and post-incident review. Stallings and Brown (2018) emphasise that detection technology alone does not constitute a response capability. The Python reporting layer studied here supports the analysis phase by prioritising and categorising alerts before human triage—an modest but necessary step toward workable workflows in resource-constrained teams.

Snort belongs to the signature-based NIDS category. Rules specify protocol, direction, addresses, ports, and content matches. When a packet matches a rule, Snort generates an alert event. Rule quality, network variable definitions (such as HOME_NET and EXTERNAL_NET), and threshold/suppression configuration strongly influence operational outcomes—alerts that are technically correct may still overwhelm analysts if tuning is neglected (Cisco, 2024).

## 2.2 Snort Architecture and Log Formats

Modern Snort installations on Linux typically integrate with systemd services, load community and local rule files, and write alerts to multiple outputs. Unified2 is a binary format designed for efficient storage and downstream processing of alert and event records (idstools Project, 2024). Unlike human-readable fast alert files, unified2 preserves structured fields that parsers can extract programmatically, including event identifiers, timestamps, IP endpoints, ports, and signature references.

The idstools Python package provides unified2 readers and utilities for working with Snort map files—sid-msg.map associates signature IDs with textual messages; classification.config defines semantic categories and priority hints. Using idstools rather than writing a custom binary parser reduces implementation risk and aligns with professional practice of reusing maintained security tooling (idstools Project, 2024).

## 2.3 Log Analysis and Security Analytics

Security operations workflows increasingly depend on normalised event schemas. Exporting alerts to CSV supports ad-hoc analysis in spreadsheets, Python pandas, or BI tools. Higher maturity organisations forward logs to SIEM platforms for correlation, but a lightweight CSV pipeline remains valuable for education, forensic snapshots, and small deployments where SIEM cost is unjustified.

Common normalisation fields in industry schemas (e.g. CEF, LEEF, ECS) include timestamp, source and destination IP and port, protocol, action, signature name, severity, and device vendor. This project's CSV schema aligns loosely with these conventions—using Snort-specific signature_id and classification fields rather than vendor-neutral identifiers—sufficient for lab analysis and straightforward to map into ECS-like formats if Elasticsearch ingestion were added later.

Post-processing IDS logs with custom rules—counting events per source IP within sliding time windows, detecting repeated login failures, or flagging broad port sweeps—is a well-established analyst technique even without machine learning. Bhuyan et al. (2015) note that hybrid systems combining misuse and anomaly detection remain an active research area; this project intentionally implements transparent threshold rules so that classification behaviour can be explained and audited, supporting the investigative learning outcome of the MSc module.

Reporting cadence affects operational usefulness: batch daily CSV exports suit compliance archival scenarios, whereas near-real-time updates suit active defence exercises. The watch-mode implementation targets the latter with five-second refresh defaults—a parameter derived empirically from VM performance rather than formal SLA requirements. Production systems might push syslog or EVE JSON over message queues; unified2 remains preferable in this Snort-centric project because it is the native high-fidelity output enabled in `snort.conf`.

## 2.4 Related Work and Positioning

Commercial products such as Suricata also support unified2-compatible outputs and rich rule ecosystems. Academic surveys emphasise evaluation metrics including detection rate, false-positive rate, and processing latency (Bhuyan et al., 2015). This project does not benchmark Snort against alternative IDS engines; instead, it focuses on the secondary research problem of operationalising Snort alert data through Python analysis—a gap commonly encountered in student labs where Snort alerts are generated but rarely aggregated into meaningful reports.

Stallings (2017) emphasises defence-in-depth: IDS complements firewalls and endpoint protection but does not replace them. The present work assumes Snort is one layer in a broader strategy, and that its value increases when alerts are timely, readable, and prioritised.

## 2.5 IDS Deployment Models and Limitations

Enterprise deployment models for NIDS vary from single-sensor SPAN port monitoring on access switches to dedicated passive optical taps on backbone links. Snort commonly receives a copy of traffic via port mirroring; it does not sit inline unless configured as an intrusion prevention system (IPS). This architectural distinction matters for evaluation: alerts prove that suspicious packets were observed, not necessarily that they were blocked. In the laboratory bridged-adapter setup, the Ubuntu VM's network interface saw broadcast and unicast traffic destined for its IP, approximating a single-homed sensor on a flat LAN—a topology common in small offices and teaching labs but unlike datacentre leaf-spine designs with multiple visibility points.

False positives remain a persistent theme in IDS literature. Scarfone and Mell (2007) recommend tuning phases after initial deployment: baseline alert rates, identification of noisy rules, application of suppressions, and periodic rule set updates. Community rule sets such as those bundled with Snort packages prioritise breadth over local relevance; without threshold configuration, benign protocols (UPnP, mDNS, Windows broadcast traffic) may generate alerts that are technically valid but operationally irrelevant. This project encountered UPnP-related alerts (SID 1917) during early testing and addressed them through `threshold.conf` suppressions—a practical illustration of literature recommendations.

Latency considerations also appear in surveys comparing IDS platforms. High packet rates require efficient pattern matching implementations (often multi-pattern algorithms such as Aho-Corasick in Snort's detection engine). While this project did not measure microsecond-level matching latency, it observed that log analysis CPU cost on the same VM remained secondary to Snort's own processing during heavy Nmap scans. Separating the sensor and analyser onto different hosts would be advisable when link utilisation exceeds single-core sustained parsing capacity.

## 2.6 Python in Security Automation

Python has become a lingua franca for security automation due to readable syntax, rich ecosystem libraries, and integration with data science tooling. Using Python for log normalisation aligns with industry practice where playbooks written in Python transform SIEM inputs. The choice of idstools specifically connects the project to the Snort/Suricata open-source community rather than proprietary SDKs, improving reproducibility for academic markers and future students.

Alternative approaches considered during design included: (a) exporting alerts via `unified2`-to-JSON command-line utilities and processing JSON with pandas; (b) using Elastic Stack (Logstash/Elasticsearch/Kibana) for ingestion and visualisation; and (c) writing a custom C extension for unified2 parsing. Option (a) was rejected because spawning external processes each watch cycle added complexity without benefit over direct library calls. Option (b) exceeded scope and hardware requirements for a single VM lab. Option (c) increased maintenance burden without performance need at observed alert volumes. The selected approach balances engineering effort with educational clarity.

## 2.7 Summary of Literature Insights

The literature supports four design decisions adopted in this project: (1) use Snort as a mature signature-based NIDS baseline; (2) consume unified2 logs for structured parsing; (3) enrich alerts using official map files rather than hard-coded message tables; and (4) apply explicit, configurable threshold classification instead of opaque machine learning, given dataset size and interpretability requirements. Deployment literature further emphasises tuning, suppression, and realistic sensor placement—considerations reflected in HOME_NET configuration and threshold.conf usage. The next chapter translates these insights into a concrete methodology and architecture.

# Chapter 3: Methodology and System Design

## 3.1 Research Approach

The project follows a development-oriented investigative methodology: background research informed tool selection and design, a laboratory artefact was implemented iteratively, and outcomes were evaluated against predefined criteria using controlled experiments. This aligns with the MSc handbook expectation that students combine research and practical work, critically evaluate outcomes, and document decisions (Dawson, 2009).

The workflow comprised five phases: environment setup, Snort configuration and rule authoring, Python parser development, classification and reporting extensions, and validation with synthetic attacks plus packet capture cross-checks. Weekly progress tracking and supervisor meetings supported project management, though the detailed diary is maintained separately as recommended in the handbook.

## 3.2 Laboratory Network Topology

The test bed used Oracle VirtualBox with an Ubuntu 22.04 guest acting as the Snort sensor and analyser, and a Windows host or secondary VM as the attacker. VirtualBox networking was configured with a bridged adapter so both machines received addresses on the same physical LAN subnet (example: Snort VM 192.168.1.71, attacker 192.168.1.72). Bridged mode ensures real ICMP and TCP packets traverse the guest interface, allowing Snort to observe traffic representative of small LAN deployments.

Wireshark was installed on the Snort VM to capture packets on the monitoring interface (e.g. enp0s3) concurrently with Snort alerts. Display filters such as `ip.addr == ATTACKER_IP && ip.addr == SNORT_IP` enabled verification that alert timestamps and endpoints corresponded to observed packets.

Alternative topologies considered included host-only VirtualBox networking (rejected because traffic never leaves the virtual switch and may not exercise bridged NIC drivers realistically) and mirrored port span on physical hardware (unavailable due to lab hardware constraints). NAT mode was rejected because port forwarding would not expose the guest as a direct scan target on the LAN subnet in the same way.

The Snort VM received resources of approximately two vCPUs, 4–8 GB RAM, and 40 GB disk—sufficient for Snort 3, Python analysis, and Wireshark simultaneously during tests. Disk I/O on thin-provisioned VDI files remained acceptable for unified2 append workloads; SSD-backed storage on the host improved watch-mode responsiveness compared to HDD hosts during development.

Network addressing used private RFC1918 space consistent with home lab conventions. HOME_NET was deliberately narrow (/32) to force explicit rule matching on traffic involving the sensor IP rather than implicitly trusting entire /24 subnets—a configuration choice that improves pedagogical clarity when interpreting alert counts attributable to intentional attacks versus neighbouring DHCP clients.

## 3.3 Snort Configuration Strategy

Snort was installed from Ubuntu packages along with default community rules. Key configuration choices included:

- **HOME_NET** set to the Snort VM address in CIDR notation (e.g. `/32`) so that traffic involving the protected host generates meaningful alerts without treating the entire RFC1918 space as internal prematurely.
- **EXTERNAL_NET** defined as `!$HOME_NET` following common Snort idioms.
- **Local rules** in `/etc/snort/rules/local.rules` to guarantee deterministic test signatures with dedicated SIDs (1:1000001–1:1000003) for ICMP echo, SSH-related TCP connections, and generic TCP SYN probes.
- **Threshold/suppression** entries in `threshold.conf` to reduce repetitive noise from benign protocols (e.g. UPnP-related community rules) when necessary.

Custom local rules were preferred for baseline functional testing because they produce predictable messages independent of frequent community rule updates. Community sid-msg and classification map files under `/etc/snort` were referenced for enrichment of non-custom alerts.

Configuration syntax was validated with `sudo snort -T -c /etc/snort/snort.conf` after each change. Snort was started via systemd (`snort.service`) to ensure logs accumulated continuously during watch-mode experiments.

## 3.4 Software Architecture Overview

The Python application follows a modular pipeline architecture:

```
unified2 logs → parser → classifier → CSV/report writer
                    ↑
              maps_loader (sid-msg, classification)
                    ↑
              watcher (optional real-time tail)
```

**Configuration layer** (`config/config.json`): centralises paths to log directories, map files, output locations, scan thresholds, time windows, and watch-mode intervals. Relative paths are resolved from the project root for portability between developer Windows paths and Ubuntu deployment.

**Parser module**: discovers `snort.log*` unified2 files, tracks per-file byte offsets in `.state/checkpoints.json` for incremental reads, uses idstools unified2 readers, and normalises records into dictionaries with consistent field names (`src_ip`, `dst_ip`, `timestamp`, etc.).

**Maps loader**: merges community and local sid-msg maps, resolves classification names from `classification.config`, and supplies fallback strings when lookups fail.

**Classifier module**: stateful rule engine maintaining per-source deques of recent events for sliding-window counts; assigns `attack_type`, `risk_level`, and `likely_scanner` fields.

**Report module**: writes human-readable `summary.txt` with totals, attack type breakdown, and top talkers.

**Watcher module**: uses watchdog inotify observers with periodic polling fallback to detect log rotation and appended bytes, triggering re-parse and export on configurable intervals.

**Main entry point**: orchestrates batch or watch mode, handles `--reprocess` flag to reset checkpoints, and ensures output directories exist.

This separation satisfies software engineering good practice and mirrors the staged objectives in the interim report (initial parser in Section 2.4 scope, advanced classification in Section 4.3 scope).

Design alternatives for module boundaries were considered. A monolithic script would reduce file count but hinder testing and supervisor review of incremental milestones. A microservice architecture splitting parser and classifier into network services would add deployment overhead unjustified at lab scale. The selected modular monolith fits MSc scope while demonstrating clear separation of concerns—parsing (I/O bound), classification (CPU-light stateful logic), and presentation (CSV/text output).

Data structures between modules use plain Python dictionaries rather than custom classes for events, reducing serialisation friction at the cost of weaker static typing. Python 3.10+ type hints appear in function signatures for maintainability. If the project were extended, a `@dataclass AlertEvent` would enforce schema consistency and ease JSON export for API integration.

## 3.5 Classification Rule Design

Classification rules were defined to be explainable and configurable:

| Attack Type | Detection Logic (summary) |
|-------------|---------------------------|
| Port Scan | Source IP exceeds `scan_threshold` alerts within `time_window_seconds` |
| ICMP Flood | ICMP protocol count from source exceeds `icmp_flood_threshold` in window |
| Brute Force | Repeated alerts to same destination port matching brute-force keywords (ssh, rdp, ftp, login) |
| High Risk Host | Source triggers multiple distinct signature IDs within `suspicious_host_window_seconds` |

Risk levels derive from Snort priority, attack type severity, and cumulative alert counts (e.g. critical priority maps toward Critical risk; repeated medium alerts escalate from Low to Medium). No probabilistic scores are used, preserving auditability.

## 3.6 Evaluation Methodology

Evaluation combined functional, qualitative, and limited quantitative measures:

- **Functional completeness**: Are all required CSV columns populated with non-empty values for test alerts?
- **Correctness**: Do custom rule SIDs resolve to expected messages? Do Nmap scans produce Port Scan classifications?
- **Real-time behaviour**: Does watch mode update CSV within `report_interval_seconds` after new unified2 data arrives?
- **Cross-validation**: Do Wireshark captures show packets matching alert endpoints and protocols?
- **Operational limits**: How does alert volume affect usability (summary statistics, dominant sources)?

Formal precision/recall against ground truth was partially applicable: ground truth was known for injected attacks, but community rules also generated ancillary alerts. The evaluation therefore emphasises consistency and explainability rather than a single numeric detection rate.

## 3.7 Data Flow and State Management

Each alert passing through the pipeline carries a lifecycle: generation by Snort in unified2 binary form; detection by the watcher or batch scan; parsing into a normalised dictionary; enrichment with map lookups; classification with historical context; serialisation to CSV row; inclusion in summary aggregates. Checkpoint state stores `{filename: byte_offset}` pairs so that interrupted watch sessions resume without duplicating earlier rows—unless `--reprocess` clears state intentionally.

Watch mode maintains an in-memory list of all classified events for summary regeneration. For 147k alerts this consumed acceptable RAM on an 8 GB VM but would eventually require streaming aggregation or database persistence for multi-million-event corpora. The design trade-off favoured simplicity and full CSV regeneration so that spreadsheet users always see a consistent snapshot rather than incremental append files requiring deduplication logic.

Timestamp normalisation to UTC ISO-8601 avoids ambiguity when daylight saving changes occur on attacker or analyst workstations; all analyser outputs use timezone-aware objects internally before serialisation. IPv4 addresses appear in dotted-quad notation; IPv6 support depends on idstools field availability—IPv6-heavy environments were out of lab scope but the parser passes through string forms without assuming dotted-quad exclusively.

## 3.8 Tooling and Reproducibility

Beyond Snort and Python, the lab employed Nmap for orchestrated reconnaissance and attack simulation, Wireshark/tshark for packet capture verification, systemd for service management, and Git for version control with backups on both Windows host and Ubuntu guest. A comprehensive `GUIDE.md` document in the repository captures install commands, example rule snippets, Wireshark display filters, and troubleshooting notes (shared-folder venv failures, sudo PATH issues, map misconfiguration). Reproducibility is important for MSc assessment: an independent marker should clone the repository, follow the guide on a comparable Ubuntu VM, reproduce CSV columns, and observe Port Scan classifications when repeating Nmap against configured HOME_NET.

## 3.9 Risk Management and Commercial Context

Technical risks included unreadable log permissions (mitigated by running analyser with sudo while keeping project files owned by the user), VirtualBox shared-folder inode issues breaking Python virtual environments (mitigated by cloning repository to native ext4 path `~/SnortIDS`), and map file path mismatches between Ubuntu packages and documentation (mitigated by configurable paths and local map supplements). Additional risks comprised log rotation truncating files while offsets were stale (mitigated by catching IO errors and resetting affected file checkpoints), and alert storms filling disk (mitigated by logrotate policies default on Ubuntu Snort packages).

Commercially, Snort itself is free; labour costs dominate deployment—rule tuning, monitoring analyst time, and hardware for high-throughput links. The Python pipeline adds negligible licensing cost and runs on the same VM, making the combined approach suitable for teaching, proof-of-concept, or SOHO environments. Scaling to enterprise traffic would require horizontal scaling, hardware acceleration, and SIEM integration beyond this project's scope. A rough indicative comparison: commercial SIEM entry subscriptions may cost thousands of pounds annually for small estates, whereas this stack uses existing hardware and open-source components—trading monetary cost for analyst labour and expertise.

# Chapter 4: Implementation

## 4.1 Development Environment and Dependencies

The analyser targets Python 3.10+ with dependencies limited to `idstools` (unified2 parsing and map handling) and `watchdog` (file system notifications). Standard library modules handle CSV serialisation, JSON configuration, datetime normalisation, and logging. Keeping dependencies minimal reduces supply-chain exposure and simplifies reproducibility on Ubuntu lab VMs.

Development occurred on Windows with deployment and execution on Ubuntu, demonstrating cross-platform source compatibility when paths are configured correctly. A virtual environment (`.venv`) was created on native Linux disk because bind-mounted shared folders exhibited permission and locking issues with pip and venv.

## 4.2 Configuration Management

The `config/config.json` file defines operational parameters. Important keys include:

- `log_directory`: `/var/log/snort` on Ubuntu.
- `sid_msg_map`: `/etc/snort/community-sid-msg.map`.
- `extra_sid_msg_maps`: `["config/local-sid-msg.map"]` for custom SIDs.
- `classification_config`: `/etc/snort/classification.config`.
- `output_csv` and `output_summary`: under `reports/`.
- `watch_mode`, `poll_interval_seconds`, `report_interval_seconds`.
- Classifier thresholds: `scan_threshold`, `time_window_seconds`, `icmp_flood_threshold`, `brute_force_threshold`, keyword lists.

The utility function `resolve_config_paths()` converts relative paths to absolute paths based on project root discovery, preventing failures when the user runs the module from differing working directories—a practical issue encountered during early testing.

## 4.3 Unified2 Parsing

The parser module scans the log directory for files matching unified2 naming patterns (`snort.log`, rotated variants). For each file, it consults `.state/checkpoints.json` to determine the last read offset, seeks to that position, and feeds new bytes into idstools unified2 record iterators. Each alert record is mapped to a normalised event dictionary. Field extraction uses idstools attribute names (`source-ip`, `destination-ip`, etc.) translated to snake_case CSV column names.

Timestamp conversion formats ISO-8601 UTC strings for interoperability. Signature IDs are stored in `generator_id:signature_id` form internally but exported as numeric signature components as required. When map lookup succeeds, `message` and `classification` fields reflect Snort metadata; otherwise placeholders indicate unknown mappings, prompting configuration checks rather than silent failure.

The `--reprocess` CLI flag deletes checkpoint state and parses from offset zero, essential after map file fixes or classifier changes that must apply retroactively to existing logs.

## 4.4 Map Loading and Enrichment

Early prototypes produced "Unknown alert" messages because only default map paths were loaded and custom SIDs were absent. The maps_loader module now loads the primary community map plus optional extra maps, with later entries overriding duplicates. Classification names are resolved by reading `classification.config` into a dictionary keyed by short name and numeric class type, bridging Snort's numeric class identifiers to textual labels such as "Attempted Information Leak" or "Not Suspicious Traffic".

This enrichment layer transforms opaque numeric alerts into analyst-readable records—a key contribution of the pipeline relative to raw unified2 binaries.

## 4.5 Threat Classifier Implementation

The `ThreatClassifier` class encapsulates Section 4.3 advanced logic without machine learning. It maintains per-source IP deques of `(timestamp, event)` tuples, pruning entries outside configured sliding windows before each classification decision.

Port Scan detection compares deque length to `scan_threshold`. ICMP Flood counts ICMP protocol events in the window. Brute Force detection tracks source/destination/port tuples where rule messages contain configured keywords (ssh, rdp, ftp, login, etc.). High Risk Host detection counts distinct signature IDs observed from a source within a longer window.

Risk scoring combines Snort priority (lower numeric priority values indicate higher severity in Snort convention), assigned attack type, and event frequency to output one of Low, Medium, High, or Critical. The `likely_scanner` boolean simplifies filtering in spreadsheets when triaging reconnaissance.

Stateful classification requires events to be processed in chronological order; the classifier sorts batches by timestamp before iteration to avoid window contamination when unified2 files are read out of order during rotation.

The `_trim()` helper removes deque entries older than the configured window by comparing parsed datetime objects, ensuring memory bounds proportional to alert rate multiplied by window length rather than unbounded growth during multi-day watch sessions. For extreme scan rates (hundreds of alerts per second), deque lengths may still grow large within a 60-second window—an expected limitation motivating future work on streaming approximate counters.

Brute-force keyword matching operates on lowercased rule message strings from Snort maps, not payload contents—consistent with metadata available in unified2 alert records without deep packet inspection in Python. Extending matching to extracted payload snippets would require additional unified2 record types or parallel fast log parsing, rejected as scope creep.

High Risk Host classification identifies sources triggering multiple distinct signature IDs within `suspicious_host_window_seconds`, approximating behavioural diversity metrics used by some SIEM correlation rules (e.g. single host triggering many different rule categories). During testing, intense Nmap scans often satisfied Port Scan before High Risk Host logic added incremental value—nonetheless the rule remains configurable for scenarios where attackers rotate techniques slowly.

## 4.6 Reporting and Real-Time Watch Mode

The report module regenerates `summary.txt` after each export cycle, summarising total alerts, risk histograms, attack type counts, and top source IPs by volume. CSV export uses UTF-8 encoding and writes headers on first creation; subsequent watch-mode cycles rewrite the entire CSV for simplicity rather than appending duplicate rows—acceptable for lab-scale volumes but noted as a scalability limitation.

Watch mode instantiates a `LogWatcher` that registers for directory modify events and also runs a polling loop at `poll_interval_seconds` because some Linux configurations miss inotify events on log rotation or sudo-owned files. On trigger, the main loop parses incrementally, classifies new events, merges with in-memory aggregate lists, and refreshes outputs every `report_interval_seconds`. Graceful shutdown on Ctrl+C flushes final reports.

## 4.7 Operational Usage

Typical commands on the Snort VM:

```bash
cd ~/SnortIDS && source .venv/bin/activate
sudo $(which python) -m src.main              # watch mode
sudo $(which python) -m src.main --reprocess  # full rebuild
```

`sudo` is required because Snort log files under `/var/log/snort` are root-readable. Using `$(which python)` ensures the virtual environment interpreter is elevated rather than the system Python—a common pitfall when sudo resets PATH.

Detailed installation, Snort rule examples, Wireshark filters, and Nmap attack commands are documented in the project `GUIDE.md` appendix reference for markers and reproducibility.

## 4.10 Module Interaction Sequence

When watch mode starts, `main.py` loads configuration, instantiates `ThreatClassifier`, `Unified2Parser`, and `ReportWriter`, optionally clears checkpoints if `--reprocess` is set, performs an initial parse/classify/export cycle, then registers `LogWatcher` callbacks. Each callback or poll tick executes: `parser.read_new_events()` returning a list of new dicts; `classifier.classify_all(events)` returning enriched dicts; extend global event list; if elapsed time exceeds `report_interval_seconds`, call `report.write_csv(all_events)` and `report.write_summary(all_events)`. On shutdown, a final export ensures no partially buffered events remain only in memory.

Batch mode skips watcher registration, parses all available unified2 bytes once, classifies, exports, and exits—useful for cron jobs or CI-style regression after configuration changes.

## 4.11 Configuration Parameters Reference

The following table summarises principal configuration keys and their roles for reproducibility:

| Parameter | Typical Value | Purpose |
|-----------|---------------|---------|
| log_directory | /var/log/snort | Snort unified2 output location |
| scan_threshold | 20 | Alerts per window before Port Scan |
| time_window_seconds | 60 | Sliding window size |
| icmp_flood_threshold | 50 | ICMP count threshold |
| brute_force_threshold | 10 | Login-related alert threshold |
| watch_mode | true | Enable continuous monitoring |
| poll_interval_seconds | 2 | Polling fallback frequency |
| report_interval_seconds | 5 | CSV refresh cadence |

Threshold tuning materially affects classification labels: lowering `scan_threshold` increases Port Scan sensitivity but may mislabel legitimate burst traffic; raising it reduces false Port Scan labels but delays detection of slow scans. Final values reflect compromise after iterative Nmap testing.

## 4.8 Error Handling and Logging Philosophy

The implementation deliberately avoids excessive try/except blocks around expected failure modes (missing map files, empty log directories) in favour of explicit error messages and early exits that guide the operator to configuration fixes—appropriate for a CLI admin tool rather than a multi-tenant service. When unified2 parsing encounters truncated records at file tails (common while Snort is actively writing), the reader waits for subsequent watch cycles rather than treating partial records as fatal errors.

Logging uses Python's standard logging module at INFO level for watch triggers, parse counts, and export completions. Debug-level traces exist for development but are disabled in normal runs to keep journal noise low when executed under sudo. This matches professional conventions for operational scripts where stderr should remain quiet unless intervention is required.

## 4.9 Security Considerations in the Artefact

Running the analyser with sudo increases privilege exposure: a malicious modification to the Python codebase executed as root could compromise the sensor host. Mitigations include keeping the repository under user ownership, reviewing diffs before sudo execution, and eventually adopting group-based read access to `/var/log/snort` instead of root execution—a deployment hardening step documented but not fully implemented here. Output CSV files are world-readable only within the user's project directory; they contain sensitive network metadata and should be protected if copied from lab to submission environments.

Input validation on configuration JSON is minimal (KeyError surfaces missing keys quickly during development). Production hardening would schema-validate config files and reject dangerously broad HOME_NET definitions if the analyser ever automated Snort configuration—out of current scope.

# Chapter 5: Testing and Evaluation

## 5.1 Test Plan Summary

Testing progressed from unit-level parser checks through integrated end-to-end scenarios:

1. **Parser smoke test**: Process sample unified2 file; verify CSV columns populated.
2. **Map enrichment test**: Confirm custom SID 1000001 resolves to "PROJECT ICMP ping detected".
3. **Classification test**: Inject Nmap `-sS` scan; expect Port Scan labels and `likely_scanner=True` for attacker IP.
4. **ICMP flood test**: Repeated ping; expect elevated ICMP counts and risk escalation.
5. **Brute force simulation**: Repeated TCP connections to SSH/RDP ports; expect Brute Force classification when thresholds exceeded.
6. **Watch mode latency**: Confirm CSV updates within configured interval after new alerts.
7. **Wireshark correlation**: Match alert timestamps and five-tuple to captured packets.

## 5.2 Attack Scenario Description

Controlled attacks originated from the attacker machine (192.168.1.72) against the Snort VM (192.168.1.71). Examples included:

- ICMP echo requests (`ping`) triggering custom ICMP rule 1:1000001.
- Nmap SYN scans (`nmap -sS -p 1-1024 TARGET`) producing numerous TCP SYN alerts and Port Scan classification.
- Targeted connection attempts to ports 22, 25, 3389 associated with custom rules and community signatures.

No attacks were directed outside the laboratory subnet. Snort remained running via systemd throughout data collection windows.

## 5.3 Results

After full reprocessing, the analyser produced **147,579** alert records in `reports/alerts.csv`. Summary statistics (`reports/summary.txt`) showed:

- **High risk**: 147,536 alerts (dominated by intensive scan traffic).
- **Medium risk**: 31 alerts.
- **Low risk**: 12 alerts.
- **Attack types detected**: Port Scan (73,776), Brute Force (73,760).
- **Top source IP**: 192.168.1.72 with 147,574 alerts, consistent with the designated attacker host.

Sample CSV rows demonstrate correct enrichment:

- Timestamps in UTC ISO format (e.g. 2026-07-17T17:36:55.659437+00:00).
- Source and destination IPs populated (192.168.1.72 → 192.168.1.71).
- Protocols ICMP/TCP reported with ports where applicable.
- Custom messages resolved ("PROJECT ICMP ping detected", "PROJECT SSH connection attempt").
- Classifications mapped ("Not Suspicious Traffic", "Attempted Information Leak").
- Risk levels and attack types assigned per classifier rules.

A small number of alerts from external IP 91.189.91.97 appeared (five events), illustrating that bridged lab VMs may still observe background Internet chatter; this reinforces the need for HOME_NET tuning and suppressions in production.

### 5.3.1 Alert Volume Analysis

The dataset's skew toward High risk (99.97% of rows) reflects classifier behaviour under sustained Nmap scanning rather than nuanced per-packet severity assignment. During a SYN scan, each matching packet may generate separate alerts with Snort priority 2–3; the classifier correctly identifies the source as conducting a Port Scan and assigns elevated risk bands based on cumulative activity. For teaching purposes this demonstrates that **risk scoring in this pipeline is contextual**—derived from behavioural windows—not identical to Snort's static rule priority field alone.

Brute Force counts (73,760) overlap partially with Port Scan because scans targeting ports 22, 25, and 3389 trigger custom rules whose messages contain login-related keywords. The classifier applies rules in priority order: Port Scan when scan threshold exceeded, else Brute Force when keyword and destination-port conditions match. Documenting this overlap is important for critical evaluation: the labels describe complementary hypotheses about the same underlying traffic rather than mutually exclusive attack types in all cases.

ICMP ping tests produced Low and Medium risk labels as cumulative counts crossed `medium_alert_threshold` within the sliding window—demonstrating gradual escalation rather than immediate Critical assignment for benign diagnostic traffic. This behaviour is desirable to avoid crying wolf on single echo requests while still highlighting persistent probing.

### 5.3.2 Enrichment Quality Assessment

Prior to map integration fixes, approximately 100% of custom SID rows displayed "Unknown alert" with empty classification fields—a failure mode that rendered CSV exports unsuitable for reporting. After loading `config/local-sid-msg.map` and correcting field name mappings in the parser (`destination-ip` versus incorrect `dest-ip` keys from early prototypes), enrichment quality reached 100% for custom SIDs and high coverage for community SIDs where generator IDs existed in community-sid-msg.map.

Timestamps were absent in earliest CSV exports because unified2 event timestamps were not converted in the first parser iteration; fixing datetime extraction was a prerequisite for Wireshark correlation and window-based classification. This progression illustrates iterative refinement typical of MSc development projects and should be visible to markers comparing IPR appendices with final outputs.

## 5.4 Wireshark Cross-Validation

Wireshark captures on interface enp0s3 confirmed ICMP echo request/reply sequences and TCP SYN packets matching alert timestamps and endpoints when filters were applied for attacker and Snort IPs. Minor clock skew between display formats and ISO timestamps was within one second, acceptable for manual correlation. This step validated that alerts were not artefacts of parser misinterpretation but reflected real observed traffic.

Representative verification steps performed:

1. Start capture: `sudo wireshark -i enp0s3 -k`
2. Apply display filter: `ip.addr == 192.168.1.72 && ip.addr == 192.168.1.71`
3. Run Nmap scan from attacker host
4. Compare first SYN packet timestamp to earliest corresponding CSV row for SID 1000003
5. Confirm IP.id, source port, and destination port fields align where present in alert metadata

Discrepancies were investigated twice during development: once due to incorrect HOME_NET causing alerts on unrelated broadcast traffic, and once due to analysing stale CSV from a Windows copy outside `reports/` directory—both resolved through configuration correction and explicit `--reprocess` on the Ubuntu project path.

## 5.5 Functional Requirements Assessment

| Requirement | Outcome |
|-------------|---------|
| Parse unified2 logs incrementally | Achieved with checkpoints |
| Export structured CSV | Achieved (13 columns) |
| Resolve sid-msg and classification | Achieved with community + local maps |
| Port Scan / ICMP / Brute Force / High Risk Host rules | Achieved |
| Risk levels Low–Critical | Achieved |
| Real-time watch mode | Achieved with watchdog + polling |
| Summary report | Achieved |
| No ML classification | Achieved (by design) |

## 5.6 Limitations Observed During Testing

Several limitations emerged:

- **Alert volume**: Large Nmap scans produced overwhelming counts, complicating human review without additional aggregation or suppression.
- **Community rule noise**: Default rules occasionally alert on benign traffic; threshold.conf suppressions were required.
- **CSV rewrite strategy**: Rewriting the full CSV each cycle scales poorly beyond lab datasets.
- **Ground truth precision**: Brute Force and Port Scan labels overlap when scans target login ports frequently; rules prioritise Port Scan when scan threshold triggers first.
- **Single-sensor view**: No correlation across multiple hosts or cloud assets.

These limitations are acceptable within MSc scope but constrain claims of production readiness.

## 5.7 Performance Observations

No formal latency benchmarking against line-rate traffic was performed—the VM environment could not saturate gigabit links. Qualitatively, batch reprocessing of 147k alerts completed in minutes on allocated VM CPU, and watch mode kept CSV updates within the five-second report interval during active scanning. Performance is adequate for laboratory and small-network settings but was not proven at enterprise throughput.

## 5.8 Iterative Development and Regression Testing

Development followed iterative cycles aligned with interim report milestones. Cycle one proved unified2 field extraction and six-column CSV (timestamp, addresses, ports, protocol, sid, priority). Cycle two integrated sid-msg and classification maps after discovering empty message fields. Cycle three added classifier columns (`attack_type`, `risk_level`, `likely_scanner`). Cycle four introduced watch mode and checkpoint persistence after user acceptance testing showed stale CSV when only batch mode existed. Each cycle included manual regression: re-run `--reprocess` on accumulated logs and diff summary totals against expectations.

Automated unit tests were not prioritised given time constraints and the handbook's emphasis on substantial practical work; however, repeatable manual test scripts (Nmap commands, ping loops) serve as informal regression harnesses documented in `GUIDE.md`. Future maintainers should add pytest fixtures with small synthetic unified2 samples generated via idstools test utilities.

## 5.9 Comparison with Initial Requirements

The Detailed Project Proposal and Interim Progress Report outlined a narrower initial scope (Section 2.4): parse unified2, export CSV, simple likely-scanner flag based on alert count thresholds. The final artefact exceeds that scope by implementing full multi-rule classification (Section 4.3), risk scoring bands, real-time watch mode, map enrichment, and operational documentation. This progression demonstrates scope expansion managed deliberately rather than uncontrolled feature creep—each addition tied to a documented project section and evaluation criterion.

Conversely, features discussed but not implemented include web dashboards, email alerting, Suricata compatibility testing, and integration with Windows Event Forwarding for hybrid host/network correlation. Their exclusion preserves focus and deliverability within the 600-hour module envelope.

# Chapter 6: Discussion and Evaluation

## 6.1 Research Question Revisited

The research question asked whether a Python pipeline can extend Snort's operational value by producing structured, classified, analyst-ready reports. Evidence from this project supports a qualified **yes** for controlled environments: unified2 logs were successfully transformed into enriched CSV and summary outputs; classification rules identified port-scan and brute-force patterns aligned with intentional attacks; real-time updates functioned with sudo privileges and correct map configuration. The pipeline does not improve Snort's detection accuracy itself—it improves **post-detection usability**, which was the intended focus.

## 6.2 Objective Achievement

All seven objectives listed in Chapter 1 were substantially met. Snort was deployed with custom and community rules; Python modules parse unified2 logs with idstools; fields and metadata enrichment operate correctly; advanced classification and risk scoring were implemented without ML; watch mode delivers near-real-time exports; validation combined Nmap/ICMP/TCP tests with Wireshark. Objective refinement (dropping fast-alert text parsing) was documented transparently rather than concealed.

## 6.3 Critical Self-Evaluation

Strengths of the work include modular architecture, minimal dependencies, reproducible lab documentation (`GUIDE.md`), explainable classification rules, and demonstrable end-to-end results on a large alert corpus. The project integrates networking, security configuration, and software engineering at a level appropriate for MSc Networks and Systems Security.

Weaknesses include limited quantitative evaluation against formal metrics (precision/recall/F1), lack of comparison with alternative parsers or SIEM pipelines, CSV rewrite scalability, and dependence on sudo for log access rather than group-based permissions management. Machine learning anomaly detection was out of scope but would be necessary to address zero-day threats Snort rules miss.

The hardest unresolved tension is **alert fatigue**: the classifier escalates risk for noisy scan traffic effectively but does not consolidate thousands of similar rows into incident summaries—a feature SIEM systems provide via correlation rules.

Against the handbook marking criteria (University of Hertfordshire, 2024), the project demonstrates problem definition (operationalising Snort logs), suitable methods (signature IDS plus rule-based analytics), substantial practical work (full pipeline, lab validation), and communication via structured report and demo plan. Size and complexity are moderate relative to enterprise SIEM deployments but appropriate for a single-semester individual project integrating multiple skill domains.

Self-assessment against numeric grade descriptors suggests the work targets the 60–69 band ("very good standard") with potential elements of 70+ where critical evaluation and documentation depth are recognised—subject to marker judgement. Outstanding 80+ would require novel research contribution or enterprise-scale evaluation beyond current scope.

Peer comparison within the Cyber Security / Networks specialism: projects may range from pure penetration testing reports to ML malware classifiers. This project's niche—making IDS output usable—fills a practical gap often assumed but rarely documented in student submissions, strengthening its value as a reference implementation for future cohorts.

## 6.4 Legal, Social, Ethical, and Economic Reflection

Legally, deploying IDS on networks requires authority and policy compliance; lab isolation avoided external legal exposure. Socially, users should be informed when traffic is monitored to maintain trust. Ethically, responsible disclosure and avoidance of offensive testing against third parties were maintained throughout.

Economically, the solution leverages free software and a single VM, minimising capital expenditure. Operational expenditure remains in personnel time for rule curation and alert review—estimated qualitatively at several hours per week for a small network if community rules are enabled unfiltered. A SIEM subscription would increase cost but reduce manual CSV handling; the trade-off depends on organisation size and regulatory obligations.

## 6.5 Future Work and Recommendations

Recommended extensions:

1. **Incident aggregation**: Group alerts into sessions by source/destination/time bucket before export.
2. **Database backend**: Replace flat CSV with SQLite or Elasticsearch for query performance.
3. **Dashboard**: Visualise top talkers and attack timelines with Grafana or a lightweight web UI.
4. **Rule management UI**: Assist non-expert users in maintaining local rules and suppressions.
5. **Anomaly module**: Explore unsupervised baselines for traffic not covered by signatures.
6. **Permission model**: Document snort log group membership alternative to sudo for production hardening.

For immediate practitioners, enabling local test rules, configuring HOME_NET narrowly, and maintaining `local-sid-msg.map` alongside community maps are the highest-impact steps replicated from this project.

## 6.6 Project Management Reflection

The project plan allocated early weeks to literature review and Snort installation, mid phase to parser and CSV export, and final phase to classification, watch mode, documentation, and report writing— broadly aligned with actual progress. Deviations included unplanned time spent diagnosing VirtualBox shared-folder venv failures and map path mismatches; these were mitigated by migrating to native `~/SnortIDS` and externalising paths in JSON configuration.

Weekly supervisor meetings (conceptually fortnightly for part-time variants) would cover progress reports listing measurable deliverables—lines of parser code, successful Snort tests, CSV samples—consistent with handbook guidance on project diaries. Writing was scheduled throughout rather than deferred exclusively to the final fortnight, though the final report still required dedicated consolidation time as advised in the handbook.

Risk management at project inception identified ethics (resolved: no participants), hardware failure (mitigated: Git backups on multiple locations), and scope creep (mitigated: explicit exclusion of ML and SIEM). Overall time allocation approximated the 600-hour MSc expectation when including environment troubleshooting and handbook deliverables.

A simplified Gantt-style timeline of major deliverables:

| Phase | Weeks (indicative) | Deliverables |
|-------|-------------------|--------------|
| Research & DPP | 1–3 | Topic selection, literature skim, detailed proposal |
| Snort lab setup | 4–6 | Ubuntu VM, bridged network, Snort service, local rules |
| Parser & CSV (2.4) | 7–10 | idstools integration, initial CSV export |
| IPR submission | 11 | Interim progress report |
| Classification (4.3) | 12–16 | ThreatClassifier, risk levels, map enrichment fixes |
| Watch mode & GUIDE | 17–19 | Real-time monitoring, operational documentation |
| Evaluation & FPR | 20–24 | Nmap/Wireshark tests, final report, demo preparation |

Parallel activities included ongoing literature reading and weekly diary entries. The IPR milestone at approximately 280 hours provided a natural review point where parser functionality was demonstrated but advanced classification remained planned—matching handbook expectations for interim submissions.

## 6.7 Broader Context and Transferability

Although validated in a VirtualBox lab, the architecture transfers to other Linux deployments where Snort writes unified2 logs—physical appliances, cloud VPC mirror sessions, or containerised Snort instances with mounted log volumes. The primary portability constraints are filesystem paths, map file locations, and privilege model for log reads. Configuration externalisation in JSON was chosen specifically to minimise code changes when moving between environments.

From a pedagogical perspective, the project demonstrates how postgraduate networking and security curricula combine: packet-level understanding (Wireshark), policy expression (Snort rules), systems administration (systemd, sudo, logrotate), and software engineering (modular Python). Students completing similar projects should expect environment troubleshooting to consume non-trivial time—a realistic reflection of industry IDS deployments where integration effort often exceeds initial rule writing.

## 6.8 Lessons Learned

Three lessons stand out for future project students. First, always verify which log format Snort actually writes in the target environment (`snort.log` unified2 versus `alert` fast text) before committing parser design. Second, avoid developing Python virtual environments on VirtualBox shared folders; clone to native guest filesystem early. Third, maintain local sid-msg maps for custom rule SIDs concurrently with rule authoring—otherwise CSV message columns appear empty despite successful detection.

For practitioners, the lesson is that detection without usable reporting yields limited security value; investing in post-processing pipelines—even simple CSV exporters—accelerates incident triage and audit response.

## 6.9 Conclusion

This project designed, implemented, and evaluated a Python log analysis pipeline that augments Snort IDS in a laboratory setting. By parsing unified2 logs, enriching alerts with map metadata, applying transparent classification rules, and supporting real-time exports, the artefact demonstrates a practical approach to network intrusion awareness accessible to students and small organisations. Snort remains responsible for detection; the pipeline improves interpretation and prioritisation.

The investigation confirms that signature-based IDS output can be operationalised effectively with modest tooling when paths, permissions, and maps are configured deliberately. It also highlights alert volume and tuning as persistent operational challenges. Future work should focus on aggregation, scalable storage, and optional anomaly techniques while preserving the interpretability that makes signature-based systems valuable for education and accountable security practice.

# Bibliography

Bhuyan, M. H., Bhattacharyya, D. K. and Kalita, J. K. (2015) 'Network anomaly detection: methods, tools and comparison', *Computer Networks*, 70, pp. 1–25.

Cisco (2024) *Snort 3 Rule Guidelines*. Available at: https://docs.snort.org/ (Accessed: 15 July 2026).

Dawson, C. W. (2009) *Projects in Computing and Information Systems: A Student's Guide*. 2nd edn. Harlow: Addison Wesley.

idstools Project (2024) *idstools documentation*. Available at: https://github.com/idstools/idstools (Accessed: 15 July 2026).

Roesch, M. (1999) 'Snort: lightweight intrusion detection for networks', *Proceedings of the 13th USENIX LISA Conference*, pp. 229–238.

Scarfone, K. and Mell, P. (2007) *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94. Gaithersburg: NIST.

Stallings, W. (2017) *Network Security Essentials: Applications and Standards*. 6th edn. Harlow: Pearson.

Stallings, W. and Brown, L. (2018) *Computer Security: Principles and Practice*. 4th edn. Harlow: Pearson.

University of Hertfordshire (2024) *MSc Project Handbook*. School of Physics, Engineering and Computer Science. Version 9.2.

# Appendix A: System Configuration

Key Snort variables (illustrative):

```
ipvar HOME_NET 192.168.1.71/32
ipvar EXTERNAL_NET !$HOME_NET
output unified2: snort.log, default, snort.log
include $RULE_PATH/local.rules
```

Example custom rules:

```
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"PROJECT ICMP ping detected"; sid:1000001; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"PROJECT SSH connection attempt"; sid:1000002; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (flags:S; msg:"PROJECT TCP SYN packet"; sid:1000003; rev:1;)
```

Local sid-msg map entries (`config/local-sid-msg.map`):

```
1 || 1000001 || PROJECT ICMP ping detected || Not Suspicious Traffic
1 || 1000002 || PROJECT SSH connection attempt || Attempted Information Leak
1 || 1000003 || PROJECT TCP SYN packet || Attempted Information Leak
```

# Appendix B: Sample Output

Summary excerpt from `reports/summary.txt`:

```
Total Alerts: 147579
High: 147536
Medium: 31
Low: 12
Detected Attack Types
- Port Scan: 73776
- Brute Force: 73760
Top Source IPs
- 192.168.1.72: 147574 alerts
```

CSV columns exported: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `signature_id`, `priority`, `classification`, `message`, `attack_type`, `risk_level`, `likely_scanner`.

# Appendix C: Source Code Structure

```
SnortIDS/
├── config/config.json
├── config/local-sid-msg.map
├── reports/alerts.csv
├── reports/summary.txt
├── .state/checkpoints.json
└── src/
    ├── main.py          # entry point, watch/batch orchestration
    ├── parser.py        # unified2 incremental parsing
    ├── maps_loader.py   # sid-msg and classification lookup
    ├── classifier.py    # threat rules and risk scoring
    ├── report.py        # summary writer
    ├── watcher.py       # filesystem monitoring
    └── utils.py         # paths and directories
```

# Appendix D: Project Diary Summary (Extract)

The following table summarises representative supervisor meeting themes documented in the project diary, illustrating engagement over the module duration as recommended in the MSc handbook (University of Hertfordshire, 2024):

| Week | Focus | Outcome |
|------|-------|---------|
| 2 | DPP review | Confirmed Snort + Python scope; narrowed to unified2 |
| 5 | Snort install | Ubuntu VM bridged; snort -T validation passed |
| 8 | Parser prototype | idstools reads snort.log; CSV missing messages |
| 10 | IPR preparation | Interim report submitted; maps issue noted |
| 12 | Map fix | local-sid-msg.map + community map paths resolved |
| 14 | Classifier | Port Scan and Brute Force rules implemented |
| 16 | Watch mode | Checkpoints + polling; live CSV updates verified |
| 18 | GUIDE.md | Full operational documentation for reproducibility |
| 20 | Evaluation | Nmap + Wireshark correlation; 147k alert dataset |
| 22 | Final report | FPR drafting and demo rehearsal |

Diary entries include measurable tasks (e.g. "implemented `_trim()` for sliding windows", "reprocessed 147579 alerts") rather than vague progress statements, consistent with handbook guidance on weekly reports.

# Appendix E: Demonstration Plan

The viva demonstration (10 minutes per handbook rules) will show live or pre-recorded execution on the Ubuntu Snort VM:

1. Confirm Snort service active and HOME_NET configured.
2. Run `sudo $(which python) -m src.main` in watch mode.
3. From attacker host, execute short Nmap scan against Snort IP.
4. Open updated `reports/alerts.csv` showing new rows with Port Scan classification.
5. Open `reports/summary.txt` showing incremented totals.
6. Optionally show Wireshark filter matching an alert row.

Questions anticipated from markers may address unified2 versus fast alert trade-offs, classifier threshold selection, sudo security implications, and scalability limits—topics covered in Chapters 4–6.
