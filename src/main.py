from __future__ import annotations

# Standard library imports
import csv
import logging
import queue
import signal
import sys
import time

from pathlib import Path
from typing import Any

# idstools provides the data structures used for Snort signature/classification maps.
from idstools import maps

# Project-specific modules
from src.classifier import ThreatClassifier
from src.maps_loader import load_classification_map, load_signature_map
from src.parser import (
    find_log_files,
    parse_unified2_log,
    parse_unified2_log_incremental,
)
from src.report import write_summary
from src.utils import (
    default_config_path,
    ensure_directory,
    load_config,
    load_json_file,
    project_root,
    resolve_config_paths,
    save_json_file,
)
from src.watcher import FileEvent, FileWatcher


# Logger used throughout this module.
logger = logging.getLogger(__name__)


# Columns that will appear in the generated CSV report.
# Any fields not included here will be ignored by DictWriter.
CSV_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "signature_id",
    "priority",
    "classification",
    "message",
    "attack_type",
    "risk_level",
    "likely_scanner",
]


def write_csv(path: Path, events: list[dict[str, Any]]) -> None:
    """
    Write all analyzed Snort events to a CSV file.

    Args:
        path:
            Destination CSV file.

        events:
            List of dictionaries containing analyzed alert data.
    """

    # Make sure the output directory exists before opening the file.
    ensure_directory(path.parent)

    # Open the CSV using UTF-8 and newline="" to avoid blank lines
    # on some platforms such as Windows.
    with path.open("w", encoding="utf-8", newline="") as handle:

        # DictWriter converts each event dictionary into a CSV row.
        #
        # extrasaction="ignore" means that if an event contains additional
        # fields that are not in CSV_COLUMNS, those fields are ignored.
        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_COLUMNS,
            extrasaction="ignore",
        )

        # Write the CSV header.
        writer.writeheader()

        # Write every event as one CSV row.
        for event in events:
            writer.writerow(event)


class SnortLogAnalyzer:
    """
    Main controller for the Snort Unified2 log analysis system.

    Responsibilities:
    - Load configuration.
    - Load Snort signature/classification maps.
    - Watch Snort log files for changes.
    - Process new Unified2 events.
    - Maintain file-processing checkpoints.
    - Classify detected threats.
    - Generate CSV and summary reports.
    """

    def __init__(
        self,
        config: dict[str, Any],
        reprocess: bool = False,
    ) -> None:

        # Store the configuration for use throughout the analyzer.
        self.config = config

        # Location of the generated CSV report.
        self.output_csv = Path(config["output_csv"])

        # Location of the human-readable summary report.
        #
        # If output_summary isn't configured, use:
        # <project_root>/reports/summary.txt
        self.output_summary = Path(
            config.get(
                "output_summary",
                str(project_root() / "reports" / "summary.txt"),
            )
        )

        # Directory used to store persistent analyzer state.
        #
        # This includes checkpoints that tell us how much of each
        # Unified2 log file has already been processed.
        self.state_directory = ensure_directory(
            Path(
                config.get(
                    "state_directory",
                    str(project_root() / ".state"),
                )
            )
        )

        # JSON file containing the last processed byte offset
        # for each monitored log file.
        self.checkpoint_path = self.state_directory / "checkpoints.json"

        # -------------------------------------------------------------
        # Load Snort signature/message maps
        # -------------------------------------------------------------

        # Additional custom signature maps can optionally be provided
        # in the configuration.
        extra_maps = [
            Path(path)
            for path in config.get("extra_sid_msg_maps", [])
            if path
        ]

        # Load SID -> message mappings.
        #
        # These maps allow the analyzer to turn a Snort signature ID
        # into a meaningful alert message.
        self.msgmap: maps.SignatureMap = load_signature_map(
            Path(config["sid_msg_map"])
            if config.get("sid_msg_map")
            else None,

            Path(config["gen_msg_map"])
            if config.get("gen_msg_map")
            else None,

            extra_maps,
        )

        # Load Snort classification mappings.
        #
        # Example:
        # "attempted-admin" -> "Attempted Administrator Privilege Gain"
        self.classmap: maps.ClassificationMap = load_classification_map(
            Path(config["classification_config"])
            if config.get("classification_config")
            else None
        )

        # Warn the user if no signature map was loaded.
        #
        # The analyzer can still operate, but alerts may only show
        # their SID instead of a descriptive message.
        if self.msgmap.size() == 0:
            logger.warning(
                "Signature map is empty — messages will show as SID or Unknown alert"
            )

        # -------------------------------------------------------------
        # Runtime state
        # -------------------------------------------------------------

        # All alerts processed during this execution.
        #
        # In watch mode this list continuously grows as new alerts
        # arrive in the Snort logs.
        self.alerts: list[dict[str, Any]] = []

        # If --reprocess was specified, delete the existing checkpoints.
        #
        # This forces the analyzer to process the log files from the
        # beginning instead of continuing from the previous offsets.
        if reprocess and self.checkpoint_path.exists():
            self.checkpoint_path.unlink()
            logger.info("Cleared checkpoints for full reprocess")

        # Load previously saved checkpoints.
        #
        # Format is roughly:
        # {
        #     "/path/to/unified2.log": 123456
        # }
        #
        # The number represents the byte offset that was already processed.
        self.checkpoints: dict[str, int] = {
            key: int(value)
            for key, value in load_json_file(
                self.checkpoint_path
            ).items()
        }

        # Controls the main watch loop.
        # Setting this to False causes the analyzer to shut down cleanly.
        self.running = True

        # Timestamp of the last generated report.
        self.last_report_at = 0.0

        # Timestamp of the last filesystem polling operation.
        self.last_poll_at = 0.0

        # -------------------------------------------------------------
        # Event queue and filesystem watcher
        # -------------------------------------------------------------

        # FileWatcher places file-change events into this queue.
        #
        # The analyzer consumes those events from the queue.
        #
        # Using queue.Queue makes this safe when the watcher and analyzer
        # operate in different threads.
        self.event_queue: queue.Queue[FileEvent] = queue.Queue()

        # Create the filesystem watcher.
        self.watcher = FileWatcher(
            config,
            self.event_queue,
        )

    def run(self) -> int:
        """
        Start the analyzer.

        Returns:
            Process exit code.
        """

        # watch_mode=True means continuously monitor Snort logs.
        if self.config.get("watch_mode", True):
            return self._run_watch()

        # Otherwise perform a one-time batch analysis.
        return self._run_once()

    def stop(self) -> None:
        """
        Request a graceful shutdown.

        The main loop checks self.running and exits once this becomes False.
        """
        self.running = False

    def _run_once(self) -> int:
        """
        Process all existing Unified2 log files once.

        This is used when watch_mode is disabled.
        """

        # Directory containing Snort Unified2 logs.
        log_directory = Path(self.config["log_directory"])

        # File patterns that should be considered Snort Unified2 logs.
        patterns = self.config.get(
            "file_patterns",
            [
                "unified2.log*",
                "snort.u2*",
            ],
        )

        # Find matching log files.
        log_files = find_log_files(
            log_directory,
            patterns,
        )

        # Nothing to process.
        if not log_files:
            logger.error(
                "No unified2 log files found in %s",
                log_directory,
            )
            return 1

        # Process every discovered log file.
        #
        # incremental=False means the entire file is parsed.
        for log_file in log_files:
            self._process_file(
                log_file.resolve(),
                incremental=False,
            )

        # Generate the final reports after all files have been processed.
        self._generate_reports(force=True)

        # Return success.
        #
        # The current implementation always returns 0 here if log files
        # were found, regardless of whether alerts were detected.
        return 0 if self.alerts else 0

    def _run_watch(self) -> int:
        """
        Continuously monitor Snort Unified2 log files.

        New filesystem events are placed into event_queue by FileWatcher.
        """

        # Start the filesystem watcher.
        self.watcher.start()

        # Scan files that already existed before the watcher started.
        self.watcher.scan_existing()

        # Initialize report/poll timers.
        self.last_report_at = time.time()
        self.last_poll_at = time.time()

        # Main monitoring loop.
        while self.running:

            try:
                # Wait for a file event.
                #
                # timeout=1.0 is important because it prevents this
                # thread from blocking forever. It allows us to perform
                # polling/report checks even when no filesystem event occurs.
                file_event = self.event_queue.get(timeout=1.0)

            except queue.Empty:
                # No filesystem event arrived during the timeout.

                # Check for changes that the filesystem watcher may
                # have missed.
                self._poll_for_changes()

                # Generate reports if the configured report interval
                # has elapsed.
                self._generate_reports(
                    force_interval=True,
                )

                # Return to the beginning of the loop.
                continue

            # ---------------------------------------------------------
            # Process the file associated with the filesystem event.
            # ---------------------------------------------------------

            self._process_file(
                file_event.path.resolve(),
                incremental=True,
            )

            # Tell the watcher that this file is now being tracked.
            self.watcher.track_file(
                file_event.path.resolve()
            )

            # Update reports after processing the event.
            self._generate_reports(
                force_interval=False,
            )

        # -------------------------------------------------------------
        # Graceful shutdown
        # -------------------------------------------------------------

        # Persist the latest offsets before exiting.
        self._save_checkpoints()

        # Generate one final report containing the latest alerts.
        self._generate_reports(force=True)

        # Stop filesystem monitoring.
        self.watcher.stop()

        return 0

    def _poll_for_changes(self) -> None:
        """
        Periodically check monitored files for changes.

        This acts as a fallback in case filesystem events are missed.
        """

        # Number of seconds between polling attempts.
        interval = float(
            self.config.get(
                "poll_interval_seconds",
                2,
            )
        )

        now = time.time()

        # Don't poll more frequently than configured.
        if now - self.last_poll_at < interval:
            return

        # Record the time of this polling operation.
        self.last_poll_at = now

        # Ask the watcher for files whose contents changed.
        for path in self.watcher.poll_changed_files():

            logger.debug(
                "Poll detected changes in %s",
                path.name,
            )

            # Process only the newly appended portion of the file.
            self._process_file(
                path,
                incremental=True,
            )

    def _process_file(
        self,
        path: Path,
        incremental: bool,
    ) -> None:
        """
        Parse a Unified2 log file and add any new alerts to self.alerts.

        Args:
            path:
                Unified2 log file to process.

            incremental:
                If True, only process data added since the previous checkpoint.
                If False, process the entire file.
        """

        if incremental:

            # Retrieve the last processed byte offset.
            #
            # If this is a new file, default to offset 0.
            offset = self.checkpoints.get(
                str(path),
                0,
            )

            # Parse only data after the previous offset.
            #
            # The parser returns:
            #   events     -> newly discovered alerts
            #   new_offset -> new byte position
            events, new_offset = parse_unified2_log_incremental(
                path,
                self.msgmap,
                self.classmap,
                offset,
            )

            # Nothing changed in the file.
            #
            # Therefore there is nothing to process and the checkpoint
            # remains unchanged.
            if new_offset == offset and not events:
                return

            # Save the new byte offset.
            #
            # This is what prevents the same Unified2 events from being
            # processed repeatedly on every polling cycle.
            self.checkpoints[str(path)] = new_offset

            # Persist the checkpoint immediately.
            self._save_checkpoints()

        else:

            # Batch mode:
            # Parse the entire Unified2 file.
            events = parse_unified2_log(
                path,
                self.msgmap,
                self.classmap,
            )

        # No alerts were discovered.
        if not events:
            return

        # Add newly discovered alerts to the in-memory collection.
        self.alerts.extend(events)

        logger.info(
            "Processed %d new alerts from %s (total: %d)",
            len(events),
            path.name,
            len(self.alerts),
        )

    def _generate_reports(
        self,
        force: bool = False,
        force_interval: bool = False,
    ) -> None:
        """
        Generate the CSV and summary reports.

        Reports are throttled using report_interval_seconds unless
        force=True is supplied.
        """

        # Minimum time between automatic report updates.
        interval = float(
            self.config.get(
                "report_interval_seconds",
                5,
            )
        )

        now = time.time()

        # If this is an interval-based update and not enough time has
        # passed, don't regenerate the reports yet.
        if force_interval and now - self.last_report_at < interval:
            return

        # If this is a normal report request and there are no alerts,
        # there is nothing to write.
        if not force and not force_interval:
            if not self.alerts:
                return

        # If this is an interval-based report and there are no alerts,
        # there is also nothing to write.
        if not force and force_interval and not self.alerts:
            return

        # Create the threat classifier.
        classifier = ThreatClassifier(self.config)

        # Classify every alert collected so far.
        #
        # This adds fields such as:
        # - attack_type
        # - risk_level
        # - likely_scanner
        classified = classifier.classify_all(
            self.alerts
        )

        # Write the complete classified alert list to CSV.
        write_csv(
            self.output_csv,
            classified,
        )

        # Write the human-readable summary report.
        write_summary(
            self.output_summary,
            classified,
        )

        # Record when the report was generated.
        self.last_report_at = now

        # Log useful statistics.
        if force or force_interval:

            # Count alerts that received an attack_type classification.
            attack_count = sum(
                1
                for event in classified
                if event.get("attack_type")
            )

            logger.info(
                "Updated %s (%d alerts, %d classified)",
                self.output_csv.name,
                len(classified),
                attack_count,
            )

    def _save_checkpoints(self) -> None:
        """
        Persist the current file offsets to disk.

        Saving checkpoints allows the analyzer to restart without
        reprocessing the entire Unified2 log.
        """

        save_json_file(
            self.checkpoint_path,
            self.checkpoints,
        )


def main() -> int:
    """
    Application entry point.
    """

    # Configure application-wide logging.
    #
    # Example:
    # 2026-08-26 16:30:10 [INFO] __main__: Starting Snort...
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Read command-line arguments.
    args = sys.argv[1:]

    # Whether the user requested a complete reprocessing of the logs.
    reprocess = False

    # -------------------------------------------------------------
    # Parse --reprocess
    # -------------------------------------------------------------

    if "--reprocess" in args:

        # Enable full reprocessing.
        reprocess = True

        # Remove the flag so the remaining argument can be treated
        # as the optional configuration path.
        args.remove("--reprocess")

    # -------------------------------------------------------------
    # Determine configuration file
    # -------------------------------------------------------------

    # If the user provided a configuration path, use it.
    #
    # Otherwise use the project's default configuration.
    config_path = (
        Path(args[0])
        if args
        else default_config_path()
    )

    # Load the configuration and resolve relative paths.
    config = resolve_config_paths(
        load_config(config_path)
    )

    # Create the analyzer.
    analyzer = SnortLogAnalyzer(
        config,
        reprocess=reprocess,
    )

    # -------------------------------------------------------------
    # Signal handling
    # -------------------------------------------------------------

    def _handle_signal(
        signum: int,
        _frame: Any,
    ) -> None:

        # Log which OS signal was received.
        logger.info(
            "Received signal %s, shutting down...",
            signum,
        )

        # Tell the analyzer to exit its main loop.
        analyzer.stop()

    # Handle Ctrl+C.
    signal.signal(
        signal.SIGINT,
        _handle_signal,
    )

    # Handle SIGTERM on platforms that provide it.
    #
    # getattr() provides SIGINT as a fallback on platforms where
    # SIGTERM is unavailable.
    signal.signal(
        getattr(
            signal,
            "SIGTERM",
            signal.SIGINT,
        ),
        _handle_signal,
    )

    # Determine which operating mode is being used.
    mode = (
        "watch"
        if config.get("watch_mode", True)
        else "batch"
    )

    logger.info(
        "Starting Snort unified2 log analysis (%s mode)",
        mode,
    )

    # Start the analyzer and return its exit code.
    return analyzer.run()


# Run main() only when this file is executed directly.
#
# If another module imports this file, main() will not automatically run.
if __name__ == "__main__":
    raise SystemExit(main())