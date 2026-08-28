from __future__ import annotations

import fnmatch
import logging
import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FileEvent:
    path: Path
    event_type: str


class SnortLogHandler(FileSystemEventHandler):
    def __init__(
        self,
        event_queue: queue.Queue[FileEvent],
        file_patterns: list[str],
        debounce_seconds: float,
    ) -> None:
        super().__init__()
        self.event_queue = event_queue
        self.file_patterns = file_patterns
        self.debounce_seconds = debounce_seconds
        self._pending: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def _matches(self, path: Path) -> bool:
        return any(fnmatch.fnmatch(path.name, pattern) for pattern in self.file_patterns)

    def _schedule(self, path: Path, event_type: str) -> None:
        key = str(path)
        with self._lock:
            existing = self._pending.pop(key, None)
            if existing is not None:
                existing.cancel()

            timer = threading.Timer(
                self.debounce_seconds,
                self._enqueue,
                args=(path, event_type),
            )
            self._pending[key] = timer
            timer.start()

    def _enqueue(self, path: Path, event_type: str) -> None:
        with self._lock:
            self._pending.pop(str(path), None)
        if path.is_file():
            self.event_queue.put(FileEvent(path=path.resolve(), event_type=event_type))

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if self._matches(path):
            self._schedule(path, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if self._matches(path):
            self._schedule(path, "modified")


class FileWatcher:
    def __init__(self, config: dict[str, Any], event_queue: queue.Queue[FileEvent]) -> None:
        self.watch_directory = Path(config["log_directory"])
        self.file_patterns = list(config.get("file_patterns", []))
        self.event_queue = event_queue
        self.handler = SnortLogHandler(
            event_queue=event_queue,
            file_patterns=self.file_patterns,
            debounce_seconds=float(config.get("debounce_seconds", 0.2)),
        )
        self.observer = Observer()
        self._file_signatures: dict[str, tuple[int, float]] = {}

    def _matching_files(self) -> list[Path]:
        watch_directory = self.watch_directory.resolve()
        if not watch_directory.exists():
            return []

        files: list[Path] = []
        for path in sorted(watch_directory.rglob("*")):
            if path.is_file() and self.handler._matches(path):
                files.append(path.resolve())
        return files

    def _file_signature(self, path: Path) -> tuple[int, float] | None:
        try:
            stat = path.stat()
        except OSError:
            return None
        return stat.st_size, stat.st_mtime

    def track_file(self, path: Path) -> None:
        signature = self._file_signature(path)
        if signature is not None:
            self._file_signatures[str(path.resolve())] = signature

    def poll_changed_files(self) -> list[Path]:
        changed: list[Path] = []
        for path in self._matching_files():
            key = str(path)
            signature = self._file_signature(path)
            if signature is None:
                continue
            if self._file_signatures.get(key) != signature:
                self._file_signatures[key] = signature
                changed.append(path)
        return changed

    def start(self) -> None:
        if not self.watch_directory.exists():
            logger.warning("Watch directory does not exist yet: %s", self.watch_directory)
            self.watch_directory.mkdir(parents=True, exist_ok=True)
        self.observer.schedule(self.handler, str(self.watch_directory.resolve()), recursive=True)
        self.observer.start()
        logger.info("Watching unified2 logs in %s", self.watch_directory.resolve())

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)
        logger.info("Stopped file watcher")

    def scan_existing(self) -> None:
        for path in self._matching_files():
            self.track_file(path)
            self.event_queue.put(FileEvent(path=path, event_type="existing"))
