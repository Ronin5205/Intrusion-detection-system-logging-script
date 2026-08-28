from __future__ import annotations

import fnmatch
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from idstools import maps, unified2
from idstools.unified2 import UnknownRecordType

logger = logging.getLogger(__name__)

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPV6",
}


def find_log_files(log_directory: Path, patterns: list[str]) -> list[Path]:
    if not log_directory.is_dir():
        raise FileNotFoundError(f"Log directory not found: {log_directory}")

    files: list[Path] = []
    for path in sorted(log_directory.rglob("*")):
        if path.is_file() and any(fnmatch.fnmatch(path.name, pattern) for pattern in patterns):
            files.append(path)
    return files


def _protocol_name(value: Any) -> str:
    if value in PROTOCOL_MAP:
        return PROTOCOL_MAP[value]
    if value is None:
        return "Unknown"
    text = str(value).strip()
    if text.isdigit() and int(text) in PROTOCOL_MAP:
        return PROTOCOL_MAP[int(text)]
    return text.upper()


def _format_timestamp(record: unified2.Event) -> str:
    seconds = _record_field(record, "event-second", "event_second")
    if seconds is None:
        return ""
    microseconds = int(record.get("event-microsecond") or 0)
    timestamp = datetime.fromtimestamp(int(seconds), tz=timezone.utc) + timedelta(
        microseconds=microseconds
    )
    return timestamp.isoformat()


def _record_field(record: unified2.Event, *names: str) -> Any:
    for name in names:
        if name in record and record.get(name) is not None:
            return record.get(name)
    return None


def _resolve_message(record: unified2.Event, msgmap: maps.SignatureMap) -> str:
    generator_id = _record_field(record, "generator-id", "generator_id") or 1
    signature_id = _record_field(record, "signature-id", "signature_id")
    if signature_id is not None:
        signature = msgmap.get(int(generator_id), int(signature_id))
        if signature and signature.get("msg"):
            return signature["msg"]
        return f"SID {generator_id}:{signature_id}"
    return "Unknown alert"


def _classification_label(classmap: maps.ClassificationMap, name: str | None) -> str | None:
    if not name:
        return None
    cleaned = name.strip()
    entry = classmap.get_by_name(cleaned)
    if entry:
        return entry.get("description") or entry.get("name")
    return cleaned.replace("-", " ").replace("_", " ").title()


def _resolve_classification(
    record: unified2.Event,
    msgmap: maps.SignatureMap,
    classmap: maps.ClassificationMap,
) -> str:
    classification_id = _record_field(record, "classification-id", "classification_id")
    if classification_id is not None:
        try:
            class_id = int(classification_id)
        except (TypeError, ValueError):
            class_id = 0
        if class_id > 0:
            classification = classmap.get(class_id)
            if classification:
                return classification.get("description") or classification.get("name") or "Unknown"

    generator_id = _record_field(record, "generator-id", "generator_id") or 1
    signature_id = _record_field(record, "signature-id", "signature_id")
    if signature_id is not None:
        signature = msgmap.get(int(generator_id), int(signature_id))
        if signature and signature.get("classification"):
            label = _classification_label(classmap, str(signature["classification"]))
            if label:
                return label

    return "Unknown"


def _resolve_priority(record: unified2.Event, msgmap: maps.SignatureMap) -> int:
    generator_id = _record_field(record, "generator-id", "generator_id") or 1
    signature_id = _record_field(record, "signature-id", "signature_id")
    if signature_id is not None:
        signature = msgmap.get(int(generator_id), int(signature_id))
        if signature and signature.get("priority") is not None:
            return int(signature["priority"])
    priority = _record_field(record, "priority")
    return int(priority) if priority is not None else 3


def _map_record(
    record: unified2.Event,
    msgmap: maps.SignatureMap,
    classmap: maps.ClassificationMap,
) -> dict[str, Any]:
    generator_id = _record_field(record, "generator-id", "generator_id")
    signature_id = _record_field(record, "signature-id", "signature_id")
    return {
        "timestamp": _format_timestamp(record),
        "src_ip": _record_field(record, "source-ip", "source_ip"),
        "dst_ip": _record_field(record, "destination-ip", "destination_ip", "dest-ip"),
        "src_port": _record_field(record, "sport-itype", "sport_itype"),
        "dst_port": _record_field(record, "dport-icode", "dport_icode"),
        "protocol": _protocol_name(record.get("protocol")),
        "signature_id": signature_id,
        "generator_id": generator_id,
        "priority": _resolve_priority(record, msgmap),
        "classification": _resolve_classification(record, msgmap, classmap),
        "message": _resolve_message(record, msgmap),
        "raw_format": "unified2",
    }


def parse_unified2_log(
    path: Path,
    msgmap: maps.SignatureMap,
    classmap: maps.ClassificationMap,
) -> list[dict[str, Any]]:
    events, _ = parse_unified2_log_incremental(path, msgmap, classmap, offset=0)
    return events


def parse_unified2_log_incremental(
    path: Path,
    msgmap: maps.SignatureMap,
    classmap: maps.ClassificationMap,
    offset: int,
) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        logger.warning("Skipping %s: %s", path, exc)
        return events, offset

    if offset > file_size:
        logger.warning("Log file %s shrank or rotated; resetting read offset", path.name)
        offset = 0

    try:
        handle = path.open("rb")
    except PermissionError:
        logger.warning("Skipping %s: permission denied", path)
        return events, offset

    with handle:
        handle.seek(offset)
        reader = unified2.RecordReader(handle)
        try:
            for record in reader:
                if not isinstance(record, unified2.Event):
                    continue
                events.append(_map_record(record, msgmap, classmap))
        except UnknownRecordType as exc:
            logger.error("Unsupported unified2 record in %s: %s", path.name, exc)
        except EOFError:
            pass
        new_offset = handle.tell()

    return events, new_offset
