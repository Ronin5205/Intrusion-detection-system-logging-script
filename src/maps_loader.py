from __future__ import annotations

import logging
from pathlib import Path

from idstools import maps

logger = logging.getLogger(__name__)


def load_signature_map(
    sid_msg_map: Path | None,
    gen_msg_map: Path | None,
    extra_sid_msg_maps: list[Path] | None = None,
) -> maps.SignatureMap:
    msgmap = maps.SignatureMap()
    if gen_msg_map and gen_msg_map.is_file():
        with gen_msg_map.open("r", encoding="utf-8", errors="replace") as handle:
            msgmap.load_generator_map(handle)
        logger.info("Loaded generator map from %s", gen_msg_map)

    map_files: list[Path] = []
    if sid_msg_map:
        map_files.append(sid_msg_map)
    if extra_sid_msg_maps:
        map_files.extend(extra_sid_msg_maps)

    loaded_any = False
    for map_path in map_files:
        if not map_path.is_file():
            logger.warning("Signature map not found: %s", map_path)
            continue
        with map_path.open("r", encoding="utf-8", errors="replace") as handle:
            msgmap.load_signature_map(handle)
        logger.info("Loaded signature map from %s", map_path)
        loaded_any = True

    if loaded_any:
        logger.info("Total signature map entries: %d", msgmap.size())
    elif sid_msg_map or extra_sid_msg_maps:
        logger.warning("No signature map files were loaded; messages will show as SID gid:sid")

    return msgmap


def load_classification_map(classification_config: Path | None) -> maps.ClassificationMap:
    classmap = maps.ClassificationMap()
    if classification_config and classification_config.is_file():
        with classification_config.open("r", encoding="utf-8", errors="replace") as handle:
            classmap.load_from_file(handle)
        logger.info(
            "Loaded classification map from %s (%d entries)",
            classification_config,
            classmap.size(),
        )
    elif classification_config:
        logger.warning("Classification config not found: %s", classification_config)
    else:
        logger.warning("No classification config configured; classifications may show as Unknown")
    return classmap
