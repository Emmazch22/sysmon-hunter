"""Administrative actions.

A destructive action (wiping the database) and a content-management one
(importing Sigma rules) live here. Kept in their own router, tagged
distinctly from the read/write endpoints an analyst reaches for moment to
moment, so both are easy to find -- and easy to lock down or remove --
independently of everything else.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml
from fastapi import APIRouter, File, UploadFile

from backend.api.ws import manager
from backend.config import settings
from backend.engine.pipeline import pipeline
from backend.engine.rule_loader import rule_store
from backend.engine.sigma_import import import_sigma_text
from backend.models import db

log = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])

# Where accepted Sigma imports are written, one YAML file per rule. Kept
# under rules/ (not somewhere separate) so rule_loader picks them up the
# same way as every hand-written rule -- an imported rule is not a second
# class of citizen, it just has a different birth certificate.
SIGMA_IMPORT_DIR = settings.rules_dir / "imported_sigma"

# A pasted rule file bigger than this is almost certainly a mistake (the
# wrong file, or a whole Sigma corpus dropped in at once) rather than a
# single detection -- reject it with a clear reason instead of parsing
# multiple megabytes of YAML from one upload.
MAX_UPLOAD_BYTES = 2_000_000


@router.delete("/admin/database")
async def reset_database() -> dict[str, Any]:
    """Wipe every detection and incident, and reset the live engine to match.

    Two things have to happen together, in this order: the persisted rows go
    first, then the in-memory process tree and detectors are rebuilt from
    scratch (see Pipeline.reset). Skipping the second half would leave the
    engine correlating new events against a tree that remembers incidents the
    database no longer has any record of.

    Every connected console is notified over the websocket, not just the tab
    that clicked the button -- this is a shared live view, and a reset that
    only one analyst's screen reflects is worse than no reset at all.
    """
    await db.reset_database()
    pipeline.reset()
    await manager.broadcast({"type": "reset", "data": {}})

    log.warning("Database reset via /admin/database")
    return {"status": "reset"}


@router.post("/admin/rules/import-sigma")
async def import_sigma_rules(files: list[UploadFile] = File(...)) -> dict[str, Any]:
    """Import one or more Sigma rule files into the live rule set.

    A file may contain several `---`-separated Sigma documents (the format
    allows it); every document is converted independently, so one bad rule
    in a batch never blocks the rest -- see engine/sigma_import.py for
    exactly what subset of Sigma is supported and why the rest is rejected
    rather than approximated.

    Accepted rules are each written to their own file under
    rules/imported_sigma/, then the whole rule store is reloaded from disk
    (the same `rule_store.load` the app calls at startup), so imports are
    live for the very next ingested event with no restart -- rules really
    are "content, not code" here, this is just the first place that claim
    gets exercised through the API instead of only by hand-editing a file.
    """
    existing_ids = {rule.id for rule in rule_store.all}
    accepted: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []

    SIGMA_IMPORT_DIR.mkdir(parents=True, exist_ok=True)

    for upload in files:
        source = upload.filename or "upload"
        raw = await upload.read()
        if len(raw) > MAX_UPLOAD_BYTES:
            rejected.append({
                "title": source,
                "source": source,
                "reason": f"file is {len(raw)} bytes, over the {MAX_UPLOAD_BYTES}-byte import limit",
            })
            continue

        text = raw.decode("utf-8", errors="replace")
        result = import_sigma_text(text, source_name=source)

        for rule in result.accepted:
            rule_id = rule.id
            if rule_id in existing_ids:
                # Astronomically unlikely (8 hex characters of the rule's own
                # Sigma UUID), but a silent overwrite of a hand-written or
                # previously imported rule is a bad way to find that out.
                suffix = 1
                candidate = f"{rule_id}-{suffix}"
                while candidate in existing_ids:
                    suffix += 1
                    candidate = f"{rule_id}-{suffix}"
                rule_id = candidate
            existing_ids.add(rule_id)

            payload = {"id": rule_id, **rule.model_dump(mode="json", exclude={"id"})}
            dest = SIGMA_IMPORT_DIR / f"{rule_id}.yml"
            dest.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
            accepted.append({"id": rule_id, "title": rule.title, "source": source})

        for rejection in result.rejected:
            rejected.append({**rejection, "source": source})

    count = rule_store.load(settings.rules_dir)
    log.info(
        "Sigma import: %d accepted, %d rejected -- rule store reloaded with %d total",
        len(accepted), len(rejected), count,
    )

    return {"accepted": accepted, "rejected": rejected, "rules_loaded": count}
