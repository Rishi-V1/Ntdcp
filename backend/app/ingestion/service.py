"""Ingestion orchestration: detect format, parse, validate, dedupe, persist.

Malformed / invalid records are never dropped silently – each one becomes a
``RejectedRecord`` with its line number, reason and a truncated excerpt.
Duplicates (identical source record, same SHA-256) are counted, not stored twice.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import AnalysisSettings, get_env
from app.ingestion import suricata, zeek
from app.models import Dataset, Event, IngestionJob, RejectedRecord
from app.normalization.schema import RecordRejected

MAX_REJECT_DETAILS = 500


class IngestionError(Exception):
    pass


def detect_sensor(text: str, filename: str) -> str:
    name = filename.lower()
    if "eve" in name or "suricata" in name:
        return "suricata"
    if zeek.guess_path(filename):
        return "zeek"
    for line in text.splitlines()[:20]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#separator") or line.startswith("#fields"):
            return "zeek"
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            if "event_type" in obj and ("src_ip" in obj or "timestamp" in obj):
                return "suricata"
            if "_path" in obj or "id.orig_h" in obj or "uid" in obj:
                return "zeek"
    raise IngestionError("Could not detect whether the file is Suricata EVE JSON or a Zeek log. "
                         "Choose the sensor explicitly.")


def ingest_text(session: Session, dataset: Dataset, text: str, filename: str, sensor: str,
                settings: AnalysisSettings) -> IngestionJob:
    env = get_env()
    if sensor == "auto":
        sensor = detect_sensor(text, filename)
    if sensor not in ("suricata", "zeek"):
        raise IngestionError(f"Unsupported sensor '{sensor}'")

    is_tsv = sensor == "zeek" and text.lstrip().startswith("#")
    job = IngestionJob(dataset_id=dataset.id, filename=filename[:255], sensor=sensor,
                       file_format=("zeek-tsv" if is_tsv else f"{sensor}-json"))
    session.add(job)
    session.flush()

    known = set(session.scalars(select(Event.event_id)).all())
    max_field = env.max_field_chars
    max_raw = settings.display.max_raw_payload_chars if settings.display.retain_raw_payload else 512
    rows: list[dict] = []
    rejects: list[RejectedRecord] = []

    def reject(line_no: int, raw: str, reason: str) -> None:
        job.rejected += 1
        if len(rejects) < MAX_REJECT_DETAILS:
            rejects.append(RejectedRecord(job_id=job.id, line_number=line_no, reason=reason[:500],
                                          raw_excerpt=raw[:500]))

    if sensor == "suricata":
        records = ((n, line, obj, None) for n, line, obj in suricata.iter_records(text, filename))
    else:
        records = zeek.iter_records(text, filename)

    for n, line, obj, path in records:
        job.total_records += 1
        if isinstance(obj, Exception):
            reject(n, line, str(obj))
            continue
        ref = f"{filename}:{n}"
        try:
            if sensor == "suricata":
                ev = suricata.parse_record(obj, ref, max_field, max_raw)
            else:
                ev = zeek.parse_record(obj, path, ref, max_field, max_raw)
        except RecordRejected as exc:
            reject(n, line, str(exc))
            continue
        except Exception as exc:  # defensive: never let one record kill the job
            reject(n, line, f"unexpected parser error: {type(exc).__name__}")
            continue
        if ev.source_ip is None and ev.destination_ip is None and ev.event_type != "zeek_notice":
            reject(n, line, "record has no valid source or destination IP")
            continue
        if ev.event_id in known:
            job.duplicates += 1
            continue
        known.add(ev.event_id)
        if ev.normalization_warnings:
            job.with_warnings += 1
        row = ev.to_row()
        row.update(dataset_id=dataset.id, job_id=job.id, detector_tags=[], tag_evidence={})
        rows.append(row)
        job.accepted += 1

    if rows:
        session.bulk_insert_mappings(Event, rows)
    session.add_all(rejects)
    job.status = "completed" if job.accepted else ("failed" if job.total_records else "empty")
    job.message = (f"{job.accepted} accepted, {job.rejected} rejected, {job.duplicates} duplicates"
                   + (f" (only first {MAX_REJECT_DETAILS} rejections stored in detail)"
                      if job.rejected > MAX_REJECT_DETAILS else ""))
    job.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.flush()
    return job
