"""REST API. Every handler is a plain ``def`` so FastAPI runs it in its worker
threadpool – long operations (correlation, LLM calls) never block the event loop.
Evaluation runs are executed as background jobs and polled by the client."""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.attack_mapping.catalog import get_catalog
from app.core.config import AnalysisSettings, get_env
from app.core.db import get_session, session_scope
from app.evaluation.runner import run_evaluation
from app.ingestion.service import IngestionError, ingest_text
from app.llm import client as llm_client
from app.llm.service import summarize
from app.models import (Analyst, AnalystNote, CorrelationRun, Dataset, Event, EventLink, EvaluationRun, Incident,
                        IngestionJob, RejectedRecord, StatusChange)
from app.normalization.schema import FIELD_DOCS, SCHEMA_VERSION
from app.reporting.report import evaluation_markdown, incident_csv, incident_html, incident_report_dict
from app.schemas import (STATUSES, DatasetOut, EvaluationRequest, IncidentUpdate, JobOut, LinkOut, NoteIn, NoteOut,
                         Page, RejectedOut, RunOut, SummaryOut, SummaryRequest)
from app.services import queries
from app.services.datasets import DemoDataMissing, activate, active_dataset, create_dataset, load_demo
from app.services.pipeline import run_correlation
from app.services.settings_service import load_settings, save_settings

router = APIRouter(prefix="/api")
DB = Annotated[Session, Depends(get_session, scope="function")]  # commit before the response is sent


def _active(session: Session) -> Dataset:
    ds = active_dataset(session)
    if ds is None:
        raise HTTPException(404, "No dataset loaded yet. Load the demo data or upload Suricata/Zeek logs.")
    return ds


def _dataset_out(session: Session, ds: Dataset) -> DatasetOut:
    out = DatasetOut.model_validate(ds)
    out.has_labels = bool(ds.labels)
    out.event_count = session.scalar(select(func.count()).select_from(Event).where(Event.dataset_id == ds.id)) or 0
    return out


# ------------------------------------------------------------------ health / meta
@router.get("/health", tags=["meta"])
def health(session: DB):
    db_ok = True
    try:
        session.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        db_ok = False
    settings = load_settings(session)
    try:
        models = llm_client.list_models(settings.llm.ollama_base_url, timeout=1.5)
        llm = {"available": True, "models": [m["name"] for m in models],
               "version": llm_client.server_version(settings.llm.ollama_base_url, 1.5)}
    except llm_client.OllamaUnavailable as exc:
        llm = {"available": False, "error": str(exc), "models": []}
    ds = active_dataset(session)
    return {"status": "ok" if db_ok else "degraded", "backend": True, "database": db_ok,
            "app_version": get_env().app_version, "llm": {**llm, "mode": settings.llm.mode,
                                                          "base_url": settings.llm.ollama_base_url},
            "active_dataset": ds.name if ds else None, "time": datetime.now(timezone.utc).isoformat()}


@router.get("/schema", tags=["meta"])
def event_schema():
    cat = get_catalog()
    return {"schema_version": SCHEMA_VERSION, "fields": FIELD_DOCS,
            "supported_inputs": {
                "suricata": "EVE JSON, one object per line (event_type alert, dns, http, tls, flow, ssh, anomaly, fileinfo)",
                "zeek": "JSON logs (one object per line, _path or file name identifies the log) or classic TSV with "
                        "#fields/#types headers; conn, dns, http, ssl, ssh, notice, files (others as generic events)"},
            "attack_catalog": {"version": cat.version, "note": cat.coverage_note},
            "max_upload_mb": get_env().max_upload_mb}


@router.get("/analysts", tags=["meta"])
def analysts(session: DB):
    return [a.name for a in session.scalars(select(Analyst).order_by(Analyst.name))]


# ------------------------------------------------------------------ settings
@router.get("/settings", tags=["settings"])
def get_settings(session: DB):
    return load_settings(session).model_dump()


@router.put("/settings", tags=["settings"])
def put_settings(body: AnalysisSettings, session: DB):
    return save_settings(session, body).model_dump()


@router.post("/settings/reset", tags=["settings"])
def reset_settings(session: DB):
    defaults = AnalysisSettings()
    defaults.llm.ollama_base_url = get_env().ollama_base_url
    return save_settings(session, defaults).model_dump()


@router.get("/llm/status", tags=["llm"])
def llm_status(session: DB, base_url: str | None = None):
    settings = load_settings(session)
    url = (base_url or settings.llm.ollama_base_url).rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise HTTPException(422, "base_url must start with http:// or https://")
    try:
        models = llm_client.list_models(url, timeout=3)
        return {"available": True, "base_url": url, "version": llm_client.server_version(url), "models": models,
                "configured": {"primary": settings.llm.primary_model, "secondary": settings.llm.secondary_model},
                "primary_installed": any(m["name"] == settings.llm.primary_model for m in models),
                "secondary_installed": any(m["name"] == settings.llm.secondary_model for m in models)}
    except llm_client.OllamaUnavailable as exc:
        return {"available": False, "base_url": url, "error": str(exc), "models": [],
                "configured": {"primary": settings.llm.primary_model, "secondary": settings.llm.secondary_model}}


# ------------------------------------------------------------------ datasets & ingestion
@router.get("/datasets", response_model=list[DatasetOut], tags=["data"])
def list_datasets(session: DB):
    return [_dataset_out(session, d) for d in session.scalars(select(Dataset).order_by(Dataset.id.desc()))]


@router.post("/datasets", response_model=DatasetOut, tags=["data"])
def new_dataset(session: DB, name: Annotated[str, Form(min_length=1, max_length=200)],
                description: Annotated[str, Form(max_length=1000)] = ""):
    return _dataset_out(session, create_dataset(session, name, description))


@router.post("/datasets/{dataset_id}/activate", response_model=DatasetOut, tags=["data"])
def activate_dataset(dataset_id: int, session: DB):
    ds = session.get(Dataset, dataset_id)
    if ds is None:
        raise HTTPException(404, "Dataset not found")
    activate(session, ds)
    return _dataset_out(session, ds)


@router.delete("/datasets/{dataset_id}", tags=["data"])
def delete_dataset(dataset_id: int, session: DB):
    ds = session.get(Dataset, dataset_id)
    if ds is None:
        raise HTTPException(404, "Dataset not found")
    session.delete(ds)
    session.flush()
    remaining = session.scalars(select(Dataset).order_by(Dataset.id.desc())).first()
    if remaining and not active_dataset(session):
        activate(session, remaining)
    return {"deleted": dataset_id}


@router.post("/demo/load", tags=["data"])
def load_demo_data(session: DB):
    settings = load_settings(session)
    try:
        ds, jobs = load_demo(session, settings)
    except DemoDataMissing as exc:
        raise HTTPException(409, str(exc)) from exc
    run = run_correlation(session, ds, settings)
    return {"dataset": _dataset_out(session, ds).model_dump(mode="json"),
            "jobs": [JobOut.model_validate(j).model_dump(mode="json") for j in jobs],
            "correlation": RunOut.model_validate(run).model_dump(mode="json")}


@router.post("/ingest", tags=["data"])
async def ingest(request: Request, file: UploadFile = File(...), sensor: str = Form("auto"),
                 run_correlation_after: bool = Form(True)):
    """Upload a Suricata EVE JSON or Zeek (JSON/TSV) file into the active dataset.
    The file is parsed in memory only – it is never written to disk."""
    if sensor not in ("auto", "suricata", "zeek"):
        raise HTTPException(422, "sensor must be auto, suricata or zeek")
    limit = get_env().max_upload_mb * 1024 * 1024
    buf = io.BytesIO()
    while chunk := await file.read(1024 * 1024):
        buf.write(chunk)
        if buf.tell() > limit:
            raise HTTPException(413, f"File exceeds the {get_env().max_upload_mb} MB upload limit")
    raw = buf.getvalue()
    if b"\x00" in raw[:4096]:
        raise HTTPException(415, "Binary file rejected: expected UTF-8 text (EVE JSON or Zeek log)")
    text_data = raw.decode("utf-8", errors="replace")
    filename = (file.filename or "upload.log").replace("\\", "/").rsplit("/", 1)[-1][:200]

    def work():
        with session_scope() as session:
            settings = load_settings(session)
            ds = active_dataset(session) or create_dataset(session, "Uploaded telemetry")
            try:
                job = ingest_text(session, ds, text_data, filename, sensor, settings)
            except IngestionError as exc:
                raise HTTPException(422, str(exc)) from exc
            out = {"job": JobOut.model_validate(job).model_dump(mode="json"),
                   "decode_warning": "Invalid UTF-8 bytes were replaced" if "�" in text_data else None}
            if run_correlation_after and job.accepted:
                run = run_correlation(session, ds, settings)
                out["correlation"] = RunOut.model_validate(run).model_dump(mode="json")
            return out
    from starlette.concurrency import run_in_threadpool
    return await run_in_threadpool(work)


@router.get("/ingest/jobs", response_model=list[JobOut], tags=["data"])
def jobs(session: DB):
    ds = _active(session)
    return list(session.scalars(select(IngestionJob).where(IngestionJob.dataset_id == ds.id).order_by(IngestionJob.id)))


@router.get("/ingest/jobs/{job_id}/rejected", response_model=list[RejectedOut], tags=["data"])
def rejected(job_id: int, session: DB):
    return list(session.scalars(select(RejectedRecord).where(RejectedRecord.job_id == job_id)
                                .order_by(RejectedRecord.line_number)))


# ------------------------------------------------------------------ correlation
@router.post("/correlation/run", response_model=RunOut, tags=["analysis"])
def correlation_run(session: DB):
    ds = _active(session)
    return run_correlation(session, ds, load_settings(session))


@router.get("/correlation/runs", response_model=list[RunOut], tags=["analysis"])
def correlation_runs(session: DB):
    ds = _active(session)
    return list(session.scalars(select(CorrelationRun).where(CorrelationRun.dataset_id == ds.id)
                                .order_by(CorrelationRun.id.desc()).limit(20)))


@router.get("/overview", tags=["analysis"])
def get_overview(session: DB):
    return queries.overview(session, _active(session))


# ------------------------------------------------------------------ incidents
@router.get("/incidents", response_model=Page, tags=["incidents"])
def list_incidents(session: DB, q: str | None = None, severity: Annotated[list[str] | None, Query()] = None,
                   status: Annotated[list[str] | None, Query()] = None, sensor: str | None = None,
                   tactic: str | None = None, technique: str | None = None, start: datetime | None = None,
                   end: datetime | None = None, sort: str = "risk_score", order: str = "desc",
                   page: Annotated[int, Query(ge=1)] = 1, page_size: Annotated[int, Query(ge=1, le=200)] = 25):
    ds = _active(session)
    to_naive = lambda d: d.astimezone(timezone.utc).replace(tzinfo=None) if d and d.tzinfo else d  # noqa: E731
    total, items = queries.incident_list(session, ds.id, q, severity, status, sensor, tactic, technique,
                                         to_naive(start), to_naive(end), sort, order, page, page_size)
    return Page(total=total, page=page, page_size=page_size, items=[i.model_dump(mode="json") for i in items])


def _incident(session: Session, incident_id: str) -> Incident:
    inc = session.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return inc


@router.get("/incidents/{incident_id}", tags=["incidents"])
def get_incident(incident_id: str, session: DB):
    return queries.incident_detail(session, _incident(session, incident_id)).model_dump(mode="json")


@router.get("/incidents/{incident_id}/events", response_model=Page, tags=["incidents"])
def get_incident_events(incident_id: str, session: DB, stage: str | None = None,
                        page: Annotated[int, Query(ge=1)] = 1, page_size: Annotated[int, Query(ge=1, le=500)] = 100):
    _incident(session, incident_id)
    total, items = queries.incident_events(session, incident_id, page, page_size, stage)
    return Page(total=total, page=page, page_size=page_size, items=[i.model_dump(mode="json") for i in items])


@router.get("/incidents/{incident_id}/links", response_model=Page, tags=["incidents"])
def get_incident_links(incident_id: str, session: DB, event_id: str | None = None,
                       page: Annotated[int, Query(ge=1)] = 1, page_size: Annotated[int, Query(ge=1, le=500)] = 50):
    inc = _incident(session, incident_id)
    stmt = select(EventLink).where(EventLink.incident_id == inc.id, EventLink.run_id == inc.run_id)
    if event_id:
        stmt = stmt.where((EventLink.event_a == event_id) | (EventLink.event_b == event_id))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.scalars(stmt.order_by(EventLink.score.desc()).offset((page - 1) * page_size).limit(page_size))
    # rule breakdown across all links of the incident
    return Page(total=total, page=page, page_size=page_size,
                items=[LinkOut.model_validate(r, from_attributes=True).model_dump() for r in rows])


@router.get("/incidents/{incident_id}/link-summary", tags=["incidents"])
def get_link_summary(incident_id: str, session: DB):
    inc = _incident(session, incident_id)
    rows = session.execute(select(EventLink.rule, func.count(), func.avg(EventLink.score), func.min(EventLink.score))
                           .where(EventLink.incident_id == inc.id, EventLink.run_id == inc.run_id)
                           .group_by(EventLink.rule)).all()
    return [{"rule": r, "count": c, "avg_score": round(a, 3), "min_score": round(m, 3)} for r, c, a, m in rows]


@router.patch("/incidents/{incident_id}", tags=["incidents"])
def update_incident(incident_id: str, body: IncidentUpdate, session: DB):
    inc = _incident(session, incident_id)
    if body.status and body.status != inc.status:
        session.add(StatusChange(incident_id=inc.id, from_status=inc.status, to_status=body.status,
                                 actor=body.actor, reason=body.reason))
        inc.status = body.status
    if body.assignee is not None:
        name = body.assignee.strip() or None
        if name and session.scalar(select(Analyst).where(Analyst.name == name)) is None:
            raise HTTPException(422, f"Unknown analyst '{name}'")
        if name != inc.assignee:
            session.add(StatusChange(incident_id=inc.id, from_status=inc.status, to_status=inc.status, actor=body.actor,
                                     reason=f"assigned to {name or 'nobody'}"))
        inc.assignee = name
    if body.suspected_false_positive is not None and body.suspected_false_positive != inc.suspected_false_positive:
        inc.suspected_false_positive = body.suspected_false_positive
        session.add(StatusChange(incident_id=inc.id, from_status=inc.status, to_status=inc.status, actor=body.actor,
                                 reason=("marked" if body.suspected_false_positive else "unmarked") + " as suspected false positive"
                                        + (f": {body.reason}" if body.reason else "")))
    inc.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    session.flush()
    session.refresh(inc)
    return queries.incident_detail(session, inc).model_dump(mode="json")


@router.post("/incidents/{incident_id}/notes", response_model=NoteOut, tags=["incidents"])
def add_note(incident_id: str, body: NoteIn, session: DB):
    inc = _incident(session, incident_id)
    note = AnalystNote(incident_id=inc.id, fingerprint=inc.fingerprint, author=body.author.strip(), text=body.text.strip())
    session.add(note)
    session.flush()
    return note


@router.post("/incidents/{incident_id}/summary", response_model=SummaryOut, tags=["llm"])
def generate_summary(incident_id: str, body: SummaryRequest, session: DB):
    inc = _incident(session, incident_id)
    settings = load_settings(session)
    if body.model and body.model not in (settings.llm.primary_model, settings.llm.secondary_model):
        raise HTTPException(422, "model must be one of the configured models (see Settings)")
    row = summarize(session, inc, settings, body.mode, body.model)
    return queries.summary_out(row, inc)


@router.get("/incidents/{incident_id}/summaries", response_model=list[SummaryOut], tags=["llm"])
def summary_history(incident_id: str, session: DB):
    inc = _incident(session, incident_id)
    return [queries.summary_out(s, inc) for s in reversed(inc.summaries)]


def _report(session: Session, inc: Incident) -> dict:
    detail = queries.incident_detail(session, inc).model_dump(mode="json")
    _, events = queries.incident_events(session, inc.id, 1, 5000)
    ds = session.get(Dataset, inc.dataset_id)
    return incident_report_dict(detail, [e.model_dump(mode="json") for e in events],
                                {"name": ds.name, "version": ds.version, "synthetic": ds.synthetic})


@router.get("/incidents/{incident_id}/report", tags=["reports"])
def incident_report(incident_id: str, session: DB, format: str = "json"):
    rep = _report(session, _incident(session, incident_id))
    fname = f"{incident_id}-report"
    if format == "json":
        return Response(json.dumps(rep, indent=1, default=str), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.json"'})
    if format == "csv":
        return PlainTextResponse(incident_csv(rep), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{fname}.csv"'})
    if format == "html":
        return HTMLResponse(incident_html(rep), headers={"Content-Disposition": f'attachment; filename="{fname}.html"'})
    raise HTTPException(422, "format must be json, csv or html")


@router.get("/reports/incidents.csv", tags=["reports"])
def incidents_csv(session: DB):
    ds = _active(session)
    _, items = queries.incident_list(session, ds.id, page_size=10_000)
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "title", "severity", "risk_score", "confidence", "first_seen", "last_seen", "event_count",
                "sensors", "tactics", "status", "assignee", "suspected_false_positive", "synthetic"])
    for i in items:
        d = i.model_dump(mode="json")
        w.writerow([d["id"], d["title"], d["severity"], d["risk_score"], d["confidence"], d["first_seen"], d["last_seen"],
                    d["event_count"], ";".join(d["sensors"]), ";".join(d["tactics"]), d["status"], d["assignee"] or "",
                    d["suspected_false_positive"], d["synthetic"]])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="incidents.csv"'})


# ------------------------------------------------------------------ events
@router.get("/events", response_model=Page, tags=["events"])
def list_events(session: DB, q: str | None = None, sensor: str | None = None, event_type: str | None = None,
                ip: str | None = None, assigned: str | None = None, tagged: bool | None = None,
                warnings: bool | None = None, incident_id: str | None = None,
                page: Annotated[int, Query(ge=1)] = 1, page_size: Annotated[int, Query(ge=1, le=500)] = 50):
    ds = _active(session)
    total, items = queries.event_list(session, ds.id, q, sensor, event_type, ip, assigned, tagged, warnings,
                                      incident_id, page, page_size)
    return Page(total=total, page=page, page_size=page_size, items=[i.model_dump(mode="json") for i in items])


@router.get("/events/types", tags=["events"])
def event_types(session: DB):
    ds = _active(session)
    return [{"event_type": t, "count": c} for t, c in session.execute(
        select(Event.event_type, func.count()).where(Event.dataset_id == ds.id).group_by(Event.event_type)
        .order_by(func.count().desc()))]


@router.get("/events/{event_id}", tags=["events"])
def get_event(event_id: str, session: DB):
    e = session.get(Event, event_id)
    if e is None:
        raise HTTPException(404, "Event not found")
    return queries.event_detail(session, e).model_dump(mode="json")


# ------------------------------------------------------------------ ATT&CK
@router.get("/attack/matrix", tags=["attack"])
def matrix(session: DB):
    return queries.attack_matrix(session, _active(session))


# ------------------------------------------------------------------ evaluation
def _eval_job(run_id: int, include_llm: bool, models: list[str] | None) -> None:
    with session_scope() as session:
        run = session.get(EvaluationRun, run_id)
        ds = session.get(Dataset, run.dataset_id)
        try:
            run_evaluation(session, ds, load_settings(session), include_llm, models, run=run)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            session.rollback()
            run = session.get(EvaluationRun, run_id)
            run.status = "failed"
            run.message = f"{type(exc).__name__}: {exc}"[:1000]


@router.post("/evaluation/run", tags=["evaluation"])
def start_evaluation(body: EvaluationRequest, background: BackgroundTasks, session: DB):
    ds = _active(session)
    run = EvaluationRun(dataset_id=ds.id, status="running", params={"include_llm": body.include_llm, "models": body.models})
    session.add(run)
    session.flush()
    background.add_task(_eval_job, run.id, body.include_llm, body.models)
    return {"id": run.id, "status": "running"}


def _eval_out(r: EvaluationRun) -> dict:
    return {"id": r.id, "dataset_id": r.dataset_id, "created_at": r.created_at.isoformat() + "Z", "status": r.status,
            "params": r.params, "results": r.results, "duration_ms": r.duration_ms, "message": r.message}


@router.get("/evaluation/runs", tags=["evaluation"])
def evaluation_runs(session: DB):
    ds = _active(session)
    return [{k: v for k, v in _eval_out(r).items() if k != "results"} | {"summary": _eval_brief(r)}
            for r in session.scalars(select(EvaluationRun).where(EvaluationRun.dataset_id == ds.id)
                                     .order_by(EvaluationRun.id.desc()).limit(30))]


def _eval_brief(r: EvaluationRun) -> dict | None:
    m = (r.results or {}).get("methods", {}).get("proposed_evidence_aware")
    if not m:
        return None
    return {"incidents": m["incidents"], "f1": (m.get("grouping") or {}).get("f1"),
            "llm": bool((r.results.get("llm") or {}).get("models"))}


@router.get("/evaluation/runs/{run_id}", tags=["evaluation"])
def evaluation_run(run_id: int, session: DB):
    r = session.get(EvaluationRun, run_id)
    if r is None:
        raise HTTPException(404, "Evaluation run not found")
    return _eval_out(r)


@router.get("/evaluation/runs/{run_id}/export", tags=["evaluation"])
def evaluation_export(run_id: int, session: DB, format: str = "json"):
    r = session.get(EvaluationRun, run_id)
    if r is None or r.status != "completed":
        raise HTTPException(404, "Completed evaluation run not found")
    out = _eval_out(r)
    if format == "json":
        return Response(json.dumps(out, indent=1), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="evaluation-{run_id}.json"'})
    if format == "md":
        return PlainTextResponse(evaluation_markdown(out), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="evaluation-{run_id}.md"'})
    raise HTTPException(422, "format must be json or md")


_ = STATUSES  # exported for clients via OpenAPI enum
