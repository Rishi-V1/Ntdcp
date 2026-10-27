"""Dataset management and demo-data loading."""
from __future__ import annotations

import json

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import AnalysisSettings, get_env
from app.ingestion.service import ingest_text
from app.models import Dataset, IngestionJob

DEMO_FILES = [
    ("suricata_eve.json", "suricata"),
    ("zeek_conn.log", "zeek"),
    ("zeek_dns.log", "zeek"),
    ("zeek_http.log", "zeek"),
    ("zeek_ssl.log", "zeek"),
    ("zeek_ssh.log", "zeek"),
    ("zeek_notice.log", "zeek"),
    ("zeek_files.tsv.log", "zeek"),
]


class DemoDataMissing(Exception):
    pass


def active_dataset(session: Session) -> Dataset | None:
    return session.scalars(select(Dataset).where(Dataset.is_active.is_(True)).order_by(Dataset.id.desc())).first()


def activate(session: Session, ds: Dataset) -> None:
    session.execute(update(Dataset).values(is_active=False))
    ds.is_active = True
    session.flush()


def create_dataset(session: Session, name: str, description: str = "", synthetic: bool = False) -> Dataset:
    ds = Dataset(name=name[:200], description=description, synthetic=synthetic, is_active=False)
    session.add(ds)
    session.flush()
    activate(session, ds)
    return ds


def load_demo(session: Session, settings: AnalysisSettings) -> tuple[Dataset, list[IngestionJob]]:
    demo_dir = get_env().demo_dir
    manifest_path = demo_dir / "manifest.json"
    if not manifest_path.exists():
        raise DemoDataMissing(f"Demo data not found in {demo_dir}. Run: python scripts/generate_demo_data.py")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # replace any previous demo dataset (deterministic reload)
    for old in session.scalars(select(Dataset).where(Dataset.synthetic.is_(True))).all():
        session.delete(old)
    session.flush()
    ds = create_dataset(session, f"Synthetic demo v{manifest['version']}",
                        "Deterministic synthetic Suricata + Zeek telemetry (scenarios A–G). Not real-world data.",
                        synthetic=True)
    ds.version = manifest["version"]
    labels_path = demo_dir / "labels.json"
    ds.labels = json.loads(labels_path.read_text(encoding="utf-8")) if labels_path.exists() else None
    jobs = []
    for fname, sensor in DEMO_FILES:
        path = demo_dir / fname
        if not path.exists():
            continue
        jobs.append(ingest_text(session, ds, path.read_text(encoding="utf-8"), fname, sensor, settings))
    session.flush()
    return ds, jobs
