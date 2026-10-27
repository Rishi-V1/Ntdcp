# Network Threat Detection and Attack Correlation Platform (NTDCP)

A passive blue-team analysis layer that sits above **Suricata** and **Zeek**. It turns thousands of
disconnected network alerts into a small number of **evidence-backed, explainable incidents**, then
helps an analyst investigate them:

- normalises Suricata EVE JSON and Zeek JSON/TSV into one versioned schema (the raw record is kept);
- correlates events with temporal, entity and behavioural evidence, with safeguards against over-merging;
- reconstructs the probable attack chain, labelling every stage **OBSERVED**, **INFERRED** or **NOT OBSERVED**;
- maps behaviour to MITRE ATT&CK (local, versioned subset) with method, confidence and evidence;
- scores **risk** (0–100) and **correlation confidence** (0–1) separately, with full breakdowns;
- writes analyst summaries with a **local** LLM through Ollama (Qwen / DeepSeek), validated against the
  evidence, with a deterministic fallback when the model is unavailable or its output fails validation;
- persists analyst workflow (status, assignee, false-positive flag, notes, history) and exports reports;
- includes an evaluation lab that compares the method against baselines on labelled scenarios.

> **Incidents are hypotheses, not proof of attack.** The demo data is synthetic. This is a local
> research/education prototype, not a production-hardened SOC product.

---

## 1. Prerequisites

| Tool | Version | Needed for |
|---|---|---|
| Python | 3.11+ (tested 3.13) | backend, tests |
| Node.js | 20+ (tested 22) | frontend |
| Ollama | any recent | *optional* – local AI summaries |
| Suricata / Zeek | any | *optional* – your own telemetry (demo data needs neither) |

## 2. Install

```bash
# from the project root
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt

cd frontend && npm install && cd ..
cp .env.example .env                 # optional; defaults work as-is
```

## 3. Run

**Option A – development (hot reload, two processes):**

```bash
# terminal 1
cd backend && python -m uvicorn app.main:app --reload --port 8000
# terminal 2
cd frontend && npm run dev
```
Open http://localhost:5173 (the dev server proxies `/api` to port 8000). On Linux/macOS `scripts/dev.sh`
starts both; on Windows use `scripts/dev.ps1`.

**Option B – single process:**

```bash
cd frontend && npm run build && cd ..
cd backend && python -m uvicorn app.main:app --port 8000
```
Open http://127.0.0.1:8000 (the backend serves `frontend/dist`). `scripts/serve.sh` does both steps.

API documentation (OpenAPI/Swagger): http://127.0.0.1:8000/docs

### Database
SQLite is created automatically on first start (`runtime/ntdcp.db`, tables created by
`init_db()`). Delete the `runtime/` folder to start from scratch. Set `NTDCP_DATABASE_URL` for another
SQLAlchemy database (see `docs/ARCHITECTURE.md` for the PostgreSQL migration notes).

## 4. Load the demo data

Click **Load demo data** on the Overview or *Data ingestion* page, or:

```bash
curl -X POST http://127.0.0.1:8000/api/demo/load
```
This ingests ~8,200 synthetic Suricata + Zeek records (scenarios A–G, see `data/demo/SCENARIOS.md`)
and runs correlation. The data is deterministic; regenerate it with
`python scripts/generate_demo_data.py`.

## 5. Your own Suricata / Zeek data (optional)

Upload files on **Data ingestion** (max 50 MB each, configurable):

- Suricata: `eve.json` (one JSON object per line).
- Zeek: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `ssh.log`, `notice.log`, `files.log` in JSON
  (`LogAscii::use_json=T`) or classic TSV. JSON records need `_path` or a recognisable file name.

Tips: enable `community-id: yes` in Suricata and the Community ID package in Zeek – matching IDs give
the strongest cross-sensor links. Create a new dataset per capture. Capture only in an authorised,
isolated lab; the platform itself never sends packets or takes response actions.

## 6. Local LLM (Ollama) – optional

```bash
# install from https://ollama.com, then:
ollama serve                      # if not already running as a service
ollama pull qwen2.5-coder:7b      # primary (configurable)
ollama pull deepseek-r1:7b        # secondary (configurable)
```
In **Settings → Local LLM assistance**: check the URL (default `http://127.0.0.1:11434`), press
**Test connection & discover models**, put the installed model names in *Primary* / *Secondary*, choose
the AI mode, and save. Any other Ollama model names can be used.

| Mode | Behaviour |
|---|---|
| **Off** | deterministic template summaries only |
| **Cached** (default) | reuse a stored summary while the incident's evidence hash is unchanged; otherwise show a template summary |
| **Live local AI** | request a new summary from Ollama (validated; falls back on failure or timeout) |

On a laptop without a GPU a 7B model can take 30–120 s per summary – raise the timeout in Settings if
needed. To try the integration without a model, run `python scripts/mock_ollama.py` (a test double that
imitates the Ollama API; **not** a language model).

## 7. Tests

```bash
cd backend && python -m pytest            # 46 unit + integration tests
cd frontend && npm test                   # 8 component/page tests (Vitest)
# browser end-to-end (needs the app on :8000 serving the build):
pip install playwright && python -m playwright install chromium
python scripts/e2e_smoke.py
```

## 8. Evaluation

**Evaluation lab → Run evaluation** (or `POST /api/evaluation/run`). It runs four grouping methods on
the active dataset – A: every alert separately, B: shared IP + time window, the proposed evidence-aware
correlation, and C: TF-IDF + DBSCAN – and scores them against the dataset's labels (demo only). Every
run stores its parameters and can be exported as Markdown/JSON. Tick *Include local LLM evaluation* to
also measure the configured Ollama models. See `docs/EVALUATION.md`.

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| UI says "Backend unreachable" | start the backend on port 8000; check `NTDCP_CORS_ORIGINS` if you changed ports |
| "No telemetry loaded yet" | load the demo or upload logs |
| `Demo data not found` | `python scripts/generate_demo_data.py` |
| Ollama "not reachable" | `ollama serve`; check the URL in Settings; firewall |
| "Model … is not installed" | `ollama pull <name>` or change the model name in Settings |
| Summaries always "deterministic fallback" | AI mode is Off/Cached, Ollama is down, the request timed out, or the model output failed validation (the reasons are shown on the incident) |
| A Zeek file is rejected | make sure it is JSON or TSV with a `#fields` header, and that the log type is recognisable |
| Start fresh | stop the backend and delete `runtime/` |

## 10. Known limitations

See `docs/LIMITATIONS.md`. In short: network telemetry only, heuristic (uncalibrated) scores, a partial
ATT&CK subset, synthetic evaluation data written by the same developer as the engine, and LLM quality
that has to be measured on your own hardware and models.

## Project layout

```
backend/app/        FastAPI app: ingestion/, normalization/, correlation/, attack_chain/,
                    attack_mapping/, risk/, llm/, evaluation/, reporting/, services/, api/
backend/tests/      pytest suite
frontend/src/       React + TypeScript UI (pages/, components/, layouts/, api/, lib/)
data/demo/          synthetic dataset + labels + SCENARIOS.md
data/mappings/      ATT&CK catalog subset + deterministic mapping rules (versioned)
docs/               architecture, correlation method, evaluation, limitations, implementation report
scripts/            demo generator, mock Ollama, e2e smoke test, start scripts
```

Research basis: Ferazza et al. (2026), "From logs to tactics", *Int. J. Inf. Secur.* 25:79 – adapted from
endpoint/syslog telemetry to network telemetry. The paper's reported results are the paper's and are
not claimed for this implementation.
