# SemLabs

**A physics-led topological analysis engine that discovers the semantic structure hidden inside your data warehouse's query history.**

---

## The Problem: Warehouse Entropy

Every mature Snowflake warehouse tells two stories. The first is the one its architects intended — clean schemas, documented tables, orderly naming conventions. The second is the one written by its users over thousands of queries: implicit joins that were never formalized, columns that became de facto dimensions through repetition, and tables so heavily referenced they warp the entire dependency graph around themselves.

This second story is the one that matters, and it is nearly impossible to read by hand.

The column-level dependency graph of a production warehouse is not a tidy tree. It is a **scale-free network** — a topology where a small number of nodes (columns like `USER_ID`, `CREATED_AT`, `ACCOUNT_ID`) accumulate a disproportionate share of all connections. These **God-Nodes** distort any naive clustering attempt. Standard community detection algorithms choke on them, grouping hundreds of unrelated columns into a single meaningless blob because they all happen to join through the same foreign key.

At the other extreme, warehouses with rigid ELT patterns produce **flat-mesh topologies** — graphs so uniformly connected that no community structure is visible at all. The signal is there, but it is buried under a homogeneous layer of weak, evenly-distributed edges.

SemLabs treats this as a physics problem. It measures the power-law exponent (gamma) of your warehouse's degree distribution, classifies the topology into one of three regimes, and applies regime-specific transformations before clustering. The result is a deterministic, reproducible set of **business concepts** — groups of columns that belong together not because someone said so, but because the query history proves it.

---

## Features

### Structural Ingestion
- Connects to Snowflake's `INFORMATION_SCHEMA` and `ACCOUNT_USAGE.QUERY_HISTORY` to ingest up to 100K historical SELECT statements
- Full SQL AST parsing via `sqlglot` (Snowflake dialect) with extraction of JOIN edges, projected columns, filter predicates, and GROUP BY references
- Automatic column classification: **Measure** (aggregation functions), **Time Dimension** (date functions), **Dimension** (GROUP BY)
- `SELECT *` constraint enforcement — star queries contribute join edges only, preventing false co-occurrence inflation

### Topological Analysis Engine
- Column-level graph construction with three weighted edge types: explicit JOINs (5.0), query co-occurrence (1.0), and Levenshtein name similarity (0.5)
- Power-law gamma calculation via weighted log-log regression on degree frequency distributions
- Three-regime preprocessing:
  - **God-Node** (γ < 2.0) — Z-score pruning of super-hub columns
  - **Scale-Free** (2.0 ≤ γ ≤ 3.0) — no transformation needed
  - **Flat-Mesh** (γ > 3.0) — sigmoid edge-weight boosting to surface latent community boundaries
- Louvain community detection per connected component with multi-resolution sweep (1.5, 2.0, 2.5) and modularity-optimal partition selection
- PK/FK cardinality inference via naming-convention heuristics

### Semantic Discovery
- Confidence scoring per concept: `0.3 × density + 0.7 × volume`, where density is the internal edge ratio and volume is a sigmoid-normalized average edge weight
- Cross-concept macro-edge aggregation for inter-concept relationship mapping
- Maximum spanning tree extraction for co-occurrence-based join inference within concepts
- Orphan detection: catalog columns with zero query history and failed Louvain clusters (size < 2)

### Interactive Review
- Dual-layer force-directed graph visualization: Macro view (concept-level) and Micro view (column-level)
- Per-concept and per-column approval workflows
- Manual column reclassification, cross-concept column moves, and manual join creation
- Export to **dbt MetricFlow** `semantic_models` YAML and **Cube.js** YAML/JS

---

## Architecture

### Tech Stack

| Layer | Technology | Role |
|-------|-----------|------|
| **API** | FastAPI + Uvicorn | Async REST API with JWT auth |
| **ORM** | SQLAlchemy 2.0 + aiosqlite | Async persistence (SQLite) |
| **Validation** | Pydantic 2.5 | Request/response schemas and settings |
| **SQL Parsing** | sqlglot | AST extraction from Snowflake SQL |
| **Graph Engine** | NetworkX | Column-level undirected graph |
| **Clustering** | python-louvain | Louvain community detection |
| **Scoring** | NumPy + SciPy | Gamma regression, Z-score pruning |
| **String Distance** | Levenshtein | Cross-table column name similarity |
| **Warehouse** | snowflake-connector-python | Metadata and query history ingestion |
| **LLM** | google-genai | On-demand column description generation |
| **Frontend** | Next.js 14 (App Router) | React 18, TypeScript |
| **State** | Zustand 5 | Client-side semantic layer state |
| **Server State** | TanStack React Query 5 | API cache and synchronization |
| **Validation (FE)** | Zod 4 | Runtime schema validation |
| **Visualization** | react-force-graph-2d + d3-force | Interactive graph rendering |
| **Styling** | Tailwind CSS | Utility-first CSS |

### Engine Pipeline

```
Snowflake ─── INFORMATION_SCHEMA ──► Catalog (schemas, tables, columns, types)
         ─── QUERY_HISTORY ────────► Raw SQL logs (up to 100K)
                                         │
                                    sqlglot AST
                                         │
                                    ParsedQuery[]
                                    (joins, projections, filters, roles)
                                         │
                               ┌─────────┴──────────┐
                               ▼                     ▼
                        Join Edges (A)      Co-occurrence Edges (B)
                               │                     │
                               └──────┬──────────────┘
                                      ▼
                              NetworkX Graph + Name Similarity Edges (C)
                                      │
                                calculate_gamma()
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                    God-Node     Scale-Free    Flat-Mesh
                    (prune)      (no-op)       (boost)
                         │            │            │
                         └────────────┼────────────┘
                                      ▼
                              Louvain Clustering
                                      │
                              ConceptCluster[]
                              (confidence, joins, columns)
                                      │
                              Serializer ──► SemanticLayerScanResult JSON
                                                    │
                                              Frontend Store
                                              (review, approve, export)
                                                    │
                                              dbt / Cube.js YAML
```

---

## Roadmap

- [ ] **Adaptive Gamma-based Normalization** — Dynamic edge-weight scaling that continuously adjusts to shifting topology regimes as new query history is ingested, replacing the current static threshold model
- [ ] **Airflow Provider Integration** — A native Airflow provider package (`apache-airflow-providers-semlabs`) enabling scan orchestration as DAG tasks, with XCom-based result passing and connection hook management
- [ ] **Automated dbt Semantic Layer YAML Generation** — End-to-end pipeline from scan completion to dbt project PR: auto-generate `semantic_models` YAML, validate against MetricFlow schemas, and open a pull request via GitHub API without manual export

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm 9+

### Backend

```bash
cd backend

python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

Create a `.env` file in the `backend/` directory (or project root) for any overrides:

```env
SECRET_KEY=your-secret-key
GEMINI_API_KEY=your-gemini-key
DEBUG=true
```

Start the API server:

```bash
uvicorn backend.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`. Health check: `GET /health`.

### Frontend

```bash
cd frontend

npm install

npm run dev
```

The UI will be available at `http://localhost:3000`.

### Synthetic Mode

If no Snowflake credentials are configured, the scanner falls back to synthetic topology generators. This allows full pipeline testing — graph construction, gamma classification, Louvain clustering, and concept assembly — without a warehouse connection. Available topologies: `scale_free`, `spaghetti`, `demo_god_node`, `islands`, `demo_star`, `cycle`.

---

## Project Structure

```
backend/
  main.py               Application entry point
  core/                 Config, JWT security, vault
  db/                   SQLAlchemy async engine
  engine/
    ingestor.py         SQL AST parsing (sqlglot)
    parsers.py          Batch parsing, scope filtering
    graph_builder.py    NetworkX graph construction
    scoring.py          Gamma, density, volume scoring
    analyzer.py         Full analysis pipeline orchestration
    serializer.py       GraphResult → JSON contract
    scanner.py          7-step async scan orchestrator
  models/               SQLAlchemy ORM + Pydantic schemas
  api/routes/           REST endpoints

frontend/src/
  app/                  Next.js pages
  components/           Review graphs, dashboards, modals
  lib/                  Compilers (dbt, Cube), graph utils, Zod schemas
  store/                Zustand semantic layer state
```

---

## License

Proprietary. All rights reserved.
