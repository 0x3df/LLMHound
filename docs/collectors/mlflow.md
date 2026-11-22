# MLflow collector

> **Status: Implemented — anonymous, read-only, bounded.** Companion to
> [design](../01-design.md),
> [graph model](../02-graph-model.md), and
> [capability matrix](../03-collector-capabilities.md).
> Implemented in `internal/collectors/mlflow`.

The MLflow collector performs anonymous, bounded, read-only enumeration of
MLflow tracking and model-registry servers (server version, experiments,
registered models, artifact-store locations, artifact inventory, and
allowlisted small text artifacts) without downloading model weights or mutating
state.

## Collection Policy and Safety

- **Read-Only & Anonymous:** No credentials are sent. Metadata and artifact
  checks use HTTP `GET` only; run/model creation or transition endpoints are
  never called.
- **No Model Weights (`mlflow_artifact_text`):** Artifact listing enumerates
  files and sizes only. Content-tier reads via `/get-artifact` are strictly
  restricted to allowlisted small text files (`MLmodel`, `requirements.txt`,
  `conda.yaml`, `python_env.yaml`, `serving_input_example.json`), exclude binary
  blobs, and never request `.pkl`, `.pt`, `.bin`, `.safetensors`, `.onnx`,
  `.h5`, `.joblib`, `.tar`, or `.zip` weights.
- **Sanitized Store References:** Reported `artifact_location` and model
  version `source` URIs are stripped of credentials, query strings, and
  fragments before entering `store_refs` and `ArtifactStore` nodes.
- **TLS & Redirects:** TLS verification is enforced by default unless
  `--insecure` is explicitly enabled and recorded; redirects are bounded and
  rechecked per hop.

## Allowlisted Operations

| Check ID | Operation | Endpoint | Method | Purpose | Outcome Semantics |
|---|---|---|---|---|---|
| `mlflow_version` | `mlflow_version` | `/version` | `GET` | MLflow server version (excluded from `anon_operations`) | `success`: valid plain-text version; `denied`: 401/403; `failed`: HTML/JSON, 404, 429, truncated, or transport error |
| `mlflow_experiments` | `mlflow_experiments` | `/api/2.0/mlflow/experiments/search` | `GET` | Paginated experiment and artifact-store inventory | `success`: experiments listed anonymously; `denied`: 401/403; `failed`: 404, 429, malformed, or transport error |
| `mlflow_registered_models` | `mlflow_registered_models` | `/api/2.0/mlflow/registered-models/search` | `GET` | Paginated registered models, versions, stages, and aliases | `success`: models listed anonymously; `denied`: 401/403; `failed`: 404, 429, malformed, or transport error |
| `mlflow_artifacts_list` | `mlflow_artifacts_list` | `/api/2.0/mlflow/artifacts/list` | `GET` | Artifact file inventory per discovered `run_id` | `success`: >=1 run listed; `skipped`: no runs or unconfirmed; `denied`/`failed`: refused or errored |
| `mlflow_artifact_text` | `mlflow_artifact_text` | `/get-artifact` | `GET` | Bounded allowlisted small text artifact capture into `.content.jsonl` | `skipped`: disabled by `content.*` policy or no allowlisted text files; `success`: >=1 artifact captured; `denied`/`failed`: refused or errored |

## Graph and Evidence Mapping

- **Nodes:**
  - `MLflowServer` (with `AIService` umbrella label), carrying the shared
    [service property contract](../02-graph-model.md#property-contract)
    (endpoint, access, `exec_surface: ["model_mutation"]` with `inferred`
    basis, `store_refs`, `model_count`, content summary, TLS),
    `software_version`, `software_version_raw`, and `experiment_count`.
  - `ModelArtifact` nodes (`Contains` from `MLflowServer`), carrying
    `model_name`, `model_version` (distinct from MLflow server version),
    `stage`, `run_id`, `source`, and `aliases`.
  - `ArtifactStore` nodes (`Contains` from `MLflowServer`), carrying sanitized
    `store_uri`.
  - Fallback `NetworkEndpoint` when unmapped.
- **Edges:**
  - `Contains` (`MLflowServer` → `ModelArtifact` / `ArtifactStore`).
  - `ObservedAt` (`MLflowServer` → mapped native node or `NetworkEndpoint`).
- **Evidence sidecar:** `check_result` / access evidence, `fingerprint`, `tls`,
  `redirect`, and `correlation` records.
