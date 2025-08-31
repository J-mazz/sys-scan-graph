# FactPack Schema Migration (v2 -> v3)

## Overview
The core scanner currently emits reports conforming to a v2 JSON structure with forward-compatible fields already introduced for v3 (e.g., `base_severity_score`). This document defines the migration plan, compatibility guarantees, and deprecation schedule for moving clients and downstream enrichment layers to the v3 schema.

## Objectives
- Preserve backward compatibility for existing integrators expecting `risk_score` while introducing `base_severity_score` as the canonical static severity-derived score.
- Decouple static severity mapping from holistic, multi-factor risk (which will be computed exclusively in the Python enrichment layer moving forward).
- Provide deterministic output across versions (ordering, numeric stability) to support reproducible hashing and signing.

## Key Field Changes
| Aspect | v2 | v3 (Target) | Rationale |
|--------|----|-------------|-----------|
| Static score field | `risk_score` | `base_severity_score` | Clarifies that value is a severity mapping, not composite risk. |
| Aggregates | `total_risk_score`, `emitted_risk_score` | `total_base_severity`, `emitted_base_severity` (planned) | Align naming with semantic meaning; avoid conflation with future holistic risk. |
| Holistic risk | (implicit / same as static) | Computed downstream only (Python) -> `risk_score` (enrichment) | Separation of concerns & extensibility. |
| Finding object | Single score | Dual: `base_severity_score` (static) + optional enriched `risk_score` | Enables layering while keeping core engine simple. |

## Timeline
| Phase | Milestone | Earliest Date | Actions |
|-------|-----------|---------------|---------|
| P0 | Introduce `base_severity_score` alongside legacy ingestion fallback | COMPLETE | Python layer normalizes; tests to ensure both accepted. |
| P1 | Deprecation Notice | +2 weeks | Emit log/metric if core output still includes legacy `risk_score`. |
| P2 | Aggregate Rename | +4 weeks | Add dual aggregate fields (`total_base_severity` + legacy aliases). |
| P3 | Hard Cut | +8 weeks | Remove legacy `risk_score` from core output; enrichment retains computed `risk_score`. |
| P4 | Alias Removal | +12 weeks | Remove legacy aggregate aliases after consumer adoption. |

## Compatibility Strategy
1. Ingestion Normalization: If a finding lacks `risk_score` but has `base_severity_score`, Python fills `risk_score` & `risk_total` (DONE).
2. Dual Emission (Optional Flag): Add compile flag or runtime option to temporarily include both fields for external consumers (future optional).
3. Metrics & Logging: Add one-time warning when legacy fields encountered after P1.
4. Schema Version Field: Maintain `meta.json_schema_version` value; bump when aggregates renamed; provide machine-readable `migration_stage` field in summary_extension during transition.

### Baseline Bootstrap Flag (`baseline_db_missing`)

During initial environment bootstrap the baseline database may not yet exist. To prevent conflating first-run conditions with truly novel findings, tools (e.g. `query_baseline`) now emit a boolean `baseline_db_missing`:

| Field | Type | Meaning |
|-------|------|---------|
| `baseline_db_missing` | bool | True = baseline DB file absent at query time (bootstrap); False = DB present (result reflects historical comparison). |

Consumer Guidance:
- If `baseline_db_missing` is True, treat `status: new` responses as informational bootstrap (optionally suppress alerts).
- Once any scan has created the DB, subsequent queries will always set it False, allowing reliable differentiation of genuinely new vs existing.
- On errors, the flag still reflects file existence to aid diagnostics.

## Consumer Guidance
- Treat `base_severity_score` as a stable severity-derived scalar (0 if operational error).
- Treat enrichment-layer `risk_score` as dynamic, subject to model/rule evolution; use with version pinning of enrichment logic.
- For deterministic compliance use cases: rely solely on `base_severity_score` + severity rank.

## Test Plan
- Golden hash update when `risk_score` removed from canonical writer.
- Dual acceptance tests: reports containing only legacy `risk_score` (pre-migration) and reports containing only `base_severity_score`.
- Aggregate rename smoke tests verifying both old and new keys present during deprecation window.

## Open Questions
- Should operational errors be completely excluded from aggregate counts (currently excluded from risk sums) in v3? (Pending decision.)
- Introduce per-finding `score_origin` metadata? (Potential future introspection aid.)

## Appendix: Migration Checklist
- [x] Introduce `base_severity_score` in core writer.
- [x] Python ingestion fallback.
- [ ] Aggregate alias fields.
- [ ] One-time deprecation warning logging.
- [ ] Dual emission feature flag (if required by adopters).
- [ ] Golden tests updated for aggregate rename.
- [ ] Remove legacy fields at hard cut milestone.
