# Labforce Dementor for Salesforce v4.2.1 — Release Validation

Date: 2026-10-12

## Release status

**PACKAGE_READY**

The assessment engine remains `PRODUCT_GRADE_CORE`. Version 4.2.1 adds real-time terminal progress and pt-BR assessment/report content while retaining the existing read-only and AI-consent controls.

## Implemented in v4.2.1

- seven visible assessment stages with current activity and elapsed time;
- animated progress on interactive terminals and stable line output in CI/logs;
- live detail for core runtime queries and long Salesforce metadata operations;
- explicit completed, safely skipped and failed states;
- `--no-progress` for silent integrations.
- pt-BR titles, descriptions, recommendations, charts and labels in JSON, Markdown, HTML, PDF and impact reports;
- stable technical keys/enums plus localized display labels for backward compatibility.

## Implemented in v4.2

- installable wheel and source distribution named `labforce-dementor`;
- primary `dementor` executable and backward-compatible `labforce-dementor` alias;
- dependency-light `--version` entry point;
- package metadata for Python 3.11 and 3.12;
- packaged report template and exact Labforce Base UI logo;
- dedicated public PyPI README with `uv tool` as the recommended installation path;
- free proprietary license declared through `LicenseRef-Labforce-Free-Proprietary-1.0` and embedded in the wheel;
- GitHub release workflow for PyPI Trusted Publishing;
- CI validation for package build, metadata and complete platform tests;
- complete test runner support for both `unittest` and pytest function-style tests.

## Implemented in v4

- deterministic record-save transaction topology / order-of-execution graph
- automation collision scoring across Flow, Trigger, Validation Rule, Workflow and Approval Process evidence
- deep Flow graph analysis: loops, record/action operations, fault-connector evidence and unreachable candidates
- Apex call graph, fan-in/fan-out, sharing-mode analysis and conservative SOQL/DML-in-loop candidates
- static test-to-class mapping correlated with ApexCodeCoverageAggregate when available
- evidence-aware Data Health, null-density/cardinality/LDV/ownership-skew correlation without raw-value persistence
- Runtime Health across Event Monitoring, app/user evidence, API clients, failed async Apex and coverage
- Integration Health across Apex callouts and Named Credential evidence
- normalized field-lineage index
- offline read-only change/remove/deprecate simulator with downstream breaking paths and migration plan
- continuous intelligence across snapshots: health trends, new/resolved risks and architecture drift
- capability matrix expanded with transaction, Flow, Apex, testing, data, runtime, integration, simulation and continuous-intelligence capabilities
- Knowledge Pack v3 with final intelligence artifacts
- Markdown/HTML/PDF report sections for the final intelligence layer
- final readiness contract with explicit product-vs-telemetry distinction

## Validation

- Python compileall: PASS
- Dementor automated tests: **53 passed**
- Complete platform suite: **397 passed across 85 modules**
- Legacy regression suite: PASS
- New v4 intelligence tests: PASS
- CLI `--version`: PASS (`dementor 4.2.1` and `labforce-dementor 4.2.1`)
- CLI `simulate`: PASS
- CLI `continuous`: PASS
- JSON report generation: PASS
- Markdown report generation: PASS
- HTML report generation: PASS
- Branded PDF report generation from the installed wheel: PASS
- Wheel build: PASS (`labforce_dementor-4.2.1-py3-none-any.whl`)
- Source distribution build: PASS (`labforce_dementor-4.2.1.tar.gz`)
- `twine check --strict`: PASS
- PEP 639 license expression and packaged license file: PASS
- isolated install with `uv tool install <wheel>`: PASS
- Fresh-environment wheel installation with declared dependencies: PASS
- Wheel assets match the canonical Base UI logo byte-for-byte: PASS
- Working-tree and Git-history distribution audits: PASS
- Read-only guardrail contract preserved: PASS

PyPI upload is performed by GitHub Trusted Publishing when the `v4.2.1` release is published.

## Safety contract

Dementor contains no deployment, DML, data import/upsert/delete, metadata mutation or Apex Anonymous execution capability. Change simulation is offline and sets `mutation_executed=false`; remediation continues to set `automatic_mutation_allowed=false`.

## Residual boundaries

These are platform/evidence boundaries, not missing engine features:

1. exact Event Monitoring depth depends on Salesforce licensing and event availability;
2. exact record-level effective access depends on sharing semantics and queryable evidence;
3. data profiling is opt-in and sample-bounded by design;
4. static analysis cannot make dynamic/configuration-driven dependencies mathematically complete, so such edges remain confidence-scored;
5. duplicate semantics require organization-specific business keys and are intentionally not inferred from low cardinality alone.

Those boundaries must remain explicit rather than be hidden behind false-positive “100% coverage” claims.
