# v3 Final Readiness Criteria

The engine is considered product-grade when all of the following remain true:

- read-only safety invariant passes payload validation;
- all findings expose confidence and evidence warnings are visible;
- graph edges are normalized before final snapshot storage;
- missing telemetry produces N/A/PARTIAL/UNAVAILABLE, never a fabricated 100/healthy state;
- P0/P1 remediation requires human validation;
- optional record profiling persists no raw business values;
- offline impact/diff/timeline/policy/SARIF commands require no Salesforce mutation;
- JSON, Markdown, HTML and PDF reporting smoke tests succeed;
- automated test suite passes before packaging.

External Salesforce licenses and permissions can still reduce evidence coverage. That is an environment limitation, not a reason to overstate assessment certainty.
