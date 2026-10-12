# Labforce Dementor v3 — Enterprise Architecture

## Product boundary

Dementor is a read-only Salesforce Org Intelligence, Architecture & Health engine. It may retrieve/read metadata and query runtime evidence, but it has no deploy, DML, data mutation, metadata mutation or Apex Anonymous execution path.

## Intelligence pipeline

```text
Salesforce metadata + runtime read evidence + optional data sample
                         |
                         v
              Normalized component inventory
                         |
                         v
                 Dependency / lineage edges
                         |
                         v
                    Org Digital Twin
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
  architecture       security/data     runtime/testing
  intelligence       intelligence       intelligence
        |                |                |
        +----------------+----------------+
                         |
                         v
          Evidence-aware findings & health
                         |
                         v
       Remediation + Advisor + Change Impact
                         |
                         v
          JSON / MD / HTML / PDF / SARIF / RAG pack
```

## Enterprise Intelligence Core

The Digital Twin de-duplicates logical edges discovered by multiple scanners, preserves all evidence locations, and computes graph topology without inflating metrics. It exposes structural hotspots, strongly-connected cycles, automation cycles, articulation points and component neighborhoods.

The Remediation Planner combines finding severity, confidence and structural criticality. P0 is reserved for sufficiently supported critical findings. All remediation items explicitly prohibit automatic mutation.

The Capability Matrix reports READY, PARTIAL or UNAVAILABLE from actual collected evidence. Missing Event Monitoring licenses, inaccessible Tooling API evidence or opt-out data profiling are represented as evidence gaps rather than healthy scores.

The Architecture Advisor is deterministic and evidence-grounded. v3 does not require an external LLM to make risk claims. A future narrative LLM layer may consume the Knowledge Pack, but deterministic evidence remains the source of truth.

## Data protection

Data profiling is opt-in. Raw business values are not persisted. Cardinality is calculated from hashes, OwnerId skew uses truncated SHA-256 identifiers, and Event Monitoring user identifiers are hashed before app/user usage evidence is persisted.

## Historical/change intelligence

Existing snapshot diff, architecture timeline, drift, PR impact, component impact, source fingerprint, test selection, SARIF and policy gates remain part of v3. Assessments are immutable evidence snapshots and can be compared longitudinally.

## Known evidence-dependent boundaries

Exact record visibility after every Salesforce sharing semantic, Event Monitoring coverage, full dynamic Apex reflection/payload lineage, and runtime business criticality depend on org features, licenses, permissions and organization-specific context. Dementor labels these as partial/unavailable rather than asserting unsupported certainty.
