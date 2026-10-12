# Security Model

Labforce Dementor for Salesforce is designed as a read-only assessment engine.

## Hard controls
- Salesforce CLI allow-list.
- REST GET-only.
- No deploy commands.
- No DML commands.
- No Apex Anonymous.
- No mutation endpoint wrappers.
- API budget safety floor.
- Deployment/validate detection before metadata retrieve.
- Data profiling is opt-in and raw sampled values are not persisted.

## Evidence
Every run records executed CLI commands, read errors, API budget estimates and an artifact integrity manifest.

## Optional AI complement

- The deterministic assessment is complete before AI is considered.
- `ai-preview` performs no provider request and creates a reviewable, sanitized payload.
- A provider request requires the exact single-use authorization phrase and the authorizing user identifier.
- Consent is bound to assessment and input SHA-256 hashes, provider, model, scopes, prompt version and expiry.
- Credentials come from a trusted local lease and are never persisted in the preview, prompt, output or audit receipt.
- Ollama is restricted to the local loopback interface.
- AI output is schema-validated and may cite only finding IDs present in the deterministic assessment.
- AI output is advisory and stored separately; it cannot replace or mutate deterministic scores and findings.
