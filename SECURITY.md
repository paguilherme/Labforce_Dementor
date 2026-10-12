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
- Deployment/validate and API headroom checks between retrieve batches.
- Fresh retrieve directories and org identity / SHA-256 validation on resume.
- Partial or unverified retrieve coverage stops analysis by default; audit is preserved.
- Data profiling is opt-in and raw sampled values are not persisted.

## Evidence
Every run records executed CLI commands, read errors, API budget estimates and an artifact integrity manifest.

## Optional AI complement

- The deterministic assessment is complete before AI is considered.
- `ai-preview` performs no provider request and creates a reviewable, sanitized payload.
- A provider request requires the exact single-use authorization phrase and the authorizing user identifier.
- Consent is bound to assessment and input SHA-256 hashes, provider, model, scopes, prompt version and expiry.
- The guided flow uses authenticated local Codex/Claude/Gemini CLIs and never loads API credentials or the Base Salesforce vault.
- Codex/Claude authentication status rejects API credentials; Gemini is configured for personal OAuth. Unsupported flags fail without a permissive fallback.
- Local generation runs in a temporary directory with restricted tools/MCP/hooks and a minimal inherited environment. Data goes over stdin; account quotas and provider data processing still apply.
- CLI timeout/error messages never echo stdout, prompt or secrets. Corporate managed CLI policy remains an environment boundary to validate.
- Legacy API adapters remain available only through explicit manual provider selection. Their credentials are not persisted in output artifacts.
- Ollama is restricted to the local loopback interface.
- AI output is schema-validated and may cite only finding IDs present in the deterministic assessment.
- AI output is advisory and stored separately; it cannot replace or mutate deterministic scores and findings.
