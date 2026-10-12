# Labforce Dementor for Salesforce v4.3.0

O diagnóstico permanece determinístico e read-only. A v4.3.0 adiciona retrieve abrangente em lotes com manifesto auditável, candidatos a Classes Deus de produção/testes, governança dos limites da org e complemento por CLI local autenticado, sem chave de API.

Veja a [auditoria e documentação da v4.3.0](docs/RETRIEVE_GOVERNANCE_LOCAL_AI.md) para configuração, metodologia e limites de cobertura.

## Instalação via CLI

A distribuição oficial usa o nome `labforce-dementor`; depois da instalação, o comando principal é `dementor`. A instalação recomendada usa o `uv tool`, que mantém o executável isolado do Python do sistema:

```bash
uv tool install labforce-dementor
dementor --version
dementor doctor
```

Também é possível usar `pipx install labforce-dementor` ou instalar com pip dentro de um ambiente virtual. O executável legado `labforce-dementor` permanece disponível como alias. Python 3.11 ou superior é obrigatório; uma análise de org conectada também requer a Salesforce CLI (`sf`).

Em sistemas protegidos pelo PEP 668, o pip global retorna `externally-managed-environment`. Use `uv tool`, pipx ou um ambiente virtual e não use `--break-system-packages`.

O nome simples de distribuição `dementor` já pertence a um projeto de terceiros no PyPI. Por isso, `pip install dementor` não instala o produto da Labforce; o comando correto é `pip install labforce-dementor`.

Para instalar um wheel entregue diretamente pela Labforce:

```bash
uv tool install ./labforce_dementor-4.3.0-py3-none-any.whl
```

## Complemento opcional por IA

Em um terminal interativo, `dementor run` pergunta ao final se você deseja gerar o complemento. O assistente oferece Codex, Claude Code ou Gemini CLI instalados no PATH e pede modelo, escopo dos dados e identificação de quem autoriza; cria a prévia sanitizada e só envia dados depois que você digita a frase de autorização exibida. A opção inicial de gerar o relatório ainda não autoriza o envio.

Para aproveitar um assessment já concluído, sem repetir a coleta Salesforce:

```bash
dementor ai-report --assessment assessments/MINHA_ORG/EXECUCAO/assessment.json
```

Use `--no-ai-prompt` no `run` para pular a pergunta. Em sessões sem terminal interativo, o Dementor não pergunta nem chama IA e mostra como iniciar a etapa depois. Cancelar ou falhar na etapa de IA preserva o assessment. O complemento usa os mesmos controles de consentimento dos comandos abaixo.

1. Gere uma prévia. Essa etapa não faz chamada externa e grava o conteúdo sanitizado que poderá ser enviado:

```bash
dementor ai-preview \
  --assessment assessment.json \
  --provider codex-local \
  --model default \
  --scope findings_with_evidence \
  --output ai-consent-preview.json
```

2. Revise `ai-consent-preview-input.json` e use a frase de autorização exibida pelo comando:

```bash
dementor ai-complement \
  --preview ai-consent-preview.json \
  --authorize AUTORIZAR-XXXXXXXX \
  --authorized-by usuario@example.com \
  --output-dir ai-complement-report
```

No fluxo guiado, os CLIs usam suas próprias contas autenticadas e quotas. O Dementor não solicita chave de API nem depende da Base Salesforce. O CLI ainda envia o payload autorizado para processamento pelo provedor. Executáveis antigos ou não autenticados falham sem fallback para API. Os adapters de API/Ollama continuam somente nos comandos manuais explícitos por compatibilidade.

O consentimento é preso ao hash do diagnóstico, provedor, modelo, escopos, prompt e payload. Ele expira, é de uso único e deixa um recibo local. O resultado da IA é um relatório consultivo separado e não altera score, severidade ou achados.

## Identidade dos relatórios

Os dados humanos do assessment e os relatórios JSON, Markdown, HTML e PDF são gerados em português (pt-BR). Identificadores técnicos, nomes de componentes e enums estáveis são preservados para integrações. Todos os relatórios registram a empresa `Labforce`, o sistema `Labforce Dementor` e a data/hora de geração. Os formatos visuais usam no topo o ativo WebP extraído da UI da Labforce Base e incluem o mesmo registro no rodapé.

---

# Labforce Dementor for Salesforce v3.0.0

## Salesforce Org Intelligence, Architecture & Health Platform

v3.0 consolidates the assessment engine into an enterprise intelligence layer while preserving the read-only safety contract.

### Enterprise Intelligence Core

- **Org Digital Twin**: normalized dependency graph with node/edge taxonomy, structural criticality, articulation points and strongly connected cycles.
- **Automation-cycle detection**: highlights Flow/Apex/Trigger/Validation dependency cycles for recursion and order-of-execution review.
- **Evidence Quality**: measures finding evidence coverage and confidence instead of treating missing telemetry as health.
- **Capability Matrix**: reports READY/PARTIAL/UNAVAILABLE status for metadata, lineage, runtime, security, data profiling, Event Monitoring, CI and safety capabilities.
- **Remediation Planner**: prioritizes findings into P0/P1/P2/P3 using severity, confidence and structural blast radius; it never mutates the org.
- **Architecture Advisor**: deterministic, evidence-grounded recommendations for hotspots, cycles, critical findings and missing assessment evidence.
- **Competitive Readiness**: internal capability-readiness matrix for benchmarking the product without making unsupported vendor-performance claims.
- **Extended governance metadata**: Workflow Rules, Approval Processes, Sharing Rules, Permission Set Groups, Custom Permissions, CORS and CSP trusted-site inventory.
- **Component Explain**: offline neighborhood explanation over a prior assessment snapshot.

New offline commands:

```bash
dementor explain --assessment assessment.json --component Account.Status__c --depth 3
dementor remediation --assessment assessment.json --output remediation-plan.json
dementor capabilities --assessment assessment.json --output capability-matrix.json
```

The v3.0 goal is product-grade assessment intelligence, not autonomous org mutation. Any high-impact remediation remains subject to human validation and the existing read-only guardrails.

---

# Labforce Dementor for Salesforce v2.0.0

## Architecture Intelligence & Deployment Impact

A v2.0 adiciona inteligência temporal e de mudança sobre o assessment:

- `pr-impact`: converte `git diff base...head` em componentes Salesforce e propaga impacto pelo dependency graph;
- `timeline`: mostra edges adicionados/removidos, findings novos/resolvidos e delta de health;
- `sarif`: exporta findings em SARIF 2.1.0 para integração com code scanning;
- `criticality`: calcula um proxy estrutural de criticidade para priorização;
- base para incremental assessment, identificando arquivos/componentes alterados via fingerprint.

### PR / deployment impact

```bash
dementor pr-impact \
  --assessment assessment.json \
  --repo-dir . \
  --base origin/developer \
  --head HEAD \
  --depth 3
```

### Architecture timeline

```bash
dementor timeline --from previous.json --to current.json --output timeline.json
```

### SARIF

```bash
dementor sarif --assessment assessment.json --output dementor.sarif
```

### Criticality

```bash
dementor criticality --assessment assessment.json --output criticality.json
```

> `criticality` é inicialmente um proxy estrutural baseado em conectividade e findings. Criticidade de negócio real deve aceitar override/curadoria da organização nas próximas camadas.

---

# Labforce Dementor for Salesforce v1.5.0

## Enterprise Assessment + CI Intelligence

A v1.5 adiciona uma camada offline de governança sobre o snapshot da org.

### Novos comandos

```bash
# Drift entre a org capturada no assessment e um source tree Git/local
dementor drift \
  --assessment assessments/ORG/RUN/assessment.json \
  --repo-dir force-app/main/default \
  --output drift-report.json

# Seleção inteligente de testes
dementor tests \
  --assessment assessments/ORG/RUN/assessment.json \
  --component Account.Status__c \
  --component AccountService \
  --tests-file RunSpecifiedTests.txt

# Knowledge Pack para RAG/agentes
dementor knowledge-pack \
  --assessment assessments/ORG/RUN/assessment.json \
  --output-dir knowledge-pack

# Policy gate
dementor policy \
  --assessment current.json \
  --before previous.json \
  --policy policies/strict-production/policy.yml

# CI gate (exit code != 0 quando a policy falha)
dementor ci \
  --assessment current.json \
  --before previous.json \
  --drift drift-report.json \
  --policy policies/strict-production/policy.yml
```

### Fingerprint e Drift

Cada assessment v1.5 grava SHA-256 dos arquivos de source/metadata analisados. O `drift` compara esses hashes com o repositório atual e classifica:

- somente na org;
- somente no repositório;
- presente nos dois mas modificado;
- idêntico.

### Test Selection

O motor combina dependency graph, vizinhança de impacto e correlação de nomes. A saída continua exigindo revisão humana e não afirma cobertura sem evidência.

### Knowledge Pack

Gera arquivos separados para ingestão por RAG/agentes:

`organization.json`, `architecture.json`, `dependency-graph.json`, `field-lineage.json`,
`automation-map.json`, `integration-map.json`, `security-map.json`, `findings.json`,
`risk.json`, `evidence.json` e `index.json`.

### Policy Packs

Policies são declarativas em YAML. O pacote inclui `default` e `strict-production`.

---

# Labforce Dementor for Salesforce v1.0.0

**Read-only Salesforce Org Assessment & Intelligence Engine**

A v1.0 consolida as releases anteriores e adiciona hardening operacional para uso controlado em orgs reais.

## Principais capacidades

- inventário de Apps, objetos, campos, layouts, Apex, Triggers, Flows, permissões, integrações, Reports e Dashboards;
- dependency graph, field lineage, blast radius, change risk e technical debt;
- análise estática com Salesforce Code Analyzer;
- runtime/API/Event Monitoring em modo best-effort;
- profiling de dados somente com `--profile-data`, sem persistir valores brutos;
- effective access, OWD interno/externo, UI lineage e análise estrutural Apex/Flow;
- PDF/HTML/Markdown/JSON;
- `diff` entre snapshots;
- `impact` offline com JSON + HTML + PDF;
- `doctor` para validar o ambiente local;
- retry exponencial para falhas transitórias;
- rate limiting entre chamadas CLI;
- API budget e deployment guard;
- checkpoint/resume;
- validação do payload final;
- manifest SHA-256 dos artefatos;
- allow-list read-only com bloqueio de DML, deploy e Apex Anonymous.

## Pré-flight

```bash
dementor doctor
```

## Assessment

```bash
dementor run \
  --target-org MINHA_ORG \
  --wait-for-deploy 900
```

Para retomar uma execução que já possui diretório de saída/work directory compatíveis:

```bash
dementor run \
  --target-org MINHA_ORG \
  --output ./assessments/MINHA_ORG/run-001 \
  --work-dir ./assessments/MINHA_ORG/run-001/_work \
  --resume
```

Profiling de dados continua opt-in:

```bash
dementor run --target-org MINHA_ORG --profile-data
```

## Change Impact offline

```bash
dementor impact \
  --assessment assessments/ORG/RUN/assessment.json \
  --component Account.Status__c \
  --depth 3 \
  --output impact-report.json
```

O comando gera JSON, HTML e PDF e não consulta a Salesforce.

## Histórico

```bash
dementor diff \
  --from assessments/ORG/RUN_A/assessment.json \
  --to assessments/ORG/RUN_B/assessment.json \
  --output assessment-diff.json
```

## Segurança

O Dementor não contém fluxo de deploy, DML ou Apex Anonymous. Todas as chamadas `sf` passam pelo `ReadOnlyCommandGuard`. REST é permitido exclusivamente com GET e sem body/request-file. Mesmo em `CONTROLLED_READ_ONLY`, a credencial Salesforce pode exigir permissões adicionais para Metadata API; isso não concede ao Dementor uma operação de escrita.

## Observação de produção

A v1.0 é uma **production candidate** do engine. Antes de classificá-la como homologada para uma org específica, execute-a primeiro em sandbox ou snapshot conhecido e valide permissões/licenças disponíveis, Event Monitoring, volume de metadata, tempos de retrieve e orçamento de API. Org Edition e features contratadas podem alterar quais evidências estão disponíveis.

---

# Labforce Dementor for Salesforce v0.4.0

## v0.4 — Enterprise graph precision

Adds conservative structural Apex analysis, structural Flow graph, LWC/Aura/Visualforce lineage, expanded effective-access evidence, OWD/sharing map, package namespace lineage and a new offline `impact` command.

```bash
dementor impact --assessment assessments/ORG/RUN/assessment.json --component Account.Status__c --depth 3 --output impact.json
```

The impact command is offline: it reads an existing snapshot and does not call Salesforce.

---

# Labforce Dementor for Salesforce

**v0.3.0** — read-only Salesforce org intelligence and assessment engine.

Dementor inventories metadata, collects runtime evidence, builds dependency/lineage graphs, imports Salesforce Code Analyzer results, scores health/risk with evidence coverage, and generates JSON, Markdown, HTML and PDF reports.

## Safety contract

Dementor is read-only by behavior. The Salesforce CLI wrapper uses a hard allow-list and contains no deploy, DML, metadata mutation, data import/upsert/delete, or Apex Anonymous path.

`sf api request rest` is allowed only with **GET**. POST/PUT/PATCH/DELETE and body/request-file flags are explicitly blocked.

Modes:

- `CONTROLLED_READ_ONLY` — can discover/retrieve metadata; Salesforce may require metadata permissions even though Dementor never deploys.
- `STRICT_READ_ONLY` — does not retrieve metadata; supply `--source-dir` with an external snapshot.

Every report includes a Safety Manifest with commands, read errors, API budget, retrieve status and zero-write counters.

## v0.3 capabilities

Everything from v0.1/v0.2 remains available, plus:

- Report/Dashboard dependency edges.
- Apex semantic dependency map: class references, Apex REST/SOAP endpoints, `Type.forName`, callouts and Named Credential syntax.
- Flow path map: element inventory, connector targets, subflows and action calls.
- EventLogFile body download/parsing for configured event types, when license/permissions expose them.
- App-usage and API-client evidence from Event Monitoring columns when available.
- Opt-in data-quality sampling: null density and sample cardinality without persisting raw values.
- Deterministic Change Risk and Technical Debt heuristics based on dependency degree + findings.
- Historical `diff` between two `assessment.json` snapshots.
- Expanded PDF/HTML sections and charts for change risk and observed app usage.

Dementor still treats missing telemetry as an **evidence gap**, never as a healthy score.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requirements: Python 3.11+, Salesforce CLI (`sf`) authenticated to the target org. Salesforce Code Analyzer is optional but recommended.

## Run

```bash
dementor run \
  --target-org MY_ORG \
  --wait-for-deploy 900
```

### Opt-in data profiling

This causes Dementor to read a bounded sample of record values. **Raw values are not persisted**; only null/cardinality statistics are retained.

```bash
dementor run \
  --target-org MY_ORG \
  --profile-data
```

Tune in YAML:

```yaml
analysis:
  data_profile_enabled: false
  data_profile_sample_size: 200
  data_profile_max_objects: 10
  data_profile_max_fields_per_object: 25
```

## Event Monitoring

By default Dementor attempts a bounded download of these EventLogFile types when available:

```yaml
analysis:
  event_log_download_enabled: true
  event_log_max_files: 12
  event_log_types:
    - ApiTotalUsage
    - LightningPageView
    - LightningInteraction
    - URI
```

Files are stored under `evidence/event-logs/`. If Event Monitoring or a specific event type is unavailable, the assessment continues and records the gap.

## Snapshot diff

Each run already produces a timestamped snapshot. Compare two runs without touching Salesforce:

```bash
dementor diff \
  --from assessments/ORG/20260801/assessment.json \
  --to assessments/ORG/20260828/assessment.json \
  --output assessment-diff.json
```

The diff includes overall/category health delta, inventory delta and new/resolved findings.

## v4.0 final intelligence layer

The v4 core consolidates the assessment engine into a product-grade read-only intelligence layer:

- record-save transaction topology and automation collision analysis
- deep Flow structure analysis (loops, record/action operations, fault-path evidence, unreachable candidates)
- Apex call graph, fan-in/fan-out, sharing-mode and SOQL/DML-in-loop candidates
- test-to-class static mapping combined with runtime Apex coverage when available
- evidence-aware data health and ownership-skew correlation without persisting raw values
- runtime health correlation across Event Monitoring, async failures and Apex coverage
- integration health across Apex callouts and Named Credential evidence
- offline change/removal simulation with downstream blast-radius paths
- continuous intelligence between snapshots: health trend, new/resolved risks and architecture drift
- final readiness contract that explicitly separates product capability from unavailable Salesforce telemetry

Offline simulation never mutates source or Salesforce:

```bash
dementor simulate --assessment assessment.json --component Account.CNPJ__c --operation remove
```

Continuous intelligence:

```bash
dementor continuous --from old/assessment.json --to new/assessment.json
```

`PRODUCT_GRADE_CORE` means the engine capabilities are present and validated. It does **not** mean every telemetry source exists in every Salesforce org; Event Monitoring, runtime coverage, effective access evidence and sampled data profiling remain edition/permission/opt-in dependent.

## Output

```text
assessments/<org>/<timestamp>/
├── assessment.json
├── assessment.md
├── assessment.html
├── assessment.pdf
├── code-analyzer.json
├── run-manifest.json
├── charts/
├── evidence/
│   └── event-logs/
└── _work/
```

## API and operational controls

```yaml
safety:
  max_api_budget_percent_of_remaining: 5.0
  stop_if_api_remaining_percent_below: 20.0
  pause_metadata_if_deploy_active: true

metadata:
  list_metadata_batch_size: 10
```

Dementor checks API headroom and detects active deploy/validate jobs before metadata retrieve. Runtime reads remain best-effort. A complete retrieve stops on budget/deploy conflicts or partial coverage and preserves its audit. The guard is checked between retrieve batches; checkpoints estimate org-wide usage rather than enforcing an exact per-request API cap.

## Interpretation rule

No destructive recommendation should be made from a heuristic alone. `unused`, `manual`, `integration`, `change risk`, `technical debt` and similar outputs must be interpreted together with their evidence and confidence.
