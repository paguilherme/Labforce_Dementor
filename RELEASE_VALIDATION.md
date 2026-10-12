# Labforce Dementor v4.3.0 — validação da release

Preparado em 2026-10-12. Status: **PACKAGE_READY_FOR_REVIEW**.

## Escopo

- Retrieve amplo via org, manifesto integral e manifestos de lotes, reconciliação e hashes.
- Profiles repetidos por lote e união local dos fragmentos de permissões.
- Guard de deploy/validate e orçamento entre lotes; cobertura parcial interrompe por padrão.
- Classes Deus de produção/teste, indicadores estáticos de operações Apex e governança da margem dos limites da org.
- Fluxo guiado por Codex/Claude/Gemini CLI com autenticação própria, payload sanitizado, consentimento e complemento separado.
- Relatórios JSON, Markdown, HTML e PDF, documentação da metodologia e CI para Python 3.11/3.12.

## Evidências locais

- Suíte automatizada: 96 testes aprovados, incluindo fluxo retrieve → análise → relatórios com fixture Salesforce.
- Regressões de read-only, consentimento, hash, expiração, uso único, não mutação do diagnóstico e ausência de chamadas diretas de API no adapter local.
- Casos de cobertura parcial, deploy entre fases/lotes, snapshots antigos e resume com hash/org divergentes.
- Métricas sem contaminação por strings/comentários, métodos de teste legados, triggers e margens exatas dos limites.
- Geração de PDF real, gráfico dos limites e inspeção visual das páginas de governança e auditoria.
- Python compileall e git diff --check aprovados.
- Wheel e sdist construídos; twine check --strict aprovado.
- Instalação do wheel em ambiente isolado, aliases `dementor`/`labforce-dementor`, versão 4.3.0, módulos, defaults incorporados, template e logo verificados.

O ambiente local executou Python 3.12. Python 3.11 está no workflow de CI e seu resultado deve ser conferido no PR. Um aviso de dependência nativa HarfBuzz-Subset do WeasyPrint não impediu a geração de PDF local; a dependência é instalada no workflow de CI.

## Fronteiras de homologação

Não houve conexão a uma org Salesforce real nem execução com conta real dos CLIs de IA neste ambiente. As chamadas Salesforce e autenticação/geração dos CLIs foram simuladas nos testes. Antes de publicar, execute um assessment em org de homologação e um complemento autorizado no Mac com o CLI atualizado e autenticado.

Cobertura é limitada pelo usuário/API/pacotes. `verified_requested_members` confirma os membros solicitados e não a totalidade da org. A análise semântica cobre as famílias do parser. Classes Deus são candidatas heurísticas; contagens de operações não medem consumo transacional. Margens de limites são observações, não previsões. Orçamento global é estimado em checkpoints e pode ser ultrapassado por uma operação indivisível ou outros consumidores.

## Publicação preparada

A versão está sincronizada em pyproject, pacote, configuração e lockfile. O workflow existente publica por PyPI Trusted Publishing apenas quando uma release `v4.3.0` é publicada no GitHub. A preparação do PR não publica no PyPI e não altera a versão instalada no Mac.

Instalação de homologação a partir do branch:

```bash
uv tool install --force 'git+https://github.com/paguilherme/Labforce_Dementor.git@feat/retrieve-governance-local-ai'
dementor --version
dementor run --target-org MINHA_ORG
dementor ai-report --assessment CAMINHO/assessment.json
```

Consulte [a auditoria técnica](docs/RETRIEVE_GOVERNANCE_LOCAL_AI.md) para configuração e comportamento dos adapters.
