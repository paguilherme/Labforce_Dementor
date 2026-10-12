# Retrieve, governança Apex e complemento por CLI — v4.3.0

## Resultado da auditoria

| Área | Situação anterior | Comportamento atual |
|---|---|---|
| Retrieve | Lista fixa de tipos; retorno não reconciliado | Descoberta via `--from-org`, manifesto integral e recuperação em lotes |
| Cobertura | Arquivos locais podiam mascarar um retrieve incompleto | Diretório novo, reconciliação de membros, inventário Tooling de Apex e hashes |
| Retomada | Presença de arquivos e checkpoint bastavam | Identidade da org e todos os hashes precisam coincidir |
| Classes Deus | Sem classificação própria para produção e teste | Métricas, sinais e limiares distintos, com evidências e revisão humana |
| Limites | Telemetria bruta sem margem de governança | Coleta final, máximo, utilizado, restante, margem e alertas configuráveis |
| IA | Fluxo guiado pedia chave/cofre de API | Fluxo guiado oferece CLIs locais e usa login da própria conta |

## Retrieve abrangente e auditável

`dementor run --target-org MINHA_ORG` descobre os metadados expostos ao usuário conectado e à versão da API, sem restringir a descoberta à lista histórica de tipos. O manifesto é dividido em lotes de até 500 membros explícitos por padrão. Profiles são incluídos em cada lote, e seus fragmentos locais de permissões são unidos por referência para preservar os grants contextuais retornados pela Metadata API. Se o número de Profiles ocupar o lote inteiro, aumente `retrieve_batch_members`. O guard de deploy/validate e o orçamento de API são conferidos antes da recuperação e entre lotes. Há limites Salesforce de tamanho de arquivos/pacotes: um bundle muito grande ainda pode exigir reduzir o lote ou investigar o componente.

Arquivos de auditoria por execução:

- `metadata-package.xml`: manifesto integral solicitado;
- `metadata-manifests/part-NNN.xml`: manifestos efetivamente recuperados por lote;
- `metadata-retrieve-audit.json`: escopo, API, membros, pacotes excluídos, mensagens, membros ausentes, lotes e SHA-256 de cada arquivo;
- `assessment.json` e `run-manifest.json`: resumo da auditoria e guardrails;
- `integrity-manifest.json`: hashes dos artefatos da execução.

O status `verified_requested_members` confirma os membros explicitamente solicitados, dentro do escopo disponível. Não comprova que toda a organização foi recuperada. Metadados não suportados pela API, permissões insuficientes, conteúdo de pacotes gerenciados e comportamentos de Profile continuam sendo fronteiras reais. Pacotes `managed` e `unlocked` ficam excluídos por padrão e podem ser incluídos explicitamente; isso não torna visível o código protegido de pacotes gerenciados.

Por padrão, mensagens/avisos, membros ausentes, wildcard sem inventário que o expanda, retorno incompleto ou snapshot vazio interrompem o assessment antes de publicar um diagnóstico baseado naquele retrieve. A auditoria continua disponível para revisão. O fallback para tipos configurados só é permitido quando `require_complete_snapshot: false`; sua cobertura é registrada como parcial.

```yaml
metadata:
  full_org: true
  require_complete_snapshot: true
  fallback_to_configured_types: true
  include_packages: []
  list_metadata_batch_size: 10
  retrieve_batch_members: 500
```

Use um diretório de trabalho vazio para cada nova coleta. `--resume` exige o checkpoint, o arquivo de auditoria, a mesma identidade de org e os mesmos arquivos/hashes. Snapshots externos via `--source-dir` são identificados como `external_snapshot_unverified`: sua origem não comprova cobertura da org. Em `STRICT_READ_ONLY`, informe um snapshot local; nenhuma recuperação via Metadata API ocorre.

Os arquivos recuperados são todos inventariados e hashados. As regras semânticas cobrem as famílias implementadas pelo parser; recuperar um tipo não significa executar regras especializadas para ele. O orçamento é uma estimativa de consumo global da org em checkpoints. Uma operação individual pode ultrapassá-lo antes da próxima medição; outras integrações também entram na variação observada. O teste de deploy é sujeito à mudança de estado entre a verificação e a chamada.

## Classes Deus de produção e de teste

A classificação exige pontuação mínima e pelo menos dois sinais acima dos limiares. O diagnóstico guarda a metodologia, os limiares, as métricas e os sinais ativados. Comentários e strings não contam como métodos, dependências ou complexidade. Objetos usados e tipos de pontos de entrada aproximam a quantidade de responsabilidades; nomes de variáveis de DML não são objetos. A complexidade é uma aproximação lexical, sem interpretar integralmente a gramática de Apex.

| Sinal | Produção | Testes |
|---|---:|---:|
| Linhas de código | 500 | 700 |
| Métodos / métodos de teste | 20 | 25 |
| Dependências de outras classes | 12 | 15 |
| Objetos/pontos de entrada | 8 | 10 |
| Complexidade aproximada | 50 | Contribui ao score; referência 60 |
| Pontuação mínima | 65/100 | 65/100 |

Achados `GOD-*` e `GODTEST-*` são candidatos para revisão, com recomendações de separação por domínio/comportamento. Eles não autorizam refatorações automáticas. Contagens de SOQL/DML/callouts por arquivo, inclusive triggers, geram `GOVCODE-*` quando ultrapassam os limiares configurados. Elas não provam o consumo de uma transação e não substituem telemetria ou testes com `Limits`.

## Governança dos limites da org

`sf org list limits` fornece a margem observada da org; não fornece todos os limites de uma transação Apex. A análise final utiliza a última coleta, registra timestamp e calcula utilizado, restante e percentuais. Valores inválidos ou máximos zero ficam indisponíveis, em vez de saudáveis. A variação durante o assessment inclui todos os consumidores da org e não é uma previsão de esgotamento.

```yaml
analysis:
  org_limits:
    warning_remaining_percent: 20
    critical_remaining_percent: 10
  governor_risk:
    soql_statements: 80
    dml_statements: 120
    callouts: 80
```

Margem de até 20% gera alerta; até 10% gera crítico. Os achados `ORGLIMIT-*`, o gráfico de menores margens e as tabelas com todos os limites ficam em JSON/Markdown/HTML/PDF. Evidência de limites também contribui à cobertura da categoria governança, mesmo sem objetos recuperados.

## Complemento de IA sem integração direta de API

O fluxo guiado detecta executáveis no `PATH`, sem afirmar que estão autenticados. Escolha entre `codex-local`, `claude-local` e `gemini-local`. Codex exige login com ChatGPT; Claude exige OAuth; Gemini usa OAuth pessoal. Instale e autentique o CLI no mesmo usuário que executa o Dementor. A autenticação não é copiada do ChatGPT no navegador nem de uma extensão remota do VS Code.

```bash
codex login
# ou
claude auth login
# para Gemini, abra gemini e conclua o login com Google

dementor ai-report --assessment assessments/MINHA_ORG/EXECUCAO/assessment.json
```

O assistente pergunta CLI, modelo (`default` usa o padrão do CLI), escopo e identificação de quem autoriza. Gera uma prévia sanitizada, com hash, expiração e frase de uso único. Prévias de versões anteriores do prompt devem ser recriadas após a atualização. Os dados vão por stdin para uma nova execução em diretório temporário. O contexto de uma conversa aberta no VS Code não é reutilizado. Codex ignora configuração do usuário e desativa shell, apps, MCP, hooks e subagentes; Claude executa sem ferramentas/MCP e com hooks/persistência desativados; Gemini restringe ferramentas/MCP, extensões e hooks. Os adapters exigem versões atuais que suportem esses flags; um CLI antigo falha sem remover controles nem recorrer a API.

O Dementor não pede chave de API, não acessa o cofre da Base Salesforce e não faz chamada HTTP direta ao provedor nesse fluxo. O próprio CLI usa a conta, quota e processamento remoto do provedor. Não é execução offline do modelo nem promessa de gratuidade ou uso ilimitado. Políticas administradas dos CLIs continuam sendo uma fronteira de ambiente e precisam ser validadas onde houver configuração corporativa.

Comandos manuais equivalentes:

```bash
dementor ai-preview --assessment assessment.json --provider codex-local --model default --scope findings_with_evidence --output ai-consent-preview.json
dementor ai-complement --preview ai-consent-preview.json --authorize AUTORIZAR-XXXXXXXX --authorized-by usuario@example.com --output-dir ai-complement-report
```

Os adapters antigos de API/Ollama permanecem apenas nos comandos manuais explícitos por compatibilidade. Eles não aparecem no fluxo guiado nem são fallback dos CLIs locais. A saída consultiva mantém referências somente aos IDs existentes, registra consentimento e `direct_api_used: false` no modo local e não modifica scores ou achados determinísticos. Timeout e falhas não ecoam o conteúdo do assessment. O limite de tokens na geração por CLI é uma orientação no prompt, não um teto de cobrança imposto pelo Dementor.

## Referências técnicas consultadas

- [Salesforce: generate manifest](https://developer.salesforce.com/docs/platform/salesforce-cli-reference/guide/cli_reference_project_generate_manifest.html)
- [Salesforce: retrieve start](https://developer.salesforce.com/docs/platform/salesforce-cli-reference/guide/cli_reference_project_retrieve_start.html)
- [OpenAI: CLI reference](https://developers.openai.com/codex/cli/reference)
- [OpenAI: configuration reference](https://developers.openai.com/codex/config-reference)
- [Claude Code: CLI reference](https://code.claude.com/docs/en/cli-reference)
- [Gemini CLI: configuration](https://geminicli.com/docs/reference/configuration/)
