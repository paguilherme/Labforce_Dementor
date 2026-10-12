# Changelog

## 4.3.0 — preparado em 2026-10-12

- Descobre metadados via org e recupera em lotes, com manifesto integral, membros retornados/ausentes, pacotes excluídos e hashes SHA-256.
- Interrompe diante de cobertura parcial, evita snapshots antigos e valida identidade/hashes ao retomar.
- Revalida deploy/validate e orçamento entre lotes de retrieve.
- Classifica candidatos a Classes Deus de produção e de teste com métricas e limiares configuráveis.
- Mostra riscos estáticos de operações Apex sem confundi-los com consumo por transação.
- Analisa a última coleta de limites da org e publica margem, alertas, tabelas e gráfico.
- Oferece complemento por CLI local Codex/Claude/Gemini autenticado, sem chave nem chamada direta de API no fluxo guiado.
- Mantém consentimento explícito, uso único atômico, sanitização e complemento consultivo separado.
- Atualiza metodologia, relatórios e testes do fluxo completo.

## 4.2.1 — 2026-10-12

- Oferece o complemento de IA ao final do `run` em terminais interativos, inclusive quando o PDF não é gerado.
- Adiciona `ai-report --assessment` para iniciar o fluxo guiado usando um JSON existente, sem repetir a coleta Salesforce.
- Exige escolha de provedor, modelo, dados e credencial, prévia sanitizada e frase de autorização exata antes de chamar IA.
- Preserva o assessment em cancelamentos e erros e adiciona `--no-ai-prompt` para pular a oferta; sessões não interativas não chamam IA.
- Mostra o andamento do assessment em tempo real no terminal, com fase atual, atividade e duração.
- Mantém saída linear e estável em logs e ambientes de CI.
- Adiciona `--no-progress` para execuções silenciosas ou integrações que não desejem o indicador.
- Expõe progresso das consultas operacionais, recuperação de metadados, análise, relatórios e integridade.
- Padroniza os relatórios JSON, Markdown, HTML, PDF e de impacto para pt-BR.
- Adiciona rótulos em português para categoria, severidade, esforço e inventário sem quebrar os enums técnicos existentes.
- Traduz títulos, descrições e recomendações dos achados determinísticos.

## 4.2.0 — 2026-10-12

- Publica o pacote Python com o nome de distribuição `labforce-dementor`.
- Adiciona o executável curto `dementor` e preserva `labforce-dementor` como alias.
- Adiciona validação de wheel e instalação isolada dos dois executáveis.
- Prepara publicação no PyPI por Trusted Publishing a partir de uma release do GitHub.

## 4.1.0 — 2026-10-12

- Adiciona complemento de IA opcional para OpenAI, Anthropic, Gemini e Ollama local.
- Exige prévia sanitizada, hash do assessment, frase de autorização, usuário identificado, validade e uso único.
- Mantém o diagnóstico determinístico imutável e grava a saída de IA como relatório consultivo separado.
- Integra as credenciais ao cofre local da Labforce Base por organização, cliente e projeto.
- Padroniza logo da UI Base, empresa, sistema, data e hora em JSON, Markdown, HTML e PDF.

## 4.0.0 — 2026-08-30

Final intelligence-layer release: transaction topology, deep Flow/Apex/test intelligence, Data Health, Runtime Health, Integration Health, offline Architecture Simulator, Continuous Intelligence, Knowledge Pack v3, expanded capability matrix, final-readiness contract and report integration.
