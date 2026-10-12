# Changelog

## 4.2.1 — 2026-10-12

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
