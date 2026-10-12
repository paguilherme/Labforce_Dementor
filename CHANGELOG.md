# Changelog

## 4.2.1 — 2026-10-12

- Oferece o complemento de IA ao final do `run` em terminais interativos, inclusive quando o PDF não é gerado.
- Adiciona `ai-report --assessment` para iniciar o fluxo guiado usando um JSON existente, sem repetir a coleta Salesforce.
- Exige escolha de provedor, modelo, dados e credencial, prévia sanitizada e frase de autorização exata antes de chamar IA.
- Preserva o assessment em cancelamentos e erros e adiciona `--no-ai-prompt` para pular a oferta; sessões não interativas não chamam IA.

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
