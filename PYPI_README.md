# Labforce Dementor

Assessment read-only para organizações Salesforce, com diagnóstico determinístico de arquitetura, automações, Apex, segurança, permissões, integrações, governança e riscos.

O diagnóstico principal funciona sem IA. Quando habilitado, o complemento de IA exige que o usuário escolha o provedor, o modelo e os dados autorizados antes de qualquer chamada externa.

## Instalação

O método recomendado mantém o executável isolado do Python do sistema:

```bash
uv tool install labforce-dementor
dementor --version
dementor doctor
```

Também é possível usar:

```bash
pipx install labforce-dementor
```

Com pip, use um ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install labforce-dementor
```

O nome de distribuição é `labforce-dementor`. O pacote chamado apenas `dementor` no PyPI pertence a outro projeto.

## Pré-requisitos

- Python 3.11 ou superior;
- Salesforce CLI (`sf`);
- uma organização autorizada na Salesforce CLI.

```bash
sf org login web --alias MINHA_ORG
sf org display --target-org MINHA_ORG
```

## Primeiro assessment

```bash
dementor run --target-org MINHA_ORG
```

Por padrão, os resultados são gravados em `./assessments/<org>/<data-hora>` e incluem JSON, Markdown, HTML, PDF e manifestos de execução e integridade.

## Contrato de segurança

- allowlist de comandos read-only;
- REST somente com GET;
- bloqueio de deploy, DML e Apex Anonymous;
- profiling de dados somente com `--profile-data`;
- valores brutos do profiling não são persistidos;
- API budget e deployment guard;
- evidências e manifestos locais.

## IA opcional com autorização explícita

Primeiro, gere a prévia sanitizada. Essa etapa não chama o provedor:

```bash
dementor ai-preview \
  --assessment assessment.json \
  --provider openai \
  --model MODELO_EXATO \
  --scope findings_with_evidence \
  --output ai-consent-preview.json
```

Depois de revisar o payload e a frase de autorização, execute o complemento:

```bash
dementor ai-complement \
  --preview ai-consent-preview.json \
  --authorize AUTORIZAR-XXXXXXXX \
  --authorized-by usuario@example.com \
  --credential-source environment \
  --output-dir ai-complement-report
```

O consentimento expira, é de uso único e fica vinculado ao diagnóstico, provedor, modelo, escopos, prompt e payload. O relatório consultivo da IA não altera o score, as severidades ou os achados determinísticos.

## Documentação

- [Labforce Dementor](https://labforce.com.br/dementor/)
- [Documentação de instalação e uso](https://labforce.com.br/dementor/documentacao/)

## Suporte

Entre em contato pelo endereço `contato@labforce.com.br`.

## Licença

O Labforce Dementor é gratuito e proprietário. O uso em assessments próprios ou em serviços de consultoria autorizados é permitido. Redistribuição, revenda, rebranding e oferta hospedada exigem autorização escrita da Labforce. Consulte o arquivo `LICENSE` incluído na distribuição.
