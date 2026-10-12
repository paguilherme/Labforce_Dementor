from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

from .ai_complement import AiComplementError, DATA_SCOPES, PROVIDERS, create_preview, execute_complement
from .ai_credentials import PROVIDER_KEYS, resolve_ai_credential


def _choose(prompt: str, options: tuple[str, ...]) -> str:
    for index, option in enumerate(options, start=1):
        print(f"  {index}. {option}")
    while True:
        answer = input(f"{prompt} (número ou nome): ").strip().lower()
        if answer in options:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1]
        print("Escolha uma das opções exibidas.")


def _required(prompt: str) -> str:
    while True:
        answer = input(prompt).strip()
        if answer:
            return answer
        print("Informe um valor ou pressione Ctrl+C para cancelar.")


def offer_ai_report(assessment_path: Path) -> bool:
    """Offer AI on an existing snapshot; never infer consent or block automation."""
    command = f"dementor ai-report --assessment {shlex.quote(str(assessment_path))}"
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("IA não executada: a sessão não é interativa.")
        print(f"Para gerar o complemento depois: {command}")
        return True

    try:
        answer = input("\nDeseja gerar um relatório complementar com IA? [s/N]: ").strip().lower()
        if answer not in {"s", "sim", "y", "yes"}:
            print("IA não executada. O assessment permanece disponível.")
            print(f"Para gerar o complemento depois: {command}")
            return True

        print("Escolha o provedor:")
        provider = _choose("Provedor", PROVIDERS)
        model = _required("Modelo exato escolhido por você: ")
        print("Escolha os dados que poderão ser enviados:")
        scope = _choose("Escopo", DATA_SCOPES)
        organization = client = project = None
        source = "environment"
        if provider != "ollama":
            print("Escolha a origem da credencial:")
            source = _choose("Credencial", ("environment", "labforce-base"))
            if source == "environment":
                print(f"A chave será lida de {PROVIDER_KEYS[provider]}; não digite a chave aqui.")
            else:
                organization = _required("Organização no cofre Labforce: ")
                client = input("Cliente no cofre (opcional): ").strip() or None
                project = input("Projeto no cofre (opcional): ").strip() or None
        authorized_by = _required("Seu nome ou e-mail para o registro de autorização: ")
        preview_path = assessment_path.parent / "ai-consent-preview.json"
        plan = create_preview(
            assessment_path,
            provider=provider,
            model=model,
            data_scopes=[scope],
            output_path=preview_path,
        )
        print("\nNenhum dado foi enviado à IA.")
        print(f"Provedor   : {plan['provider']}")
        print(f"Modelo     : {plan['model']}")
        print(f"Escopos    : {', '.join(plan['data_scopes'])}")
        print(f"Itens      : {plan['item_counts']}")
        print(f"Tokens est.: {plan['estimated_input_tokens']}")
        print(f"Expira em  : {plan['expires_at']}")
        print(f"Prévia     : {preview_path}")
        print(f"Conteúdo   : {plan['input_path']}")
        print(plan["notice"])
        print("Revise o arquivo de conteúdo antes de autorizar. O provedor pode cobrar pelo uso.")
        phrase = input(
            f"Para autorizar o envio, digite {plan['authorization_phrase']} (Enter cancela): "
        ).strip()
        if phrase != plan["authorization_phrase"]:
            print("Envio não autorizado. Nenhum dado foi enviado à IA.")
            return True

        def credential_loader() -> tuple[str | None, str]:
            credential = resolve_ai_credential(
                provider,
                source=source,
                organization=organization,
                client=client,
                project=project,
            )
            return credential.api_key, credential.reference

        output_dir = assessment_path.parent / "ai-complement-report"
        result = execute_complement(
            preview_path,
            authorization_phrase=phrase,
            authorized_by=authorized_by,
            output_dir=output_dir,
            credential_loader=credential_loader,
        )
        print("Complemento consultivo concluído; o diagnóstico determinístico foi preservado.")
        print(f"Provedor   : {result['provider']}")
        print(f"Modelo     : {result['model']}")
        print(f"Relatórios : {output_dir.resolve()}")
        return True
    except (EOFError, KeyboardInterrupt):
        print("\nEtapa de IA cancelada. O assessment permanece disponível.")
        return True
    except (AiComplementError, OSError, json.JSONDecodeError) as exc:
        print(f"ERRO na etapa de IA: {exc}", file=sys.stderr)
        print("O assessment determinístico permanece disponível.")
        return False
