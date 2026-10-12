from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

from .ai_complement import AiComplementError, DATA_SCOPES, create_preview, execute_complement
from .ai_credentials import PROVIDER_KEYS, resolve_ai_credential
from .local_ai import LOCAL_AI_PROVIDERS, detect_local_ai


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

        detected = detect_local_ai()
        if not detected:
            print("Nenhum assistente local compatível foi encontrado no PATH.")
            print("Instale e autentique Codex, Claude Code ou Gemini CLI no mesmo usuário do VS Code.")
            print("Nenhuma API foi chamada e o assessment permanece disponível.")
            return True
        print("Assistentes locais autenticáveis detectados:")
        for item in detected:
            print(f"  - {item['label']} ({item['executable']})")
        provider = _choose("Assistente", tuple(item["provider"] for item in detected))
        model = input("Modelo escolhido (Enter usa o padrão da sessão): ").strip() or "default"
        print("Escolha os dados que poderão ser enviados:")
        scope = _choose("Escopo", DATA_SCOPES)
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
        print("Revise o conteúdo antes de autorizar. O CLI usa sua conta e quota; os dados serão processados pelo provedor.")
        phrase = input(
            f"Para autorizar o envio, digite {plan['authorization_phrase']} (Enter cancela): "
        ).strip()
        if phrase != plan["authorization_phrase"]:
            print("Envio não autorizado. Nenhum dado foi enviado à IA.")
            return True

        output_dir = assessment_path.parent / "ai-complement-report"
        result = execute_complement(
            preview_path,
            authorization_phrase=phrase,
            authorized_by=authorized_by,
            output_dir=output_dir,
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
