from __future__ import annotations

import os
import shutil
import sys
import threading
import time
from typing import TextIO


STAGES: tuple[tuple[str, str], ...] = (
    ("preflight", "Validando organização e limites de API"),
    ("runtime_collection", "Coletando sinais operacionais"),
    ("deployment_guard", "Verificando deploys ativos"),
    ("metadata_retrieve", "Descobrindo e recuperando metadados"),
    ("static_analysis", "Analisando componentes e dependências"),
    ("report_generation", "Gerando relatórios e gráficos"),
    ("integrity", "Validando integridade dos artefatos"),
)


def _duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, remainder = divmod(seconds, 60)
    return f"{minutes}m {remainder:02d}s"


class AssessmentProgress:
    """Thread-safe terminal progress for long-running assessment stages."""

    _spinner = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(
        self,
        *,
        enabled: bool = True,
        stream: TextIO | None = None,
        interactive: bool | None = None,
        refresh_interval: float = 0.12,
    ) -> None:
        self.enabled = enabled
        self.stream = stream or sys.stdout
        detected_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self.interactive = detected_tty if interactive is None else interactive
        self.refresh_interval = refresh_interval
        self._stage_labels = dict(STAGES)
        self._stage_numbers = {name: index for index, (name, _) in enumerate(STAGES, start=1)}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stage: str | None = None
        self._detail: str | None = None
        self._stage_started = 0.0
        self._spinner_index = 0
        self._line_visible = False

    def update(self, stage: str, status: str, detail: str | None = None) -> None:
        if not self.enabled:
            return
        with self._lock:
            if status == "start":
                self._stage = stage
                self._detail = detail
                self._stage_started = time.monotonic()
                self._spinner_index = 0
                if self.interactive:
                    self._ensure_thread()
                    self._render_current()
                else:
                    self._write_line(self._format_line("→", stage, detail))
                return

            if status == "update":
                if self._stage == stage:
                    self._detail = detail
                    if self.interactive:
                        self._render_current()
                return

            if status in {"done", "skipped"}:
                elapsed = time.monotonic() - self._stage_started if self._stage == stage else 0.0
                symbol = "✓" if status == "done" else "↷"
                suffix = detail or ("Ignorado com segurança" if status == "skipped" else None)
                if self.interactive:
                    self._clear_current()
                self._write_line(self._format_line(symbol, stage, suffix, elapsed=elapsed))
                if self._stage == stage:
                    self._stage = None
                    self._detail = None
                return

    def fail(self, message: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            stage = self._stage or "preflight"
            elapsed = time.monotonic() - self._stage_started if self._stage else 0.0
            if self.interactive:
                self._clear_current()
            self._write_line(self._format_line("✗", stage, message, elapsed=elapsed))
            self._stage = None
            self._detail = None

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.25, self.refresh_interval * 3))
        with self._lock:
            if self.interactive:
                self._clear_current()

    def _ensure_thread(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._animate, name="dementor-progress", daemon=True)
        self._thread.start()

    def _animate(self) -> None:
        while not self._stop.wait(self.refresh_interval):
            with self._lock:
                if self._stage is not None:
                    self._spinner_index = (self._spinner_index + 1) % len(self._spinner)
                    self._render_current()

    def _format_line(
        self,
        symbol: str,
        stage: str,
        detail: str | None = None,
        *,
        elapsed: float | None = None,
    ) -> str:
        number = self._stage_numbers.get(stage, 0)
        label = self._stage_labels.get(stage, stage.replace("_", " ").title())
        line = f"{symbol} [{number}/{len(STAGES)}] {label}"
        if detail:
            line += f" · {detail}"
        if elapsed is not None:
            line += f" · {_duration(elapsed)}"
        return line

    def _render_current(self) -> None:
        if self._stage is None:
            return
        elapsed = time.monotonic() - self._stage_started
        symbol = self._spinner[self._spinner_index]
        line = self._format_line(symbol, self._stage, self._detail, elapsed=elapsed)
        width = max(40, shutil.get_terminal_size(fallback=(100, 24)).columns)
        if len(line) >= width:
            line = line[: max(1, width - 2)] + "…"
        self.stream.write("\r\033[2K" + line)
        self.stream.flush()
        self._line_visible = True

    def _clear_current(self) -> None:
        if self._line_visible:
            self.stream.write("\r\033[2K")
            self.stream.flush()
            self._line_visible = False

    def _write_line(self, line: str) -> None:
        # NO_COLOR affects color only; control sequences remain necessary for a live line.
        if self.interactive and os.environ.get("NO_COLOR") is None:
            if line.startswith("✓"):
                line = f"\033[32m{line}\033[0m"
            elif line.startswith("✗"):
                line = f"\033[31m{line}\033[0m"
            elif line.startswith("↷"):
                line = f"\033[33m{line}\033[0m"
        self.stream.write(line + "\n")
        self.stream.flush()

