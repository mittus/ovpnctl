"""Общие утилиты: вывод, запуск процессов, работа с файлами."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile

IS_TTY = sys.stdout.isatty()

# Палитра в духе 3x-ui: текст и рамки белые, номера и активные значения —
# тёмно-зелёные, проблемы — красные.
C_RESET = "\033[0m" if IS_TTY else ""
C_BOLD = "\033[1m" if IS_TTY else ""
C_WHITE = "\033[37m" if IS_TTY else ""
C_GREEN = "\033[32m" if IS_TTY else ""
C_RED = "\033[31m" if IS_TTY else ""
C_YELLOW = "\033[33m" if IS_TTY else ""
C_DIM = "\033[2m" if IS_TTY else ""

_ANSI = re.compile(r"\033\[[0-9;]*m")


class OvpnError(Exception):
    """Ошибка, которую показываем пользователю без traceback."""


def info(msg: str) -> None:
    print("%s%s%s" % (C_WHITE, msg, C_RESET))


def ok(msg: str) -> None:
    print("%s%s%s" % (C_GREEN, msg, C_RESET))


def warn(msg: str) -> None:
    print("%s%s%s" % (C_YELLOW, msg, C_RESET), file=sys.stderr)


def err(msg: str) -> None:
    print("%s%s%s" % (C_RED, msg, C_RESET), file=sys.stderr)


def bold(msg: str) -> str:
    return "%s%s%s" % (C_BOLD, msg, C_RESET)


def dim(msg: str) -> str:
    return "%s%s%s" % (C_DIM, msg, C_RESET)


def hl(value) -> str:
    """Активное значение (имя, число, адрес) — тёмно-зелёным."""
    return "%s%s%s" % (C_GREEN, value, C_RESET)


def red(value) -> str:
    return "%s%s%s" % (C_RED, value, C_RESET)


def visible_len(text: str) -> int:
    return len(_ANSI.sub("", text))


def pad(text: str, width: int) -> str:
    return text + " " * max(width - visible_len(text), 0)


def run(cmd, check=True, capture=True, input_data=None, env=None, cwd=None):
    """Запуск команды. Возвращает CompletedProcess (stdout/stderr — строки)."""
    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            universal_newlines=True,
            env=env,
            cwd=cwd,
        )
    except OSError as exc:
        if check:
            raise OvpnError("failed to run '%s': %s" % (" ".join(cmd), exc))
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise OvpnError(
            "command exited with code %d: %s\n%s"
            % (proc.returncode, " ".join(cmd), detail)
        )
    return proc


def run_ok(cmd) -> bool:
    """True, если команда отработала успешно (вывод игнорируется)."""
    return run(cmd, check=False).returncode == 0


def which(binary: str):
    return shutil.which(binary)


def require_root() -> None:
    if os.geteuid() != 0:
        raise OvpnError("root privileges required (run with sudo).")


def write_file(path: str, content: str, mode: int = 0o644, owner=None) -> None:
    """Атомарная запись файла с нужными правами."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        os.chmod(tmp, mode)
        if owner:
            shutil.chown(tmp, *owner)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_file(path: str) -> str:
    with open(path, "r") as fh:
        return fh.read()


def ensure_dir(path: str, mode: int = 0o755) -> str:
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)
    return path


def ask(prompt: str, default=None, validator=None):
    """Интерактивный ввод с дефолтом и валидацией."""
    suffix = " [%s]" % default if default not in (None, "") else ""
    while True:
        try:
            raw = input("%s%s: " % (prompt, suffix)).strip()
        except EOFError:
            if default in (None, ""):
                raise OvpnError(
                    "no interactive input for the question '%s' — use flags "
                    "or --non-interactive." % prompt)
            raw = ""
        if not raw and default is not None:
            raw = str(default)
        if not raw:
            continue
        if validator:
            try:
                return validator(raw)
            except (ValueError, OvpnError) as exc:
                err("  %s" % exc)
                continue
        return raw


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            raw = input("%s [%s]: " % (prompt, hint)).strip().lower()
        except EOFError:
            return default
        if not raw:
            return default
        if raw in ("y", "yes", "д", "да", "1"):
            return True
        if raw in ("n", "no", "н", "нет", "0"):
            return False


def clear_screen() -> None:
    """Очистка экрана перед отрисовкой меню (в не-TTY ничего не делает)."""
    if IS_TTY:
        sys.stdout.write("\033[H\033[2J")
        sys.stdout.flush()


def pause(message: str = "Press Enter to return to the menu") -> None:
    try:
        input("\n%s%s%s" % (C_DIM, message, C_RESET))
    except (EOFError, KeyboardInterrupt):
        print()


def ask_optional(prompt: str, current=None):
    """Необязательный ввод: пустая строка = оставить как есть (вернёт None)."""
    suffix = " (now %s, Enter to keep)" % current if current not in (None, "") else " (Enter to skip)"
    try:
        raw = input("%s%s: " % (prompt, suffix)).strip()
    except EOFError:
        return None
    return raw or None


def human_bytes(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024:
            return "%.0f %s" % (num, unit) if unit == "B" else "%.1f %s" % (num, unit)
        num /= 1024.0
    return "%.1f PiB" % num


def table(rows, headers) -> str:
    """Простая текстовая таблица без внешних зависимостей.

    Ячейки могут быть раскрашены (hl/red) — ширина считается без ANSI-кодов.
    Заголовки и разделитель белые.
    """
    all_rows = [list(headers)] + [[str(c) for c in r] for r in rows]
    widths = [max(visible_len(r[i]) for r in all_rows) for i in range(len(headers))]
    line = "  ".join("-" * w for w in widths)
    head = "  ".join(pad(h, widths[i]) for i, h in enumerate(all_rows[0])).rstrip()
    out = ["%s%s%s" % (C_WHITE + C_BOLD, head, C_RESET), "%s%s%s" % (C_WHITE, line, C_RESET)]
    for row in all_rows[1:]:
        out.append("  ".join(pad(row[i], widths[i]) for i in range(len(widths))).rstrip())
    return "\n".join(out)
