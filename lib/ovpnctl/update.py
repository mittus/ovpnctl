"""Обновление ovpnctl из GitHub без повторной установки.

Скачивает архив ветки, подменяет код в /opt/ovpnctl и запускает уже новый код
(`ovpnctl update --finish`), чтобы тот перегенерировал конфиги по своим шаблонам.
Пакеты, PKI, клиенты и настройки не трогаются.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from . import __version__
from . import config as cfgmod
from .util import OvpnError, info, read_file, warn

DEFAULT_REPO = "https://github.com/mittus/ovpnctl"
DEFAULT_BRANCHES = ("master", "main")
SRC_DIR = cfgmod.ROOT + "/opt/ovpnctl"
SOURCE_FILE = os.path.join(SRC_DIR, "SOURCE")
EXTRA_FILES = ("VERSION", "README.md", "uninstall.sh", "install.sh")


# --------------------------------------------------------------------------- #
# Откуда и что
# --------------------------------------------------------------------------- #
def source(repo: str = None, branch: str = None) -> dict:
    """Источник обновлений: аргументы → переменные окружения → SOURCE → умолчание.

    SOURCE пишет install.sh, когда ставит из git, — так обновление приходит
    оттуда же, откуда была установка (форк, другая ветка).
    """
    saved = {}
    if os.path.exists(SOURCE_FILE):
        for line in read_file(SOURCE_FILE).splitlines():
            key, sep, value = line.partition("=")
            if sep and value.strip():
                saved[key.strip()] = value.strip()
    return {
        "repo": (repo or os.environ.get("OVPN_REPO_URL") or saved.get("repo")
                 or DEFAULT_REPO).rstrip("/"),
        "branch": branch or os.environ.get("OVPN_REPO_BRANCH") or saved.get("branch") or "",
    }


def fingerprint(lib_dir: str) -> str:
    """Отпечаток кода — тот же, что показывает install.sh (md5 всех *.py по порядку путей)."""
    if not os.path.isdir(lib_dir):
        return "none"
    paths = []
    for root, _dirs, files in os.walk(lib_dir):
        paths += [os.path.join(root, f) for f in files if f.endswith(".py")]
    digest = hashlib.md5()
    for path in sorted(paths):
        with open(path, "rb") as fh:
            digest.update(fh.read())
    return digest.hexdigest()[:8]


def payload_version(payload: str) -> str:
    path = os.path.join(payload, "VERSION")
    if os.path.exists(path):
        return read_file(path).strip() or "?"
    return "?"


# --------------------------------------------------------------------------- #
# Загрузка
# --------------------------------------------------------------------------- #
def _download(url: str, target: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "ovpnctl/%s" % __version__})
    with urllib.request.urlopen(request, timeout=60) as resp, open(target, "wb") as fh:
        shutil.copyfileobj(resp, fh)


def _safe_extract(archive: str, dest: str) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        members = []
        for member in tar.getmembers():
            name = member.name
            if name.startswith("/") or ".." in name.split("/"):
                raise OvpnError("suspicious path in archive: %s" % name)
            if member.isfile() or member.isdir():
                members.append(member)
        if hasattr(tarfile, "data_filter"):
            tar.extractall(dest, members=members, filter="data")
        else:
            tar.extractall(dest, members=members)


def _find_payload(tree: str) -> str:
    for root, dirs, _files in os.walk(tree):
        if os.path.basename(root) == "lib" and "ovpnctl" in dirs:
            return os.path.dirname(root)
    raise OvpnError("lib/ovpnctl directory not found in archive.")


def fetch(src: dict, workdir: str, local: str = None) -> dict:
    """Кладёт новую версию в workdir. Возвращает {payload, origin}."""
    archive = os.path.join(workdir, "src.tgz")
    if local:
        if os.path.isdir(local):
            return {"payload": _find_payload(local), "origin": os.path.abspath(local)}
        if not os.path.exists(local):
            raise OvpnError("no such file or directory: %s" % local)
        shutil.copyfile(local, archive)
        origin = os.path.abspath(local)
    else:
        branches = [src["branch"]] if src["branch"] else list(DEFAULT_BRANCHES)
        origin, errors = "", []
        for branch in branches:
            url = "%s/archive/refs/heads/%s.tar.gz" % (src["repo"], branch)
            try:
                _download(url, archive)
                origin, src["branch"] = url, branch
                break
            except (OSError, ValueError) as exc:
                errors.append("%s: %s" % (branch, exc))
        if not origin:
            raise OvpnError("failed to download %s (%s)." % (src["repo"], "; ".join(errors)))
    tree = os.path.join(workdir, "tree")
    os.makedirs(tree)
    try:
        _safe_extract(archive, tree)
    except (tarfile.TarError, OSError) as exc:
        raise OvpnError("corrupted source archive: %s" % exc)
    return {"payload": _find_payload(tree), "origin": origin}


# --------------------------------------------------------------------------- #
# Установка новой версии
# --------------------------------------------------------------------------- #
def _new_code(*args, env_lib: str = None):
    """Запуск ovpnctl из свежего кода (текущий процесс держит в памяти старый)."""
    env = dict(os.environ, PYTHONPATH=env_lib or os.path.join(SRC_DIR, "lib"))
    return subprocess.run([sys.executable, "-m", "ovpnctl"] + list(args), env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)


def install_payload(payload: str) -> None:
    """Подменяет lib целиком; новый код сначала пробно запускается — неработающий не ставится."""
    lib, staged, old = (os.path.join(SRC_DIR, "lib"), os.path.join(SRC_DIR, "lib.new"),
                        os.path.join(SRC_DIR, "lib.old"))
    for path in (staged, old):
        shutil.rmtree(path, ignore_errors=True)
    shutil.copytree(os.path.join(payload, "lib"), staged,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    probe = _new_code("--version", env_lib=staged)
    if probe.returncode != 0:
        shutil.rmtree(staged, ignore_errors=True)
        raise OvpnError("new version fails to run, update aborted:\n%s"
                        % probe.stdout.strip())

    if os.path.isdir(lib):
        os.rename(lib, old)
    os.rename(staged, lib)
    shutil.rmtree(old, ignore_errors=True)

    for name in EXTRA_FILES:
        src = os.path.join(payload, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(SRC_DIR, name))
    if os.path.isdir(os.path.join(payload, "tests")):
        shutil.rmtree(os.path.join(SRC_DIR, "tests"), ignore_errors=True)
        shutil.copytree(os.path.join(payload, "tests"), os.path.join(SRC_DIR, "tests"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for root, dirs, files in os.walk(SRC_DIR):
        for name in dirs + files:
            path = os.path.join(root, name)
            if not os.path.islink(path):
                os.chmod(path, stat.S_IMODE(os.stat(path).st_mode) & ~0o022)


def save_source(src: dict) -> None:
    with open(SOURCE_FILE, "w") as fh:
        fh.write("repo=%s\nbranch=%s\n" % (src["repo"], src["branch"]))


def run(repo: str = None, branch: str = None, local: str = None,
        check_only: bool = False, force: bool = False) -> dict:
    """Главный сценарий. Возвращает сводку для вывода."""
    src = source(repo, branch)
    current = {"version": __version__, "build": fingerprint(os.path.join(SRC_DIR, "lib"))}
    workdir = tempfile.mkdtemp(prefix="ovpnctl-update-")
    try:
        info("Fetching %s…" % (local or "%s (%s)" % (src["repo"], src["branch"] or "master/main")))
        got = fetch(src, workdir, local)
        latest = {"version": payload_version(got["payload"]),
                  "build": fingerprint(os.path.join(got["payload"], "lib"))}
        result = {"current": current, "latest": latest, "origin": got["origin"],
                  "updated": False, "changed": []}
        if check_only or (latest["build"] == current["build"] and not force):
            return result

        install_payload(got["payload"])
        if not local:
            save_source(src)
        result["updated"] = True
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # конфиги перегенерирует уже новая версия — по своим шаблонам
    if cfgmod.config_exists():
        done = _new_code("update", "--finish")
        if done.returncode != 0:
            warn("Code updated, but configuration was not applied:\n%s" % done.stdout.strip())
            warn("Retry: ovpnctl update --finish")
        else:
            result["changed"] = [line[2:] for line in done.stdout.splitlines()
                                 if line.startswith("* ")]
    return result


def finish() -> list:
    """Вызывается новым кодом после подмены: юниты, конфиги, версия в config.json."""
    from . import provision
    from . import server as srv
    from .system import systemctl

    cfg = cfgmod.load()
    provision.write_units()
    systemctl("enable", "--now", cfgmod.TRAFFIC_TIMER, check=False)
    changed = srv.refresh_generated(cfg)
    if cfg.get("version") != __version__:
        cfg["version"] = __version__
        cfgmod.save(cfg)
    return changed
