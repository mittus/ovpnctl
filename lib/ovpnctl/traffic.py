"""Накопительный трафик клиентов.

Завершённые сессии пишет в журнал сам openvpn (client-disconnect, см.
server.TRAFFIC_SCRIPT), здесь журнал сворачивается в traffic.json. К сумме
прошлых сессий добавляются байты текущей — из status-файла.

Байты считаются со стороны сервера: rx — принято от клиента (его исходящий
трафик), tx — отправлено клиенту.
"""
from __future__ import annotations

import json
import os

from . import config as cfgmod
from . import server as srv
from .util import write_file

STORE = os.path.join(cfgmod.ETC_DIR, "traffic.json")


def _load() -> dict:
    try:
        with open(STORE) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    write_file(STORE, json.dumps(data, indent=2, sort_keys=True) + "\n", 0o600)


def _number(value: str) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def collect() -> dict:
    """Переносит журнал сессий в traffic.json и возвращает накопленное.

    Журнал сначала переименовывается: openvpn открывает файл заново на каждую
    запись, так что новые сессии уже пойдут в свежий sessions.log.
    """
    data = _load()
    work = srv.TRAFFIC_LOG + ".work"
    try:
        if os.path.exists(srv.TRAFFIC_LOG):
            if os.path.exists(work):
                # прошлый сбор оборвался — дописываем, а не затираем
                with open(srv.TRAFFIC_LOG) as src, open(work, "a") as dst:
                    dst.write(src.read())
                os.unlink(srv.TRAFFIC_LOG)
            else:
                os.rename(srv.TRAFFIC_LOG, work)
        if not os.path.exists(work):
            return data
        with open(work) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return data                     # не root — показываем то, что уже собрано

    for line in lines:
        parts = line.strip().split(",")
        if len(parts) != 3 or not parts[0]:
            continue
        entry = data.setdefault(parts[0], {"rx": 0, "tx": 0, "sessions": 0})
        entry["rx"] = entry.get("rx", 0) + _number(parts[1])
        entry["tx"] = entry.get("tx", 0) + _number(parts[2])
        entry["sessions"] = entry.get("sessions", 0) + 1
    _save(data)
    os.unlink(work)
    return data


def totals(online=None) -> dict:
    """{имя: {"rx", "tx", "total"}} — прошлые сессии плюс текущая."""
    if online is None:
        online = srv.online_clients()
    result = {}
    for name, entry in collect().items():
        result[name] = {"rx": entry.get("rx", 0), "tx": entry.get("tx", 0)}
    for client in online:
        entry = result.setdefault(client["name"], {"rx": 0, "tx": 0})
        entry["rx"] += client.get("bytes_received", 0)
        entry["tx"] += client.get("bytes_sent", 0)
    for entry in result.values():
        entry["total"] = entry["rx"] + entry["tx"]
    return result


def forget(name: str) -> None:
    """Сбрасывает статистику клиента (при полном удалении имя может занять новый)."""
    data = collect()
    if data.pop(name, None) is not None:
        _save(data)
