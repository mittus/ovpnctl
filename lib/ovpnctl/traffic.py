"""Накопительный трафик клиентов с разбивкой по дням.

Два источника:
  * журнал завершённых сессий — его пишет сам openvpn (client-disconnect,
    см. server.TRAFFIC_SCRIPT): имя, байты сессии, время подключения и длительность;
  * status-файл — байты текущих сессий.

collect() раз в несколько минут (таймер ovpnctl-traffic.timer, а также при каждом
просмотре) раскладывает прирост по дням: для идущей сессии запоминается, сколько
байт уже учтено, и в сегодняшний день ложится только разница. Когда сессия
завершается, её остаток относится ко дню отключения.

Байты считаются со стороны сервера: rx — принято от клиента, tx — отправлено ему.
"""
from __future__ import annotations

import datetime
import json
import os
import time

from . import config as cfgmod
from . import server as srv
from .util import write_file

STORE = os.path.join(cfgmod.ETC_DIR, "traffic.json")
KEEP_DAYS = 400             # дневные корзины старше не нужны ни одному периоду
CLOSED_TTL = 86400          # сколько помнить завершённые сессии (status-файл может отставать)
STALE_TTL = 7 * 86400       # сессия пропала без записи в журнале (сбой openvpn)

PERIODS = [
    ("day", "Today", 1),
    ("week", "Week (7 days)", 7),
    ("month", "Month (30 days)", 30),
    ("year", "Year (365 days)", 365),
    ("all", "All time", None),
]


def _load() -> dict:
    try:
        with open(STORE) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    write_file(STORE, json.dumps(data, indent=1, sort_keys=True) + "\n", 0o600)


def _number(value) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _day(stamp: float) -> str:
    return datetime.date.fromtimestamp(stamp).isoformat()


def _entry(data: dict, name: str) -> dict:
    entry = data.setdefault(name, {})
    for key, default in (("rx", 0), ("tx", 0), ("days", {}), ("live", {}), ("closed", {})):
        entry.setdefault(key, default)
    return entry


def _add(entry: dict, day: str, rx: int, tx: int) -> None:
    if rx <= 0 and tx <= 0:
        return
    entry["rx"] += rx
    entry["tx"] += tx
    bucket = entry["days"].setdefault(day, [0, 0])
    bucket[0] += rx
    bucket[1] += tx


def _read_log() -> list:
    """Забирает журнал сессий. Сначала переименовываем: openvpn открывает файл
    заново на каждую запись, так что новые сессии пойдут уже в свежий журнал."""
    work = srv.TRAFFIC_LOG + ".work"
    if os.path.exists(srv.TRAFFIC_LOG):
        if os.path.exists(work):
            # прошлый сбор оборвался — дописываем, а не затираем
            with open(srv.TRAFFIC_LOG) as src, open(work, "a") as dst:
                dst.write(src.read())
            os.unlink(srv.TRAFFIC_LOG)
        else:
            os.rename(srv.TRAFFIC_LOG, work)
    if not os.path.exists(work):
        return []
    with open(work) as fh:
        return fh.read().splitlines()


def collect(online=None, now: float = None) -> dict:
    """Раскладывает новый трафик по дням и возвращает всю статистику."""
    now = time.time() if now is None else now
    data = _load()
    try:
        lines = _read_log()
    except OSError:
        return data                     # не root — показываем то, что уже собрано

    # завершённые сессии: имя,rx,tx[,время подключения,длительность]
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) not in (3, 5) or not parts[0]:
            continue
        entry = _entry(data, parts[0])
        rx, tx = _number(parts[1]), _number(parts[2])
        ended = now
        if len(parts) == 5 and _number(parts[3]):
            key = parts[3]
            seen = entry["live"].pop(key, None)
            if seen:
                rx, tx = max(rx - seen[0], 0), max(tx - seen[1], 0)
            entry["closed"][key] = now
            ended = min(_number(parts[3]) + _number(parts[4]), now)
        _add(entry, _day(ended), rx, tx)

    # идущие сессии: в сегодняшний день — прирост с прошлого сбора
    if online is None:
        online = srv.online_clients()
    today = _day(now)
    active = set()
    for client in online:
        key = client.get("connected_since_t") or ""
        if not client["name"] or not key:
            continue
        entry = _entry(data, client["name"])
        if key in entry["closed"]:
            continue                    # status-файл ещё не обновился после отключения
        active.add((client["name"], key))
        seen = entry["live"].get(key, [0, 0, now])
        rx, tx = client.get("bytes_received", 0), client.get("bytes_sent", 0)
        _add(entry, today, max(rx - seen[0], 0), max(tx - seen[1], 0))
        entry["live"][key] = [max(rx, seen[0]), max(tx, seen[1]), now]

    # уборка: старые дни, давно завершённые и потерянные сессии
    oldest = _day(now - KEEP_DAYS * 86400)
    for name, entry in data.items():
        _entry(data, name)
        entry["days"] = {d: v for d, v in entry["days"].items() if d >= oldest}
        entry["closed"] = {k: t for k, t in entry["closed"].items() if now - t < CLOSED_TTL}
        entry["live"] = {k: v for k, v in entry["live"].items()
                         if (name, k) in active or now - v[2] < STALE_TTL}

    try:
        _save(data)
        if lines:
            os.unlink(srv.TRAFFIC_LOG + ".work")
    except OSError:
        pass
    return data


def summary(online=None, now: float = None) -> dict:
    """{имя: {"rx", "tx", "total"}} за всё время."""
    result = {}
    for name, entry in collect(online, now).items():
        rx, tx = entry.get("rx", 0), entry.get("tx", 0)
        result[name] = {"rx": rx, "tx": tx, "total": rx + tx}
    return result


def periods(name: str, online=None, now: float = None) -> list:
    """Трафик клиента за день/неделю/месяц/год/всё время."""
    now = time.time() if now is None else now
    entry = collect(online, now).get(name) or {}
    days = entry.get("days", {})
    today = datetime.date.fromtimestamp(now)
    rows = []
    for key, title, length in PERIODS:
        if length is None:
            rx, tx = entry.get("rx", 0), entry.get("tx", 0)
        else:
            since = (today - datetime.timedelta(days=length - 1)).isoformat()
            picked = [v for d, v in days.items() if d >= since]
            rx, tx = sum(v[0] for v in picked), sum(v[1] for v in picked)
        rows.append({"period": key, "title": title, "rx": rx, "tx": tx, "total": rx + tx})
    return rows


def forget(name: str) -> None:
    """Сбрасывает статистику клиента (при полном удалении имя может занять новый)."""
    data = collect()
    if data.pop(name, None) is not None:
        _save(data)
