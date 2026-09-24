"""Накопительный трафик клиентов с разбивкой по дням.

Два источника:
  * журнал завершённых сессий — его пишет сам openvpn (client-disconnect,
    см. server.TRAFFIC_SCRIPT): имя, байты сессии, время подключения и длительность;
  * status-файл — байты текущих сессий.

collect() раз в несколько минут (таймер ovpnctl-traffic.timer, а также при каждом
просмотре) раскладывает прирост по дням: для идущей сессии запоминается, сколько
байт и на какой момент уже учтено. Новый прирост делится между днями
пропорционально времени — от прошлого замера (для первого замера — от момента
подключения) до текущего; для завершённой сессии — до момента отключения. Так
многодневная сессия не ложится целиком в день, когда её впервые увидели.

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
SLOT = 300                  # мелкие корзины для окон в часах — по 5 минут (шаг таймера)
KEEP_SLOTS = 13 * 3600      # хватает на самое длинное окно в часах (12 ч)
CLOSED_TTL = 86400          # сколько помнить завершённые сессии (status-файл может отставать)
STALE_TTL = 7 * 86400       # сессия пропала без записи в журнале (сбой openvpn)

# (ключ, заголовок, длина, единица): окна в часах скользящие, в днях — календарные
PERIODS = [
    ("1h", "Last hour", 1, "hours"),
    ("7h", "Last 7 hours", 7, "hours"),
    ("12h", "Last 12 hours", 12, "hours"),
    ("day", "Today", 1, "days"),
    ("week", "Week (7 days)", 7, "days"),
    ("month", "Month (30 days)", 30, "days"),
    ("year", "Year (365 days)", 365, "days"),
    ("all", "All time", None, None),
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
    for key, default in (("rx", 0), ("tx", 0), ("days", {}), ("slots", {}), ("live", {}),
                         ("closed", {})):
        entry.setdefault(key, default)
    return entry


def _next_midnight(stamp: float) -> float:
    day = datetime.date.fromtimestamp(stamp) + datetime.timedelta(days=1)
    return time.mktime(day.timetuple())


def _next_slot(stamp: float) -> float:
    return (int(stamp) // SLOT + 1) * SLOT


def _slot(stamp: float) -> str:
    return str(int(stamp) // SLOT)


def _spread(start: float, end: float, total: int, border, key, since: float = None) -> dict:
    """Делит total по интервалам [start, end], разрезанным границами border(),
    пропорционально времени. Округление накопительное: сумма частей по всему
    интервалу ровно total. since — не считать части раньше этого момента."""
    if total <= 0:
        return {}
    if end <= start:
        return {key(end): total}
    length = end - start
    moment = start if since is None else max(start, since)
    result = {}
    done = round(total * (moment - start) / length)
    while moment < end:
        edge = min(border(moment), end)
        upto = round(total * (edge - start) / length)
        if upto > done:
            result[key(moment)] = result.get(key(moment), 0) + upto - done
        done, moment = upto, edge
    return result


def _add(entry: dict, start: float, end: float, rx: int, tx: int, now: float) -> None:
    """Прирост за интервал [start, end]: по дням и по 5-минутным слотам последних часов."""
    if rx <= 0 and tx <= 0:
        return
    entry["rx"] += rx
    entry["tx"] += tx
    start = min(start, end)
    since = now - KEEP_SLOTS
    for store, border, key, clip in (("days", _next_midnight, _day, None),
                                     ("slots", _next_slot, _slot, since)):
        parts_rx = _spread(start, end, rx, border, key, clip)
        parts_tx = _spread(start, end, tx, border, key, clip)
        for name in set(parts_rx) | set(parts_tx):
            bucket = entry[store].setdefault(name, [0, 0])
            bucket[0] += parts_rx.get(name, 0)
            bucket[1] += parts_tx.get(name, 0)


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
        start = ended = now             # старый формат без времени — относим к моменту сбора
        if len(parts) == 5 and _number(parts[3]):
            key = parts[3]
            start = _number(parts[3])
            ended = min(start + _number(parts[4]), now)
            seen = entry["live"].pop(key, None)
            if seen:
                rx, tx = max(rx - seen[0], 0), max(tx - seen[1], 0)
                start = seen[2]
            entry["closed"][key] = now
        _add(entry, start, ended, rx, tx, now)

    # идущие сессии: прирост с прошлого замера (или с момента подключения)
    if online is None:
        online = srv.online_clients()
    active = set()
    for client in online:
        key = client.get("connected_since_t") or ""
        if not client["name"] or not key:
            continue
        entry = _entry(data, client["name"])
        if key in entry["closed"]:
            continue                    # status-файл ещё не обновился после отключения
        active.add((client["name"], key))
        seen = entry["live"].get(key) or [0, 0, min(_number(key) or now, now)]
        rx, tx = client.get("bytes_received", 0), client.get("bytes_sent", 0)
        _add(entry, seen[2], now, max(rx - seen[0], 0), max(tx - seen[1], 0), now)
        entry["live"][key] = [max(rx, seen[0]), max(tx, seen[1]), now]

    # уборка: старые дни, давно завершённые и потерянные сессии
    oldest = _day(now - KEEP_DAYS * 86400)
    for name, entry in data.items():
        _entry(data, name)
        entry["days"] = {d: v for d, v in entry["days"].items() if d >= oldest}
        first_slot = int(now - KEEP_SLOTS) // SLOT
        entry["slots"] = {k: v for k, v in entry["slots"].items() if int(k) >= first_slot}
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
    """Трафик клиента: последние 1/7/12 часов, сегодня, неделя, месяц, год, всё время."""
    now = time.time() if now is None else now
    entry = collect(online, now).get(name) or {}
    days, slots = entry.get("days", {}), entry.get("slots", {})
    today = datetime.date.fromtimestamp(now)
    rows = []
    for key, title, length, unit in PERIODS:
        if length is None:
            rx, tx = entry.get("rx", 0), entry.get("tx", 0)
        elif unit == "hours":
            # слот, в который попадает начало окна, считается целиком (погрешность ≤ 5 мин)
            first = int(now - length * 3600) // SLOT
            picked = [v for k, v in slots.items() if int(k) >= first]
            rx, tx = sum(v[0] for v in picked), sum(v[1] for v in picked)
        else:
            since = (today - datetime.timedelta(days=length - 1)).isoformat()
            picked = [v for d, v in days.items() if d >= since]
            rx, tx = sum(v[0] for v in picked), sum(v[1] for v in picked)
        rows.append({"period": key, "title": title, "rx": rx, "tx": tx, "total": rx + tx})
    return rows


def reset(name: str = None, online=None, now: float = None) -> list:
    """Обнуляет статистику клиента (или всех, если name не задан).

    Сначала досчитываем всё, что накопилось, и только потом обнуляем. Базу
    идущих сессий (live) не трогаем: иначе следующий замер посчитал бы
    весь трафик сессии заново, с момента подключения.
    """
    data = collect(online, now)
    names = [name] if name else list(data)
    for key in names:
        entry = data.get(key)
        if entry is None:
            continue
        entry.update(rx=0, tx=0, days={}, slots={})
    _save(data)
    return [key for key in names if key in data]


def forget(name: str) -> None:
    """Сбрасывает статистику клиента (при полном удалении имя может занять новый)."""
    data = collect()
    if data.pop(name, None) is not None:
        _save(data)
