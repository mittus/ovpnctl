"""Управление клиентами: выпуск, отзыв, продление, генерация .ovpn."""
from __future__ import annotations

import datetime
import ipaddress
import os
import shutil

from . import config as cfgmod
from . import pki
from . import server as srv
from . import traffic
from .util import OvpnError, ensure_dir, read_file, warn, write_file

PROFILE_HEADER = """client
dev {dev}
proto {proto}
remote {endpoint} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
reneg-sec 3600
auth {auth}
tls-version-min 1.2
verb 3
setenv opt data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
setenv opt data-ciphers-fallback AES-256-GCM
setenv opt cipher AES-256-GCM
setenv opt allow-compression no
"""


# --------------------------------------------------------------------------- #
# Профиль
# --------------------------------------------------------------------------- #
def _pem_block(tag: str, path: str) -> str:
    body = read_file(path).strip()
    return "<%s>\n%s\n</%s>\n" % (tag, body, tag)


def profile_text(name: str, cfg: dict) -> str:
    if not pki.exists(name):
        raise OvpnError("client '%s' not found." % name)
    crt = pki.cert_path(name)
    key = pki.key_path(name)
    if not os.path.exists(key):
        raise OvpnError("no private key for client '%s' (profile cannot be rebuilt)." % name)

    head = PROFILE_HEADER.format(
        dev=cfg.get("dev", "tun"),
        proto=cfg["proto"],
        endpoint=cfg["endpoint"],
        port=cfg["port"],
        auth="SHA256",
    )
    parts = [head, "\n"]
    parts.append(_pem_block("ca", pki.CA_CRT))
    parts.append(_pem_block("cert", crt))
    parts.append(_pem_block("key", key))
    parts.append("<tls-crypt>\n%s\n</tls-crypt>\n" % read_file(pki.TC_KEY).strip())
    return "".join(parts)


def profile_path(name: str) -> str:
    return os.path.join(cfgmod.PROFILE_DIR, "%s.ovpn" % name)


def write_profile(name: str, cfg: dict) -> str:
    ensure_dir(cfgmod.PROFILE_DIR, 0o700)
    path = profile_path(name)
    write_file(path, profile_text(name, cfg), 0o600)
    return path


def regenerate_all_profiles(cfg: dict) -> list:
    """Перегенерация всех профилей (после ротации CA или смены endpoint)."""
    updated = []
    db = pki.db_load()
    for name, meta in db["clients"].items():
        if meta.get("revoked"):
            continue
        if not pki.exists(name):
            continue
        try:
            write_profile(name, cfg)
            updated.append(name)
        except OvpnError as exc:
            warn("profile '%s' not regenerated: %s" % (name, exc))
    return updated


# --------------------------------------------------------------------------- #
# CRUD клиентов
# --------------------------------------------------------------------------- #
def add(name: str, cfg: dict, days: int = None, static_ip: str = None) -> dict:
    pki.valid_name(name)
    db = pki.db_load()
    if name in db["clients"] and not db["clients"][name].get("revoked"):
        raise OvpnError("client '%s' already exists (view profile: "
                        "ovpnctl client show %s)." % (name, name))
    if pki.exists(name):
        raise OvpnError("certificate '%s' already issued — revoke or remove it first." % name)

    if static_ip:
        check_static_ip(name, static_ip, cfg)   # до выпуска сертификата: не оставлять сироту
    days = int(days or cfg["client_days"])
    pki.issue(name, "client_cert", days, cfg)
    path = write_profile(name, cfg)

    if static_ip:
        set_static_ip(name, static_ip, cfg)

    db = pki.db_load()
    db["clients"][name] = {
        "created": pki.now_iso(),
        "days": days,
        "serial": pki.serial_of(pki.cert_path(name)),
        "expires": pki.not_after(pki.cert_path(name)).isoformat(),
        "revoked": False,
        "static_ip": static_ip or "",
        "profile": path,
        "renewed": [],
    }
    pki.db_save(db)
    return {"name": name, "profile": path, "expires": db["clients"][name]["expires"]}


def revoke(name: str, cfg: dict) -> None:
    db = pki.db_load()
    if name not in db["clients"]:
        raise OvpnError("client '%s' not found." % name)
    if db["clients"][name].get("revoked"):
        raise OvpnError("client '%s' is already revoked." % name)
    pki.revoke(name, cfg)
    srv.reload_crl()
    srv.kill_client(name)                       # рвём активную сессию, если есть
    db = pki.db_load()
    db["clients"][name]["revoked"] = True
    db["clients"][name]["revoked_at"] = pki.now_iso()
    pki.db_save(db)
    path = profile_path(name)
    if os.path.exists(path):
        os.unlink(path)
    key = pki.key_path(name)
    if os.path.exists(key):
        shutil.move(key, pki.p("revoked", "%s.key" % name))


def delete(name: str, cfg: dict) -> None:
    """Полное удаление: отзыв (если нужно) + удаление всех артефактов."""
    db = pki.db_load()
    if name in db["clients"] and not db["clients"][name].get("revoked"):
        revoke(name, cfg)
        db = pki.db_load()
    for path in (
        pki.cert_path(name), pki.key_path(name), pki.p("reqs", "%s.req" % name),
        profile_path(name), os.path.join(srv.CCD_DIR, name),
    ):
        if os.path.exists(path):
            os.unlink(path)
    db["clients"].pop(name, None)
    pki.db_save(db)
    traffic.forget(name)


def renew(name: str, cfg: dict, days: int = None, new_key: bool = False) -> dict:
    """Продление клиентского сертификата (по умолчанию — тем же ключом,
    чтобы старый профиль продолжал работать до истечения старого сертификата)."""
    db = pki.db_load()
    meta = db["clients"].get(name)
    if not meta:
        raise OvpnError("client '%s' not found." % name)
    if meta.get("revoked"):
        raise OvpnError("client '%s' is revoked — cannot renew." % name)

    days = int(days or meta.get("days") or cfg["client_days"])
    old = pki.cert_path(name)
    if os.path.exists(old):
        stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        shutil.copy2(old, pki.p("archive", "%s-%s.crt" % (name, stamp)))
        os.unlink(old)
    pki.issue(name, "client_cert", days, cfg, reuse_key=not new_key)
    path = write_profile(name, cfg)

    db = pki.db_load()
    meta = db["clients"][name]
    meta["days"] = days
    meta["serial"] = pki.serial_of(pki.cert_path(name))
    meta["expires"] = pki.not_after(pki.cert_path(name)).isoformat()
    meta["profile"] = path
    meta.setdefault("renewed", []).append(pki.now_iso())
    pki.db_save(db)
    return {"name": name, "profile": path, "expires": meta["expires"]}


def static_range(cfg: dict) -> str:
    plan = cfgmod.address_plan(cfg)
    if not plan["static"]:
        return "none (static_reserve = 0)"
    return "%s–%s" % plan["static"]


def check_static_ip(name: str, address: str, cfg: dict):
    """Проверка адреса для client ip. Годятся только адреса резерва (static_reserve):
    динамический пул о ccd не знает и выдал бы тот же адрес другому клиенту."""
    plan = cfgmod.address_plan(cfg)
    net = plan["network"]
    try:
        addr = ipaddress.IPv4Address(address)
    except ValueError:
        raise OvpnError("invalid address: %s" % address)
    if addr not in net:
        raise OvpnError("address %s is outside VPN subnet %s." % (address, net))
    static = plan["static"]
    if not static or not static[0] <= addr <= static[1]:
        raise OvpnError("address %s is not in the static range %s (the rest of %s is the "
                        "dynamic pool)." % (addr, static_range(cfg), net))
    for other, ip in pinned_addresses().items():
        if other != name and ip == str(addr):
            raise OvpnError("address %s is already pinned to '%s'." % (addr, other))
    return addr, net


def pinned_addresses() -> dict:
    """{клиент: адрес} из client-config-dir (его и читает OpenVPN) и из базы ovpnctl."""
    found = {}
    db = pki.db_load()["clients"]
    for name, meta in db.items():
        if meta.get("static_ip") and not meta.get("revoked"):
            found[name] = meta["static_ip"]
    if os.path.isdir(srv.CCD_DIR):
        for name in os.listdir(srv.CCD_DIR):
            if db.get(name, {}).get("revoked"):
                continue                  # отозванный не подключится — адрес свободен
            try:
                body = read_file(os.path.join(srv.CCD_DIR, name))
            except OSError:
                continue
            for line in body.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "ifconfig-push":
                    found[name] = parts[1]
    return found


def _ccd_path(name: str) -> str:
    return os.path.join(srv.CCD_DIR, name)


def _ccd_lines(name: str) -> list:
    path = _ccd_path(name)
    if not os.path.exists(path):
        return []
    return read_file(path).splitlines()


def _ccd_write(name: str, lines: list) -> str:
    """Пишет ccd клиента; файл без директив удаляется (OpenVPN читает его при подключении)."""
    path = _ccd_path(name)
    if not any(line.strip() and not line.lstrip().startswith("#") for line in lines):
        if os.path.exists(path):
            os.unlink(path)
        return path
    ensure_dir(srv.CCD_DIR, 0o755)
    write_file(path, "\n".join(lines).rstrip("\n") + "\n", 0o644)
    return path


def _directive(line: str) -> str:
    parts = line.split()
    return parts[0] if parts else ""


def set_static_ip(name: str, address: str, cfg: dict) -> str:
    """Фиксированный адрес клиента через client-config-dir (прочие директивы ccd сохраняются)."""
    addr, net = check_static_ip(name, address, cfg)
    db = pki.db_load()
    lines = [line for line in _ccd_lines(name) if _directive(line) != "ifconfig-push"]
    path = _ccd_write(name, lines + ["ifconfig-push %s %s" % (addr, net.netmask)])
    if name in db["clients"]:
        db["clients"][name]["static_ip"] = str(addr)
        pki.db_save(db)
    return path


def static_conflicts(cfg: dict) -> list:
    """Закреплённые адреса, которые попали в динамический пул (остались от старых версий)."""
    plan = cfgmod.address_plan(cfg)
    first, last = plan["dynamic"]
    found = []
    for name, ip in sorted(pinned_addresses().items()):
        try:
            if first <= ipaddress.IPv4Address(ip) <= last:
                found.append((name, ip))
        except ValueError:
            continue
    return found


def is_suspended(name: str) -> bool:
    return any(_directive(line) == "disable" for line in _ccd_lines(name))


def suspend(name: str, cfg: dict) -> bool:
    """Приостановить доступ: `disable` в ccd + разрыв текущей сессии.

    Сертификат и профиль не трогаются — после resume клиент подключается
    тем же .ovpn. Возвращает True, если активную сессию удалось разорвать.
    """
    db = pki.db_load()
    meta = db["clients"].get(name)
    if not meta:
        raise OvpnError("client '%s' not found." % name)
    if meta.get("revoked"):
        raise OvpnError("client '%s' is revoked." % name)
    if not is_suspended(name):
        _ccd_write(name, ["disable"] + _ccd_lines(name))
    meta["suspended"] = True
    meta["suspended_at"] = pki.now_iso()
    pki.db_save(db)
    return srv.kill_client(name)


def resume(name: str, cfg: dict) -> None:
    """Вернуть доступ приостановленному клиенту (тот же профиль снова работает)."""
    db = pki.db_load()
    meta = db["clients"].get(name)
    if not meta:
        raise OvpnError("client '%s' not found." % name)
    if meta.get("revoked"):
        raise OvpnError("client '%s' is revoked — create a new one instead." % name)
    _ccd_write(name, [line for line in _ccd_lines(name) if _directive(line) != "disable"])
    meta["suspended"] = False
    meta.pop("suspended_at", None)
    pki.db_save(db)


def known_addresses() -> dict:
    """Адреса, выданные клиентам ранее (ifconfig-pool-persist)."""
    result = {}
    path = srv.IPP_FILE
    if not os.path.exists(path):
        return result
    try:
        body = read_file(path)
    except OSError:
        return result
    for line in body.splitlines():
        parts = line.split(",")
        if len(parts) >= 2 and parts[1].strip():
            result[parts[0].strip()] = parts[1].strip()
    return result


def listing(cfg: dict) -> list:
    """Сводка по всем клиентам с актуальными сроками и адресами."""
    db = pki.db_load()
    online = {c["name"]: c.get("virtual_address", "") for c in srv.online_clients()}
    pool = known_addresses()
    rows = []
    for name in sorted(db["clients"]):
        meta = db["clients"][name]
        revoked = bool(meta.get("revoked"))
        suspended = not revoked and is_suspended(name)
        status = "revoked" if revoked else ("online" if name in online else "offline")
        left = None
        expires = meta.get("expires", "")
        if not revoked and pki.exists(name):
            left = pki.days_left(pki.cert_path(name))
            expires = pki.not_after(pki.cert_path(name)).strftime("%Y-%m-%d")
            if left < 0:
                status = "expired"
        if suspended:
            status = "suspended"
        # что показать в колонке адреса: закреплённый → текущий → последний выданный
        address = meta.get("static_ip") or online.get(name) or pool.get(name, "")
        rows.append({
            "name": name,
            "status": status,
            "expires": expires[:10],
            "days_left": left,
            "static_ip": meta.get("static_ip", ""),
            "address": address,
            "created": meta.get("created", "")[:10],
            "suspended": suspended,
        })
    return rows


def overview(cfg: dict) -> list:
    """Список клиентов для экрана Client List: адрес, откуда подключён, последнее
    подключение и трафик за всё время.

    Порядок: сначала онлайн, потом остальные, отозванные в самом конце; внутри
    группы — по последнему подключению, свежие сверху; кто ни разу не
    подключался — в конце группы по имени.
    """
    online = srv.online_clients()
    sessions = {c["name"]: c for c in online if c["name"] and c["name"] != srv.UNDEF}
    store = traffic.collect(online)
    rows = []
    for row in listing(cfg):
        entry = store.get(row["name"]) or {}
        session = sessions.get(row["name"])
        stamp, exact = traffic.last_connected(entry)
        if session and session.get("connected_since_t"):
            stamp, exact = float(session["connected_since_t"]), True
        rx, tx = entry.get("rx", 0), entry.get("tx", 0)
        row.update(
            real_address=session.get("real_address", "") if session else "",
            last_connected=stamp,
            last_connected_exact=exact,
            rx=rx, tx=tx, total=rx + tx,
        )
        rows.append(row)
    group = {"online": 0, "revoked": 2}
    rows.sort(key=lambda r: (group.get(r["status"], 1), -(r["last_connected"] or 0), r["name"]))
    return rows
