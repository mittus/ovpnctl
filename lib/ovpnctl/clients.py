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


def set_static_ip(name: str, address: str, cfg: dict) -> str:
    """Фиксированный адрес клиента через client-config-dir."""
    net = ipaddress.IPv4Network(cfgmod.network_cidr(cfg))
    addr = ipaddress.IPv4Address(address)
    if addr not in net:
        raise OvpnError("address %s is outside VPN subnet %s." % (address, net))
    ensure_dir(srv.CCD_DIR, 0o755)
    path = os.path.join(srv.CCD_DIR, name)
    write_file(path, "ifconfig-push %s %s\n" % (addr, net.netmask), 0o644)
    db = pki.db_load()
    if name in db["clients"]:
        db["clients"][name]["static_ip"] = str(addr)
        pki.db_save(db)
    return path


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
        status = "revoked" if revoked else ("online" if name in online else "offline")
        left = None
        expires = meta.get("expires", "")
        if not revoked and pki.exists(name):
            left = pki.days_left(pki.cert_path(name))
            expires = pki.not_after(pki.cert_path(name)).strftime("%Y-%m-%d")
            if left < 0:
                status = "expired"
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
        })
    return rows
