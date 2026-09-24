"""Движок автопродления: CA, серверный сертификат, CRL и клиентские сертификаты.

Запускается ежедневно из systemd-таймера ovpnctl-renew.timer, а также вручную:
    ovpnctl pki renew            # продлить всё, чему пора
    ovpnctl pki renew --force    # продлить принудительно
    ovpnctl pki check            # только отчёт, без изменений
"""
from __future__ import annotations

import datetime
import os
import shutil
import time

from . import clients
from . import config as cfgmod
from . import pki
from . import server as srv
from .system import service_active, systemctl
from .util import OvpnError, ensure_dir, info, warn

MAX_LOG_BYTES = 1024 * 1024


# --------------------------------------------------------------------------- #
# Лог
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    ensure_dir(cfgmod.LOG_DIR, 0o750)
    path = cfgmod.RENEW_LOG
    try:
        if os.path.exists(path) and os.path.getsize(path) > MAX_LOG_BYTES:
            os.replace(path, path + ".1")
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a") as fh:
            fh.write("%s %s\n" % (stamp, msg))
        os.chmod(path, 0o640)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Отчёт о состоянии PKI
# --------------------------------------------------------------------------- #
def check(cfg: dict) -> dict:
    report = {"items": [], "action_needed": False, "problems": []}

    def add(kind, name, path, threshold, extra=None):
        entry = {"kind": kind, "name": name, "threshold": threshold}
        try:
            entry["expires"] = pki.not_after(path).strftime("%Y-%m-%d")
            entry["days_left"] = pki.days_left(path)
        except OvpnError as exc:
            entry["expires"] = "—"
            entry["days_left"] = None
            report["problems"].append("%s %s: %s" % (kind, name, exc))
        if extra:
            entry.update(extra)
        entry["needs_renew"] = (
            entry["days_left"] is not None and entry["days_left"] < threshold
        )
        if entry["needs_renew"]:
            report["action_needed"] = True
        report["items"].append(entry)
        return entry

    add("ca", "CA", pki.CA_CRT, cfg["renew_ca_before"])
    add("server", "server", pki.cert_path(pki.SERVER_NAME), cfg["renew_server_before"])

    # CRL живёт по своей схеме (nextUpdate)
    crl_entry = {"kind": "crl", "name": "CRL", "threshold": cfg["renew_crl_before"]}
    try:
        crl_entry["expires"] = pki.crl_next_update().strftime("%Y-%m-%d")
        crl_entry["days_left"] = pki.crl_days_left()
    except OvpnError as exc:
        crl_entry["expires"] = "—"
        crl_entry["days_left"] = None
        report["problems"].append("CRL: %s" % exc)
    crl_entry["needs_renew"] = (
        crl_entry["days_left"] is None or crl_entry["days_left"] < cfg["renew_crl_before"]
    )
    if crl_entry["needs_renew"]:
        report["action_needed"] = True
    report["items"].append(crl_entry)

    db = pki.db_load()
    for name in sorted(db["clients"]):
        if db["clients"][name].get("revoked"):
            continue
        if not pki.exists(name):
            report["problems"].append("client %s: certificate missing" % name)
            continue
        add("client", name, pki.cert_path(name), cfg["renew_client_before"])

    # состояние служб
    report["service_active"] = service_active(cfgmod.SERVICE)
    report["timer_active"] = service_active(cfgmod.RENEW_TIMER)
    if not report["service_active"]:
        report["problems"].append("service %s is not running" % cfgmod.SERVICE)
    if not report["timer_active"]:
        report["problems"].append("auto-renewal timer %s is not active" % cfgmod.RENEW_TIMER)
    return report


# --------------------------------------------------------------------------- #
# Продление
# --------------------------------------------------------------------------- #
def _crl_stale(cfg: dict) -> bool:
    if not os.path.exists(pki.CRL):
        return True
    try:
        if pki.crl_days_left() < int(cfg["renew_crl_before"]):
            return True
    except OvpnError:
        return True
    # подстраховка: освежаем CRL хотя бы раз в 30 дней
    age_days = (time.time() - os.path.getmtime(pki.CRL)) / 86400.0
    return age_days > 30


def run(cfg: dict, force: bool = False, quiet: bool = False) -> dict:
    """Продлевает всё, чему пора. Возвращает сводку выполненных действий."""
    actions = {"ca": False, "server": False, "crl": False, "clients": [], "restarted": False,
               "profiles": []}
    say = (lambda m: None) if quiet else info

    # 1. CRL — самая частая причина «внезапно отвалившегося» VPN
    if force or _crl_stale(cfg):
        pki.gen_crl(cfg)
        srv.reload_crl()
        actions["crl"] = True
        log("CRL reissued (valid until %s)" % pki.crl_next_update().strftime("%Y-%m-%d"))
        say("CRL reissued until %s" % pki.crl_next_update().strftime("%Y-%m-%d"))

    # 2. CA — перевыпуск тем же ключом, цепочка и клиентские сертификаты остаются валидны
    ca_days = pki.days_left(pki.CA_CRT)
    if force or ca_days < int(cfg["renew_ca_before"]):
        result = pki.renew_ca(cfg)
        actions["ca"] = True
        log("CA reissued with the same key, valid until %s (old one saved: %s). "
            "Already distributed profiles keep working until their CA copy expires (%s) — "
            "distribute updated .ovpn files before that date"
            % (result["not_after"][:10], os.path.basename(result["archived"]),
               pki.not_after(result["archived"]).strftime("%Y-%m-%d")))
        if not pki.old_ca_still_trusts(pki.SERVER_NAME):
            log("WARNING: the old CA copy no longer verifies the server certificate — "
                "clients must update their profiles immediately")
        say("CA reissued until %s" % result["not_after"][:10])
        # профили содержат CA-бандл => обновляем их все
        actions["profiles"] = clients.regenerate_all_profiles(cfg)
        # CRL подписан ключом CA — перевыпускаем, чтобы дата была свежей
        pki.gen_crl(cfg)
        actions["crl"] = True

    # 3. Серверный сертификат
    server_crt = pki.cert_path(pki.SERVER_NAME)
    server_days = pki.days_left(server_crt) if os.path.exists(server_crt) else -1
    if force or server_days < int(cfg["renew_server_before"]):
        renew_server(cfg)
        actions["server"] = True
        log("Server certificate reissued, valid until %s"
            % pki.not_after(server_crt).strftime("%Y-%m-%d"))
        say("Server certificate reissued until %s"
            % pki.not_after(server_crt).strftime("%Y-%m-%d"))

    # 4. Клиентские сертификаты
    if cfg.get("auto_renew_clients", True):
        db = pki.db_load()
        for name in sorted(db["clients"]):
            meta = db["clients"][name]
            if meta.get("revoked") or not pki.exists(name):
                continue
            left = pki.days_left(pki.cert_path(name))
            if force or left < int(cfg["renew_client_before"]):
                # Не даём коротким сертификатам продлеваться каждый день:
                # минимальный новый срок — два порога автопродления.
                days = max(int(meta.get("days") or cfg["client_days"]),
                           int(cfg["renew_client_before"]) * 2)
                res = clients.renew(name, cfg, days=days)
                actions["clients"].append(name)
                log("Client '%s' renewed until %s — profile updated (%s), the client must "
                    "re-import the .ovpn before the old certificate expires"
                    % (name, res["expires"][:10], res["profile"]))
                say("Client '%s' renewed until %s" % (name, res["expires"][:10]))

    # 5. Применяем изменения на сервере
    if actions["ca"] or actions["server"]:
        srv.deploy_pki_to_server(cfg)
        srv.restart()
        actions["restarted"] = True
        log("Service %s restarted after PKI update" % cfgmod.SERVICE)
    elif actions["crl"]:
        srv.reload_crl()

    # 6. Служба должна работать
    if not service_active(cfgmod.SERVICE):
        warn("Service %s is not active — trying to start it." % cfgmod.SERVICE)
        systemctl("restart", cfgmod.SERVICE, check=False)
        log("Service was inactive, restart performed")

    if not any([actions["ca"], actions["server"], actions["crl"], actions["clients"]]):
        log("Check completed, no renewal needed")
    return actions


def renew_server(cfg: dict) -> None:
    """Перевыпуск серверного сертификата тем же ключом + редеплой."""
    crt = pki.cert_path(pki.SERVER_NAME)
    if os.path.exists(crt):
        stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        shutil.copy2(crt, pki.p("archive", "server-%s.crt" % stamp))
        os.unlink(crt)
    pki.issue(pki.SERVER_NAME, "server_cert", int(cfg["server_days"]), cfg, reuse_key=True)
    srv.deploy_pki_to_server(cfg)
