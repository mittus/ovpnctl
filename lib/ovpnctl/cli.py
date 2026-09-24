"""CLI: подкоманды и интерактивное меню (в стиле 3x-ui, без веб-интерфейса)."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import clients
from . import config as cfgmod
from . import pki
from . import provision
from . import renew as renew_mod
from . import server as srv
from . import traffic
from . import update as update_mod
from .system import (
    give_to_user,
    run,
    service_active,
    service_enabled,
    system_facts,
    systemctl,
    user_output_dir,
)
from .util import (
    C_GREEN,
    C_RESET,
    C_WHITE,
    OvpnError,
    ask_optional,
    ask_yes_no,
    bold,
    clear_screen,
    dim,
    err,
    hl,
    human_bytes,
    info,
    ok,
    pad,
    pause,
    red,
    require_root,
    table,
    warn,
    write_file,
)


# --------------------------------------------------------------------------- #
# Раскраска ячеек таблиц: активные значения — тёмно-зелёные, проблемы — красные
# --------------------------------------------------------------------------- #
def _status(value: str) -> str:
    if value == "online":
        return hl(value)
    if value in ("revoked", "expired"):
        return red(value)
    return value


def _days(value) -> str:
    if value is None:
        return "—"
    return red(value) if value < 0 else hl(value)


def _bytes(num) -> str:
    return hl(human_bytes(num)) if num else human_bytes(num)


def _or_dash(value) -> str:
    return hl(value) if value else "—"


# --------------------------------------------------------------------------- #
# Команды: клиенты
# --------------------------------------------------------------------------- #
def cmd_client_add(args) -> int:
    cfg = cfgmod.load()
    result = clients.add(args.name, cfg, days=args.days, static_ip=args.ip)
    profile = export_profile(args.name, cfg)
    ok("Client '%s' created (certificate valid until %s)." % (args.name, result["expires"][:10]))
    print("  Profile: %s" % hl(profile))
    if args.print_profile:
        print()
        sys.stdout.write(open(profile).read())
    return 0


def export_profile(name: str, cfg: dict, output: str = None) -> str:
    """Кладёт .ovpn в личный каталог вызвавшего пользователя (~/ovpnctl) или по
    указанному пути и передаёт файл ему во владение — чтобы забрать без sudo."""
    if not output:
        target = os.path.join(user_output_dir(), "%s.ovpn" % name)
    elif os.path.isdir(output):
        target = os.path.join(output, "%s.ovpn" % name)
    else:
        target = output
    target = os.path.abspath(target)
    write_file(target, clients.profile_text(name, cfg), 0o600)
    give_to_user(target)
    return target


def _client_rows(rows, numbered: bool = False) -> str:
    printable = []
    for index, r in enumerate(rows, 1):
        row = [hl(r["name"]), _status(r["status"]), r["expires"], _days(r["days_left"]),
               _or_dash(r["address"]), r["created"]]
        printable.append((["%d." % index] if numbered else []) + row)
    headers = ["NAME", "STATUS", "EXPIRES", "DAYS", "ADDRESS", "CREATED"]
    return table(printable, (["#"] if numbered else []) + headers)


def cmd_client_list(args) -> int:
    cfg = cfgmod.load()
    rows = clients.listing(cfg)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    if not rows:
        info("No clients yet. Create one: ovpnctl client add <certname>")
        return 0
    print(_client_rows(rows, numbered=getattr(args, "numbered", False)))
    return 0


def cmd_client_show(args) -> int:
    cfg = cfgmod.load()
    path = clients.profile_path(args.name)
    if not os.path.exists(path):
        clients.write_profile(args.name, cfg)
    if args.path:
        print(path)
    else:
        sys.stdout.write(open(path).read())
    return 0


def cmd_client_revoke(args) -> int:
    cfg = cfgmod.load()
    if not args.yes and not ask_yes_no(
            "Revoke client '%s'? Access is cut off immediately." % args.name, False):
        return 1
    clients.revoke(args.name, cfg)
    ok("Client '%s' revoked, CRL updated, active session terminated." % args.name)
    return 0


def cmd_client_delete(args) -> int:
    cfg = cfgmod.load()
    if not args.yes and not ask_yes_no("Delete client '%s' completely?" % args.name, False):
        return 1
    clients.delete(args.name, cfg)
    ok("Client '%s' deleted." % args.name)
    return 0


def cmd_client_renew(args) -> int:
    cfg = cfgmod.load()
    result = clients.renew(args.name, cfg, days=args.days, new_key=args.new_key)
    ok("Certificate '%s' renewed until %s. Updated profile: %s"
       % (args.name, result["expires"][:10], result["profile"]))
    warn("The client must re-import the .ovpn (the old one works until the previous expiry date).")
    return 0


def cmd_client_ip(args) -> int:
    cfg = cfgmod.load()
    path = clients.set_static_ip(args.name, args.address, cfg)
    ok("Client '%s' pinned to %s (%s). No restart needed — applies on the next connection."
       % (args.name, args.address, path))
    return 0


# --------------------------------------------------------------------------- #
# Команды: статус и сервер
# --------------------------------------------------------------------------- #
def _flag(active: bool, yes: str, no: str) -> str:
    return hl(yes) if active else red(no)


def cmd_status(args) -> int:
    cfg = cfgmod.load()
    facts = system_facts()
    summary = srv.status_summary(cfg)
    report = renew_mod.check(cfg)
    if args.json:
        print(json.dumps({"config": cfg, "system": facts, "status": summary, "pki": report},
                         indent=2, ensure_ascii=False))
        return 0

    firewall = _flag(summary["firewall"], "active", "NOT active")
    if cfg.get("ufw_configured"):
        firewall += ", ufw configured"
    elif srv.ufw_active():
        firewall += ", ufw active without ovpnctl rules"
    print(bold("Server"))
    print("  OpenVPN:        %s" % _flag(summary["active"], "running", "STOPPED"))
    print("  Endpoint:       %s" % hl(summary["endpoint"]))
    print("  Subnet:         %s (interface %s)" % (hl(cfgmod.network_cidr(cfg)), hl(cfg["nic"])))
    print("  Client DNS:     %s" % hl(", ".join(cfg["dns"])))
    print("  Firewall:       %s" % firewall)
    print("  Auto-renewal:   %s" % _flag(summary["timer"], "timer active", "TIMER DISABLED"))
    print("  System:         %s, OpenVPN %s, OpenSSL %s"
          % (facts["distro"], facts["openvpn"], facts["openssl"]))

    print()
    print(bold("Certificates"))
    rows = []
    for item in report["items"]:
        if item["kind"] == "client":
            continue
        mark = red("renew") if item["needs_renew"] else hl("ok")
        rows.append([hl(item["name"]), item["expires"], _days(item["days_left"]), mark])
    print(table(rows, ["OBJECT", "EXPIRES", "DAYS", "STATE"]))

    online = srv.online_clients()
    all_clients = clients.listing(cfg)
    active = [c for c in all_clients if c["status"] != "revoked"]
    print()
    print(bold("Clients"))
    print("  Total: %s, active: %s, online: %s"
          % (hl(len(all_clients)), hl(len(active)), hl(len(online))))
    if all_clients:
        shown = all_clients[:20]
        rows = [[hl(c["name"]), _status(c["status"]), c["expires"], _days(c["days_left"]),
                 _or_dash(c["address"])] for c in shown]
        print()
        print(table(rows, ["NAME", "STATUS", "EXPIRES", "DAYS", "ADDRESS"]))
        if len(all_clients) > len(shown):
            print(dim("  …%d more — see 'ovpnctl client list'" % (len(all_clients) - len(shown))))
    if online:
        print()
        print(bold("Connected now"))
        for client in online:
            print("   • %s %s %s ↓ / %s ↑  since %s"
                  % (pad(hl(client["name"]), 20), pad(hl(client["virtual_address"]), 16),
                     _bytes(client["bytes_received"]), _bytes(client["bytes_sent"]),
                     client["connected_since"]))
    if report["problems"]:
        print()
        warn("Notes:")
        for problem in report["problems"]:
            warn("  • %s" % problem)
    return 0


def cmd_online(args) -> int:
    online = srv.online_clients()
    if args.json:
        print(json.dumps(online, indent=2, ensure_ascii=False))
        return 0
    if not online:
        info("No active connections.")
        return 0
    rows = [[hl(c["name"]), hl(c["virtual_address"]), c["real_address"],
             _bytes(c["bytes_received"]), _bytes(c["bytes_sent"]), c["connected_since"]]
            for c in online]
    print(table(rows, ["NAME", "VPN ADDRESS", "FROM", "RECEIVED", "SENT", "CONNECTED SINCE"]))
    return 0


def cmd_traffic(args) -> int:
    """Трафик: общий список за всё время или один клиент по периодам."""
    if args.collect:
        traffic.collect()               # вызывается таймером
        return 0

    if args.name:
        known = {r["name"] for r in clients.listing(cfgmod.load())}
        if args.name not in known and args.name not in traffic.summary():
            raise OvpnError("client '%s' not found." % args.name)
        rows = traffic.periods(args.name)
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return 0
        print(bold("Traffic of client ") + hl(args.name))
        print(table([[r["title"], _bytes(r["rx"]), _bytes(r["tx"]), _bytes(r["total"])]
                     for r in rows], ["PERIOD", "RECEIVED", "SENT", "TOTAL"]))
        return 0

    rows = _traffic_rows(cfgmod.load())
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    if not rows:
        info("No clients yet. Create one: ovpnctl client add <certname>")
        return 0
    print(bold("Client traffic, all time"))
    print(_traffic_table(rows))
    print(dim("  Received/sent — from the server's side. Per period: ovpnctl traffic <certname>"))
    return 0


def _traffic_rows(cfg: dict) -> list:
    usage = traffic.summary()
    zero = {"rx": 0, "tx": 0, "total": 0}
    return [dict(name=r["name"], status=r["status"], **usage.get(r["name"], zero))
            for r in clients.listing(cfg)]


def _traffic_table(rows, numbered: bool = False) -> str:
    printable = [(["%d." % i] if numbered else [])
                 + [hl(r["name"]), _status(r["status"]), _bytes(r["rx"]), _bytes(r["tx"]),
                    _bytes(r["total"])]
                 for i, r in enumerate(rows, 1)]
    headers = ["NAME", "STATUS", "RECEIVED", "SENT", "TOTAL"]
    return table(printable, (["#"] if numbered else []) + headers)


def cmd_server(args) -> int:
    cfg = cfgmod.load()
    action = args.action
    if action == "restart":
        srv.restart()
        ok("Service restarted.")
    elif action == "start":
        systemctl("start", cfgmod.SERVICE)
        ok("Service started.")
    elif action == "stop":
        systemctl("stop", cfgmod.SERVICE)
        ok("Service stopped.")
    elif action == "rebuild":
        srv.deploy_pki_to_server(cfg)
        srv.write_server_conf(cfg)
        srv.setup_networking(cfg)
        provision.write_units()
        systemctl("restart", cfgmod.FIREWALL_UNIT, check=False)
        srv.restart()
        ok("Configuration rebuilt and applied.")
    elif action == "config":
        sys.stdout.write(open(cfgmod.server_conf_path()).read())
    elif action == "logs":
        run(["journalctl", "-u", cfgmod.SERVICE, "-n", str(args.lines), "--no-pager"],
            capture=False, check=False)
    return 0


def cmd_set(args) -> int:
    """Изменение ключевых параметров с пересборкой конфигурации."""
    cfg = cfgmod.load()
    old_port, old_proto = cfg["port"], cfg["proto"]
    changed = []
    if args.endpoint:
        cfg["endpoint"] = args.endpoint
        changed.append("endpoint")
    if args.port:
        cfg["port"] = int(args.port)
        changed.append("port")
    if args.proto:
        cfg["proto"] = args.proto
        changed.append("proto")
    if args.dns:
        cfg["dns"] = [d.strip() for d in args.dns.split(",") if d.strip()]
        changed.append("dns")
    if args.nic:
        cfg["nic"] = args.nic
        changed.append("nic")
    if not changed:
        raise OvpnError("no parameters given (see ovpnctl set --help).")

    srv.validate_cfg(cfg)
    cfgmod.save(cfg)
    if cfg.get("ufw_configured") and ("port" in changed or "proto" in changed):
        for step in srv.setup_ufw(cfg, old_port=old_port, old_proto=old_proto):
            info("  ufw: %s" % step)
    srv.write_server_conf(cfg)
    srv.setup_networking(cfg)
    systemctl("restart", cfgmod.FIREWALL_UNIT, check=False)
    srv.restart()
    updated = clients.regenerate_all_profiles(cfg)
    ok("Changed: %s. Profiles regenerated: %d." % (", ".join(changed), len(updated)))
    warn("Clients need to download the updated .ovpn (connection parameters changed).")
    return 0


# --------------------------------------------------------------------------- #
# Команды: PKI
# --------------------------------------------------------------------------- #
def cmd_ufw(args) -> int:
    cfg = cfgmod.load()
    if args.remove:
        steps = srv.setup_ufw(cfg, remove=True)
        ok("ufw rules for OpenVPN removed.")
    else:
        steps = srv.setup_ufw(cfg, install=args.install, with_ssh=args.ssh)
        ok("OpenVPN port opened in ufw: %d/%s." % (cfg["port"], cfg["proto"]))
    for step in steps:
        print("  • %s" % step)
    if srv.ufw_available():
        print()
        print(bold("Current ufw state"))
        run(["ufw", "status", "verbose"], capture=False, check=False)
    return 0


def cmd_pki_check(args) -> int:
    cfg = cfgmod.load()
    report = renew_mod.check(cfg)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    rows = [[i["kind"], hl(i["name"]), i["expires"], _days(i["days_left"]),
             red("renew") if i["needs_renew"] else hl("ok"),
             "%d days" % i["threshold"]]
            for i in report["items"]]
    print(table(rows, ["TYPE", "NAME", "EXPIRES", "DAYS", "STATE", "THRESHOLD"]))
    print()
    print("Auto-renewal timer: %s" % _flag(report["timer_active"], "active", "DISABLED"))
    if report["problems"]:
        for problem in report["problems"]:
            warn("• %s" % problem)
    if report["action_needed"]:
        info("Some items are due for renewal — run: ovpnctl pki renew")
    else:
        ok("All certificates are fine.")
    return 0


def cmd_pki_renew(args) -> int:
    cfg = cfgmod.load()
    actions = renew_mod.run(cfg, force=args.force, quiet=args.quiet)
    if args.quiet:
        return 0
    done = []
    if actions["ca"]:
        done.append("CA")
    if actions["server"]:
        done.append("server certificate")
    if actions["crl"]:
        done.append("CRL")
    if actions["clients"]:
        done.append("clients: %s" % ", ".join(actions["clients"]))
    if done:
        ok("Renewed: %s." % "; ".join(done))
        if actions["profiles"]:
            info("Profiles regenerated: %s" % ", ".join(actions["profiles"]))
        if actions["restarted"]:
            info("OpenVPN service restarted.")
    else:
        ok("No renewal needed — all expiry dates are fine.")
    return 0


def cmd_pki_info(args) -> int:
    cfg = cfgmod.load()
    print(bold("CA"))
    print("  subject:     %s" % pki.subject_of(pki.CA_CRT))
    print("  serial:      %s" % pki.serial_of(pki.CA_CRT))
    print("  expires:     %s (%s days)" % (pki.not_after(pki.CA_CRT).strftime("%Y-%m-%d"),
                                          _days(pki.days_left(pki.CA_CRT))))
    print("  fingerprint: %s" % pki.fingerprint(pki.CA_CRT))
    server_crt = pki.cert_path(pki.SERVER_NAME)
    print(bold("Server certificate"))
    print("  expires:     %s (%s days)" % (pki.not_after(server_crt).strftime("%Y-%m-%d"),
                                          _days(pki.days_left(server_crt))))
    print(bold("CRL"))
    print("  expires:     %s (%s days)" % (pki.crl_next_update().strftime("%Y-%m-%d"),
                                          _days(pki.crl_days_left())))
    print(bold("Renewal policy"))
    print("  CA: %d days before | server: %d days before | clients: %d days before | CRL: %d days before"
          % (cfg["renew_ca_before"], cfg["renew_server_before"],
             cfg["renew_client_before"], cfg["renew_crl_before"]))
    print("  Client auto-renewal: %s" % _flag(cfg["auto_renew_clients"], "enabled", "disabled"))
    return 0


def cmd_backup(args) -> int:
    cfgmod.load()
    archive = provision.backup(args.output)
    ok("Backup: %s" % archive)
    print(dim("Restore: extract the archive into /etc/ovpnctl and run 'ovpnctl server rebuild'"))
    return 0


def cmd_uninstall(args) -> int:
    if not args.yes and not ask_yes_no("Remove the OpenVPN configuration and ovpnctl?", False):
        return 1
    provision.uninstall(keep_pki=args.keep_pki, purge_packages=args.purge)
    return 0


def cmd_update(args) -> int:
    """Обновление кода ovpnctl из GitHub; пакеты, PKI и клиенты не трогаются."""
    if args.finish:
        # сюда приходит уже новый код — перегенерировать конфиги по своим шаблонам
        for item in update_mod.finish():
            print("* %s" % item)
        return 0

    result = update_mod.run(repo=args.repo, branch=args.branch, local=args.source,
                            check_only=args.check, force=args.force)
    current, latest = result["current"], result["latest"]
    print("  Installed: %s (build %s)" % (hl(current["version"]), hl(current["build"])))
    print("  Available: %s (build %s)" % (hl(latest["version"]), hl(latest["build"])))
    if not result["updated"]:
        if latest["build"] == current["build"]:
            ok("Nothing to update — the latest version is installed.")
        else:
            info("An update is available — install it: ovpnctl update")
        return 0

    ok("ovpnctl updated: %s → %s (build %s → %s)."
       % (current["version"], latest["version"], current["build"], latest["build"]))
    if result["changed"]:
        info("Server files updated: %s — OpenVPN restarted, clients will reconnect."
             % ", ".join(result["changed"]))
    elif cfgmod.config_exists():
        info("Server configuration unchanged, connections were not interrupted.")
    return 0


def cmd_doctor(args) -> int:
    """Самодиагностика: зависимости, служба, сеть, PKI."""
    from .system import verify_dependencies

    problems = []
    try:
        facts = verify_dependencies(install=False)
        ok("Dependencies: OpenVPN %s, OpenSSL %s" % (facts["openvpn"], facts["openssl"]))
    except OvpnError as exc:
        problems.append(str(exc))
        err("Dependencies: %s" % exc)

    cfg = cfgmod.load()
    for name, path in (("server config", cfgmod.server_conf_path()),
                       ("CA", pki.CA_CRT), ("server certificate", pki.cert_path(pki.SERVER_NAME)),
                       ("CRL", pki.CRL), ("tls-crypt key", pki.TC_KEY)):
        if os.path.exists(path):
            ok("%s: %s" % (name, path))
        else:
            problems.append("missing %s (%s)" % (name, path))
            err("missing %s: %s" % (name, path))

    if service_active(cfgmod.SERVICE):
        ok("Service %s is running" % cfgmod.SERVICE)
    else:
        problems.append("service %s is not running" % cfgmod.SERVICE)
        err("Service %s is not running (journalctl -u %s -n 50)" % (cfgmod.SERVICE, cfgmod.SERVICE))

    for timer, title in ((cfgmod.RENEW_TIMER, "Auto-renewal"), (cfgmod.TRAFFIC_TIMER, "Traffic accounting")):
        if service_active(timer):
            ok("%s timer is active" % title)
        else:
            problems.append("timer %s is disabled" % timer)
            err("Timer %s is disabled — enable it: systemctl enable --now %s" % (timer, timer))

    forward = "0"
    try:
        forward = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    except OSError:
        pass
    if forward == "1":
        ok("IP forwarding is enabled")
    else:
        problems.append("net.ipv4.ip_forward = 0")
        err("IP forwarding is disabled — 'ovpnctl server rebuild' will fix it")

    nat = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", cfgmod.network_cidr(cfg),
               "-o", cfg["nic"], "-j", "MASQUERADE"], check=False)
    if nat.returncode == 0:
        ok("NAT rule is in place")
    else:
        problems.append("no MASQUERADE rule for %s" % cfgmod.network_cidr(cfg))
        err("No NAT rule — 'systemctl restart %s'" % cfgmod.FIREWALL_UNIT)

    report = renew_mod.check(cfg)
    for item in report["items"]:
        if item["needs_renew"]:
            warn("Needs renewal: %s %s (%s days left)"
                 % (item["kind"], item["name"], item["days_left"]))

    print()
    if problems:
        err("Problems found: %d" % len(problems))
        return 1
    ok("No problems found.")
    return 0


# --------------------------------------------------------------------------- #
# Интерактивное меню
# --------------------------------------------------------------------------- #
class _Args(object):
    """Лёгкая замена argparse.Namespace для вызова команд из меню."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


MENU_SECTIONS = [
    [
        (1, "Add Client"),
        (2, "Client List"),
        (3, "Online Clients"),
        (4, "Traffic"),
        (5, "Renew Client Certificate"),
        (6, "Delete Client"),
        (7, "Assign Static IP"),
    ],
    [
        (8, "Server Status"),
        (9, "Restart OpenVPN"),
        (10, "Server Logs"),
        (11, "Rebuild Configuration"),
        (12, "Change Endpoint, Port or DNS"),
    ],
    [
        (13, "Check Certificate Expiry"),
        (14, "Renew Due Certificates"),
    ],
    [
        (15, "Diagnostics (doctor)"),
        (16, "Backup"),
        (17, "Open VPN Port in ufw"),
        (18, "Update ovpnctl"),
    ],
]

MENU_TITLE = "ovpnctl — OpenVPN Management Script"
MENU_WIDTH = 46
MENU_MAX = max(num for section in MENU_SECTIONS for num, _ in section)


def _box_row(content: str = "") -> str:
    """Строка внутри рамки: рамка белая, содержимое уже раскрашено."""
    return "%s│%s  %s%s│%s" % (C_WHITE, C_RESET, pad(content, MENU_WIDTH - 2), C_WHITE, C_RESET)


def _item(num: int, text: str) -> str:
    return "%s%s%s %s%s%s" % (C_GREEN, ("%d." % num).rjust(3), C_RESET, C_WHITE, text, C_RESET)


def render_menu() -> str:
    edge = "─" * MENU_WIDTH
    lines = ["%s╔%s╗%s" % (C_WHITE, edge, C_RESET)]
    lines.append(_box_row(" %s%s%s" % (C_GREEN, MENU_TITLE, C_RESET)))
    lines.append(_box_row(_item(0, "Exit")))
    for section in MENU_SECTIONS:
        lines.append("%s│%s│%s" % (C_WHITE, edge, C_RESET))
        for num, text in section:
            lines.append(_box_row(_item(num, text)))
    lines.append("%s╚%s╝%s" % (C_WHITE, edge, C_RESET))
    return "\n".join(lines)


def render_state(cfg: dict) -> str:
    """Сводка состояния под меню — аналог строк Panel state у 3x-ui."""
    def line(label, value):
        return "%s%s:%s %s" % (C_WHITE, label, C_RESET, value)

    online = len(srv.online_clients())
    total = len([c for c in clients.listing(cfg) if c["status"] != "revoked"])
    return "\n".join([
        line("OpenVPN state", _flag(service_active(cfgmod.SERVICE), "Running", "Not running")),
        line("Start automatically", _flag(service_enabled(cfgmod.SERVICE), "Yes", "No")),
        line("Auto-renewal", _flag(service_active(cfgmod.RENEW_TIMER), "Active", "Inactive")),
        line("Endpoint", hl("%s:%d/%s" % (cfg["endpoint"], cfg["port"], cfg["proto"]))),
        line("Clients", "%s, online: %s" % (hl(total), hl(online))),
    ])


def menu(args) -> int:
    if not sys.stdin.isatty():
        raise OvpnError("the interactive menu requires a terminal — use subcommands "
                        "(ovpnctl --help).")
    if not cfgmod.config_exists():
        raise OvpnError("server is not set up — run: ovpnctl setup")

    while True:
        cfg = cfgmod.load()
        clear_screen()
        print(render_menu())
        print()
        print(render_state(cfg))
        print()
        try:
            choice = input("%sPlease enter your selection [0-%d]:%s " % (C_WHITE, MENU_MAX, C_RESET)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "0":
            return 0
        if not choice:
            continue

        # результат команды остаётся на экране, меню возвращается по Enter
        print()
        handler = MENU_ACTIONS.get(choice)
        if handler is None:
            warn("No such option: %s" % choice)
        else:
            try:
                handler(cfg)
            except BackToMenu:
                continue                # пользователь сам отказался — сразу в меню
            except OvpnError as exc:
                err("Error: %s" % exc)
            except KeyboardInterrupt:
                print()
        pause()


CANCEL_WORDS = ("", "0", "q", "b", "back", "exit", "cancel")


class BackToMenu(Exception):
    """Отказ от действия (Enter или 0 в запросе) — меню рисуется сразу, без паузы."""


def _ask_or_back(prompt: str, default=None, cast=None):
    """Запрос значения с возможностью вернуться в меню (Enter или 0)."""
    hint = " [%s]" % default if default not in (None, "") else ""
    try:
        raw = input("%s%s (Enter or 0 — back): " % (prompt, hint)).strip()
    except EOFError:
        raise BackToMenu()
    if raw.lower() in CANCEL_WORDS:
        if raw == "" and default not in (None, ""):
            raw = str(default)
        else:
            raise BackToMenu()
    if cast:
        try:
            return cast(raw)
        except (ValueError, OvpnError) as exc:
            err("  %s" % exc)
            return None
    return raw


def _pick_client(cfg: dict, include_revoked: bool = False, prompt: str = "Client number or name",
                 show_list: bool = True):
    """Выбор клиента: можно ввести номер из списка или имя. Enter — вернуться."""
    rows = [r for r in clients.listing(cfg)
            if include_revoked or r["status"] != "revoked"]
    if not rows:
        info("No clients yet. Create the first one with option 1.")
        return None
    if show_list:
        print(bold("Clients:"))
        for index, row in enumerate(rows, 1):
            print("  %s %s %s expires %s"
                  % (hl(("%d." % index).rjust(3)), pad(hl(row["name"]), 24),
                     pad(_status(row["status"]), 8), row["expires"]))
        print()
    raw = _ask_or_back(prompt)
    if raw is None:
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(rows):
        return rows[int(raw) - 1]["name"]
    if any(row["name"] == raw for row in rows):
        return raw
    warn("Client '%s' not found." % raw)
    return None


def _menu_client_add(cfg: dict) -> None:
    name = _ask_or_back("New client name")
    if name is None:
        return
    cmd_client_add(_Args(name=name, days=None, ip=None, print_profile=False))
    if ask_yes_no("Print the profile to the screen?", False):
        print()
        cmd_client_show(_Args(name=name, path=False))


def _menu_client_list(cfg: dict) -> None:
    """Список клиентов, а следом — возможность вывести чей-нибудь .ovpn."""
    cmd_client_list(_Args(json=False, numbered=True))
    if not clients.listing(cfg):
        return
    print()
    name = _pick_client(cfg, prompt="Print a client's .ovpn — number or name", show_list=False,
                        include_revoked=True)
    if name is None:
        return
    print()
    cmd_client_show(_Args(name=name, path=False))


def _menu_traffic(cfg: dict) -> None:
    """Общий трафик всех клиентов, затем — по периодам для выбранного."""
    rows = _traffic_rows(cfg)
    if not rows:
        info("No clients yet. Create the first one with option 1.")
        return
    print(bold("Client traffic, all time"))
    print(_traffic_table(rows, numbered=True))
    print(dim("  Received/sent — from the server's side."))
    print()
    raw = _ask_or_back("Traffic by period — client number or name")
    names = [r["name"] for r in rows]
    if raw.isdigit() and 1 <= int(raw) <= len(names):
        raw = names[int(raw) - 1]
    if raw not in names:
        warn("Client '%s' not found." % raw)
        return
    print()
    cmd_traffic(_Args(name=raw, json=False, collect=False))


def _menu_client_action(cfg: dict, action) -> None:
    name = _pick_client(cfg)
    if name is None:
        return
    action(name)


def _menu_client_ip(cfg: dict) -> None:
    name = _pick_client(cfg)
    if name is None:
        return
    address = _ask_or_back("Address in subnet %s" % cfgmod.network_cidr(cfg))
    if address is None:
        return
    cmd_client_ip(_Args(name=name, address=address))


def _menu_change_settings(cfg: dict) -> None:
    endpoint = ask_optional("Server address (domain or IP)", cfg["endpoint"])
    port = ask_optional("Port", cfg["port"])
    proto = ask_optional("Protocol (udp/tcp)", cfg["proto"])
    dns = ask_optional("DNS, comma-separated", ", ".join(cfg["dns"]))
    if not any([endpoint, port, proto, dns]):
        raise BackToMenu()
    cmd_set(_Args(endpoint=endpoint, port=int(port) if port else None,
                  proto=proto, dns=dns, nic=None))


def _menu_ufw(cfg: dict) -> None:
    install_ufw = False
    if not srv.ufw_available():
        warn("ufw is not installed.")
        install_ufw = ask_yes_no("Install ufw now?", True)
        if not install_ufw:
            raise BackToMenu()
    with_ssh = ask_yes_no("Also allow SSH (so you don't lose access)?", True)
    cmd_ufw(_Args(install=install_ufw, remove=False, ssh=with_ssh))


def _menu_update(cfg: dict) -> None:
    result = update_mod.run()
    current, latest = result["current"], result["latest"]
    if not result["updated"]:
        ok("Nothing to update — the latest version %s (build %s) is installed."
           % (current["version"], current["build"]))
        return
    ok("ovpnctl updated: %s → %s (build %s → %s)."
       % (current["version"], latest["version"], current["build"], latest["build"]))
    if result["changed"]:
        info("Server files updated: %s — OpenVPN restarted." % ", ".join(result["changed"]))
    # в памяти этого процесса старый код — перезапускаем меню уже новым
    pause("Press Enter to open the menu of the new version")
    os.execv(sys.executable, [sys.executable, "-m", "ovpnctl"])


MENU_ACTIONS = {
    "1": _menu_client_add,
    "2": _menu_client_list,
    "3": lambda cfg: cmd_online(_Args(json=False)),
    "4": _menu_traffic,
    "5": lambda cfg: _menu_client_action(
        cfg, lambda name: cmd_client_renew(_Args(name=name, days=None, new_key=False))),
    "6": lambda cfg: _menu_client_action(
        cfg, lambda name: cmd_client_delete(_Args(name=name, yes=False))),
    "7": _menu_client_ip,
    "8": lambda cfg: cmd_status(_Args(json=False)),
    "9": lambda cfg: cmd_server(_Args(action="restart", lines=50)),
    "10": lambda cfg: cmd_server(_Args(action="logs", lines=50)),
    "11": lambda cfg: cmd_server(_Args(action="rebuild", lines=50)),
    "12": _menu_change_settings,
    "13": lambda cfg: cmd_pki_check(_Args(json=False)),
    "14": lambda cfg: cmd_pki_renew(_Args(force=False, quiet=False)),
    "15": lambda cfg: cmd_doctor(_Args()),
    "16": lambda cfg: cmd_backup(_Args(output=None)),
    "17": _menu_ufw,
    "18": _menu_update,
}


# --------------------------------------------------------------------------- #
# Разбор аргументов
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ovpnctl",
        description="Install and manage an OpenVPN server (Debian 10/11/12/13, Ubuntu 20.04+).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Without arguments, the interactive menu opens.",
    )
    parser.add_argument("--version", action="version", version="ovpnctl %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    # setup
    setup_parser = sub.add_parser(
        "setup", help="initial server setup (called by the installer)")
    setup_parser.set_defaults(func=provision.setup)

    # client
    client_parser = sub.add_parser("client", help="manage clients (certificates and profiles)")
    client_sub = client_parser.add_subparsers(dest="subcommand")

    add_parser = client_sub.add_parser("add", help="create a client and its .ovpn profile")
    add_parser.add_argument("name", metavar="certname", help="client name: Latin letters, digits, . _ -")
    add_parser.add_argument("--days", type=int, help="certificate lifetime in days")
    add_parser.add_argument("--ip", help="pin a static address in the VPN subnet")
    add_parser.add_argument("--print", dest="print_profile", action="store_true", help="print the .ovpn right away")
    add_parser.set_defaults(func=cmd_client_add)

    list_parser = client_sub.add_parser("list", help="list clients and expiry dates")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=cmd_client_list)

    show_parser = client_sub.add_parser("show", help="print a client's .ovpn to the console")
    show_parser.add_argument("name", metavar="certname")
    show_parser.add_argument("--path", action="store_true", help="show only the file path")
    show_parser.set_defaults(func=cmd_client_show)

    revoke_parser = client_sub.add_parser("revoke", help="revoke access (certificate goes to the CRL)")
    revoke_parser.add_argument("name", metavar="certname")
    revoke_parser.add_argument("-y", "--yes", action="store_true")
    revoke_parser.set_defaults(func=cmd_client_revoke)

    del_parser = client_sub.add_parser("delete", help="revoke and delete all of the client's files")
    del_parser.add_argument("name", metavar="certname")
    del_parser.add_argument("-y", "--yes", action="store_true")
    del_parser.set_defaults(func=cmd_client_delete)

    renew_parser = client_sub.add_parser("renew", help="renew a client certificate")
    renew_parser.add_argument("name", metavar="certname")
    renew_parser.add_argument("--days", type=int)
    renew_parser.add_argument("--new-key", action="store_true", help="generate a new key")
    renew_parser.set_defaults(func=cmd_client_renew)

    ip_parser = client_sub.add_parser("ip", help="pin a static address to a client")
    ip_parser.add_argument("name", metavar="certname")
    ip_parser.add_argument("address", metavar="address")
    ip_parser.set_defaults(func=cmd_client_ip)

    # status / online
    status_parser = sub.add_parser("status", help="overall server and PKI status")
    status_parser.add_argument("--json", action="store_true")
    status_parser.set_defaults(func=cmd_status)

    traffic_parser = sub.add_parser(
        "traffic", help="client traffic: all clients, or one client by period")
    traffic_parser.add_argument("name", metavar="certname", nargs="?",
                                help="client — show today/week/month/year/all time")
    traffic_parser.add_argument("--json", action="store_true")
    traffic_parser.add_argument("--collect", action="store_true", help=argparse.SUPPRESS)
    traffic_parser.set_defaults(func=cmd_traffic)

    online_parser = sub.add_parser("online", help="active connections")
    online_parser.add_argument("--json", action="store_true")
    online_parser.set_defaults(func=cmd_online)

    # server
    server_parser = sub.add_parser("server", help="manage the service and configuration")
    server_parser.add_argument("action", choices=["start", "stop", "restart", "rebuild", "config", "logs"])
    server_parser.add_argument("-n", "--lines", type=int, default=50, help="log lines")
    server_parser.set_defaults(func=cmd_server)

    # set
    set_parser = sub.add_parser("set", help="change settings (endpoint/port/protocol/DNS/interface)")
    set_parser.add_argument("--endpoint")
    set_parser.add_argument("--port", type=int)
    set_parser.add_argument("--proto", choices=["udp", "tcp"])
    set_parser.add_argument("--dns")
    set_parser.add_argument("--nic")
    set_parser.set_defaults(func=cmd_set)

    # pki
    pki_parser = sub.add_parser("pki", help="certificates and auto-renewal")
    pki_sub = pki_parser.add_subparsers(dest="subcommand")

    check_parser = pki_sub.add_parser("check", help="expiry of all certificates")
    check_parser.add_argument("--json", action="store_true")
    check_parser.set_defaults(func=cmd_pki_check)

    prenew_parser = pki_sub.add_parser("renew", help="renew everything that is due (called by the timer)")
    prenew_parser.add_argument("--force", action="store_true", help="force renewal")
    prenew_parser.add_argument("--quiet", action="store_true", help="no output (for systemd)")
    prenew_parser.set_defaults(func=cmd_pki_renew)

    pinfo_parser = pki_sub.add_parser("info", help="CA/server/CRL details")
    pinfo_parser.set_defaults(func=cmd_pki_info)

    # ufw
    ufw_parser = sub.add_parser("ufw", help="allow the VPN port in ufw")
    ufw_parser.add_argument("--install", action="store_true", help="install ufw if missing")
    ufw_parser.add_argument("--remove", action="store_true", help="remove the added rules")
    ufw_parser.add_argument("--ssh", action="store_true",
                            help="also allow sshd ports (so you don't lose access)")
    ufw_parser.set_defaults(func=cmd_ufw)

    # backup / uninstall / doctor / menu
    backup_parser = sub.add_parser("backup", help="archive of PKI, profiles and configuration")
    backup_parser.add_argument("-o", "--output", help="directory for the archive")
    backup_parser.set_defaults(func=cmd_backup)

    update_parser = sub.add_parser(
        "update", help="update ovpnctl from GitHub (without reinstalling the server)")
    update_parser.add_argument("--check", action="store_true",
                               help="only check whether a new version is available")
    update_parser.add_argument("--force", action="store_true",
                               help="reinstall the code even if the build is the same")
    update_parser.add_argument("--repo", help="repository (default: where it was installed from)")
    update_parser.add_argument("--branch", help="branch (default: master, then main)")
    update_parser.add_argument("--from", dest="source", metavar="PATH",
                               help="update from a local directory or .tar.gz")
    update_parser.add_argument("--finish", action="store_true", help=argparse.SUPPRESS)
    update_parser.set_defaults(func=cmd_update)

    doctor_parser = sub.add_parser("doctor", help="self-diagnostics of the installation")
    doctor_parser.set_defaults(func=cmd_doctor)

    uninstall_parser = sub.add_parser("uninstall", help="remove configuration and services")
    uninstall_parser.add_argument("-y", "--yes", action="store_true")
    uninstall_parser.add_argument("--keep-pki", action="store_true", help="keep PKI and profiles")
    uninstall_parser.add_argument("--purge", action="store_true", help="also remove the openvpn package")
    uninstall_parser.set_defaults(func=cmd_uninstall)

    menu_parser = sub.add_parser("menu", help="interactive menu")
    menu_parser.set_defaults(func=menu)

    return parser


def main(argv) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "func", None):
        if args.command in ("client", "pki"):
            parser.parse_args([args.command, "--help"])
            return 2
        args = argparse.Namespace(func=menu, command=None)

    try:
        if os.geteuid() != 0:
            require_root()
        return args.func(args) or 0
    except OvpnError as exc:
        err("Error: %s" % exc)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
