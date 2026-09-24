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
    C_CYAN,
    C_GREEN,
    C_RED,
    C_RESET,
    OvpnError,
    ask_optional,
    ask_yes_no,
    bold,
    clear_screen,
    dim,
    err,
    human_bytes,
    info,
    ok,
    pause,
    require_root,
    table,
    warn,
    write_file,
)


# --------------------------------------------------------------------------- #
# Команды: клиенты
# --------------------------------------------------------------------------- #
def cmd_client_add(args) -> int:
    cfg = cfgmod.load()
    result = clients.add(args.name, cfg, days=args.days, static_ip=args.ip)
    profile = export_profile(args.name, cfg)
    ok("Клиент '%s' создан (сертификат действует до %s)." % (args.name, result["expires"][:10]))
    print("  Профиль: %s" % profile)
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


def cmd_client_list(args) -> int:
    cfg = cfgmod.load()
    rows = clients.listing(cfg)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    if not rows:
        info("Клиентов пока нет. Создать: ovpnctl client add <certname>")
        return 0
    printable = [
        [r["name"], r["status"], r["expires"],
         "—" if r["days_left"] is None else str(r["days_left"]),
         r["address"] or "—", human_bytes(r["traffic_total"]), r["created"]]
        for r in rows
    ]
    print(table(printable, ["ИМЯ", "СТАТУС", "ДО", "ДНЕЙ", "АДРЕС", "ТРАФИК", "СОЗДАН"]))
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
    if not args.yes and not ask_yes_no("Отозвать клиента '%s'? Доступ пропадёт сразу." % args.name, False):
        return 1
    clients.revoke(args.name, cfg)
    ok("Клиент '%s' отозван, CRL обновлён, активная сессия разорвана." % args.name)
    return 0


def cmd_client_delete(args) -> int:
    cfg = cfgmod.load()
    if not args.yes and not ask_yes_no("Удалить клиента '%s' полностью?" % args.name, False):
        return 1
    clients.delete(args.name, cfg)
    ok("Клиент '%s' удалён." % args.name)
    return 0


def cmd_client_renew(args) -> int:
    cfg = cfgmod.load()
    result = clients.renew(args.name, cfg, days=args.days, new_key=args.new_key)
    ok("Сертификат '%s' продлён до %s. Обновлённый профиль: %s"
       % (args.name, result["expires"][:10], result["profile"]))
    warn("Клиенту нужно заново импортировать .ovpn (старый работает до истечения прежнего срока).")
    return 0


def cmd_client_ip(args) -> int:
    cfg = cfgmod.load()
    path = clients.set_static_ip(args.name, args.address, cfg)
    ok("Клиенту '%s' закреплён адрес %s (%s). Перезапуск не нужен — применится при следующем подключении."
       % (args.name, args.address, path))
    return 0


# --------------------------------------------------------------------------- #
# Команды: статус и сервер
# --------------------------------------------------------------------------- #
def cmd_status(args) -> int:
    cfg = cfgmod.load()
    facts = system_facts()
    summary = srv.status_summary(cfg)
    report = renew_mod.check(cfg)
    if args.json:
        print(json.dumps({"config": cfg, "system": facts, "status": summary, "pki": report},
                         indent=2, ensure_ascii=False))
        return 0

    state = ok if summary["active"] else err
    print(bold("Сервер"))
    state("  OpenVPN:        %s" % ("работает" if summary["active"] else "ОСТАНОВЛЕН"))
    print("  Точка входа:    %s" % summary["endpoint"])
    print("  Подсеть:        %s (интерфейс %s)" % (cfgmod.network_cidr(cfg), cfg["nic"]))
    print("  DNS клиентам:   %s" % ", ".join(cfg["dns"]))
    print("  Файрвол:        %s%s"
          % ("активен" if summary["firewall"] else "НЕ активен",
             ", ufw настроен" if cfg.get("ufw_configured") else
             (", ufw активен без правил ovpnctl" if srv.ufw_active() else "")))
    print("  Автопродление:  %s" % ("таймер активен" if summary["timer"] else "ТАЙМЕР ВЫКЛЮЧЕН"))
    print("  Система:        %s, OpenVPN %s, OpenSSL %s"
          % (facts["distro"], facts["openvpn"], facts["openssl"]))

    print()
    print(bold("Сертификаты"))
    rows = []
    for item in report["items"]:
        if item["kind"] == "client":
            continue
        left = "—" if item["days_left"] is None else str(item["days_left"])
        mark = "продлить" if item["needs_renew"] else "ок"
        rows.append([item["name"], item["expires"], left, mark])
    print(table(rows, ["ОБЪЕКТ", "ДО", "ДНЕЙ", "СОСТОЯНИЕ"]))

    online = srv.online_clients()
    all_clients = clients.listing(cfg)
    active = [c for c in all_clients if c["status"] != "отозван"]
    print()
    print(bold("Клиенты"))
    print("  Всего: %d, активных: %d, онлайн: %d" % (len(all_clients), len(active), len(online)))
    if all_clients:
        shown = all_clients[:20]
        rows = [[c["name"], c["status"], c["expires"],
                 "—" if c["days_left"] is None else str(c["days_left"]),
                 c["address"] or "—", human_bytes(c["traffic_total"])] for c in shown]
        print()
        print(table(rows, ["ИМЯ", "СТАТУС", "ДО", "ДНЕЙ", "АДРЕС", "ТРАФИК"]))
        if len(all_clients) > len(shown):
            print(dim("  …ещё %d — смотрите 'ovpnctl client list'" % (len(all_clients) - len(shown))))
    if online:
        print()
        print(bold("Подключены сейчас"))
        for client in online:
            print("   • %-20s %-16s %s ↓ / %s ↑  c %s"
                  % (client["name"], client["virtual_address"],
                     human_bytes(client["bytes_received"]), human_bytes(client["bytes_sent"]),
                     client["connected_since"]))
    if report["problems"]:
        print()
        warn("Замечания:")
        for problem in report["problems"]:
            warn("  • %s" % problem)
    return 0


def cmd_online(args) -> int:
    online = srv.online_clients()
    if args.json:
        print(json.dumps(online, indent=2, ensure_ascii=False))
        return 0
    if not online:
        info("Нет активных подключений.")
        return 0
    rows = [[c["name"], c["virtual_address"], c["real_address"],
             human_bytes(c["bytes_received"]), human_bytes(c["bytes_sent"]), c["connected_since"]]
            for c in online]
    print(table(rows, ["ИМЯ", "АДРЕС В VPN", "ОТКУДА", "ПРИНЯТО", "ОТПРАВЛЕНО", "ПОДКЛЮЧЁН С"]))
    return 0


def cmd_server(args) -> int:
    cfg = cfgmod.load()
    action = args.action
    if action == "restart":
        srv.restart()
        ok("Служба перезапущена.")
    elif action == "start":
        systemctl("start", cfgmod.SERVICE)
        ok("Служба запущена.")
    elif action == "stop":
        systemctl("stop", cfgmod.SERVICE)
        ok("Служба остановлена.")
    elif action == "rebuild":
        srv.deploy_pki_to_server(cfg)
        srv.write_server_conf(cfg)
        srv.setup_networking(cfg)
        provision.write_units()
        systemctl("restart", cfgmod.FIREWALL_UNIT, check=False)
        srv.restart()
        ok("Конфигурация пересобрана и применена.")
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
        raise OvpnError("не указано ни одного параметра (см. ovpnctl set --help).")

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
    ok("Изменено: %s. Перегенерировано профилей: %d." % (", ".join(changed), len(updated)))
    warn("Клиентам нужно забрать обновлённые .ovpn (изменились параметры подключения).")
    return 0


# --------------------------------------------------------------------------- #
# Команды: PKI
# --------------------------------------------------------------------------- #
def cmd_ufw(args) -> int:
    cfg = cfgmod.load()
    if args.remove:
        steps = srv.setup_ufw(cfg, remove=True)
        ok("Правила ufw для OpenVPN удалены.")
    else:
        steps = srv.setup_ufw(cfg, install=args.install, with_ssh=args.ssh)
        ok("В ufw открыт порт OpenVPN: %d/%s." % (cfg["port"], cfg["proto"]))
    for step in steps:
        print("  • %s" % step)
    if srv.ufw_available():
        print()
        print(bold("Текущее состояние ufw"))
        run(["ufw", "status", "verbose"], capture=False, check=False)
    return 0


def cmd_pki_check(args) -> int:
    cfg = cfgmod.load()
    report = renew_mod.check(cfg)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    rows = [[i["kind"], i["name"], i["expires"],
             "—" if i["days_left"] is None else str(i["days_left"]),
             "продлить" if i["needs_renew"] else "ок",
             "%d дн." % i["threshold"]]
            for i in report["items"]]
    print(table(rows, ["ТИП", "ИМЯ", "ДО", "ДНЕЙ", "СОСТОЯНИЕ", "ПОРОГ"]))
    print()
    print("Таймер автопродления: %s" % ("активен" if report["timer_active"] else "ВЫКЛЮЧЕН"))
    if report["problems"]:
        for problem in report["problems"]:
            warn("• %s" % problem)
    if report["action_needed"]:
        info("Есть объекты для продления — выполните: ovpnctl pki renew")
    else:
        ok("Все сертификаты в порядке.")
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
        done.append("сертификат сервера")
    if actions["crl"]:
        done.append("CRL")
    if actions["clients"]:
        done.append("клиенты: %s" % ", ".join(actions["clients"]))
    if done:
        ok("Продлено: %s." % "; ".join(done))
        if actions["profiles"]:
            info("Перегенерированы профили: %s" % ", ".join(actions["profiles"]))
        if actions["restarted"]:
            info("Служба OpenVPN перезапущена.")
    else:
        ok("Продление не требуется — все сроки в норме.")
    return 0


def cmd_pki_info(args) -> int:
    cfg = cfgmod.load()
    print(bold("CA"))
    print("  subject:  %s" % pki.subject_of(pki.CA_CRT))
    print("  serial:   %s" % pki.serial_of(pki.CA_CRT))
    print("  до:       %s (%d дн.)" % (pki.not_after(pki.CA_CRT).strftime("%Y-%m-%d"),
                                       pki.days_left(pki.CA_CRT)))
    print("  отпечаток:%s" % pki.fingerprint(pki.CA_CRT))
    server_crt = pki.cert_path(pki.SERVER_NAME)
    print(bold("Сертификат сервера"))
    print("  до:       %s (%d дн.)" % (pki.not_after(server_crt).strftime("%Y-%m-%d"),
                                       pki.days_left(server_crt)))
    print(bold("CRL"))
    print("  до:       %s (%d дн.)" % (pki.crl_next_update().strftime("%Y-%m-%d"),
                                       pki.crl_days_left()))
    print(bold("Политика продления"))
    print("  CA: за %d дн. | сервер: за %d дн. | клиенты: за %d дн. | CRL: за %d дн."
          % (cfg["renew_ca_before"], cfg["renew_server_before"],
             cfg["renew_client_before"], cfg["renew_crl_before"]))
    print("  Автопродление клиентов: %s" % ("включено" if cfg["auto_renew_clients"] else "выключено"))
    return 0


def cmd_backup(args) -> int:
    cfgmod.load()
    archive = provision.backup(args.output)
    ok("Резервная копия: %s" % archive)
    print(dim("Восстановление: распакуйте архив в /etc/ovpnctl и выполните 'ovpnctl server rebuild'"))
    return 0


def cmd_uninstall(args) -> int:
    if not args.yes and not ask_yes_no("Удалить OpenVPN-конфигурацию и ovpnctl?", False):
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
    print("  Установлена: %s (сборка %s)" % (current["version"], current["build"]))
    print("  Доступна:    %s (сборка %s)" % (latest["version"], latest["build"]))
    if not result["updated"]:
        if latest["build"] == current["build"]:
            ok("Обновлять нечего — установлена актуальная версия.")
        else:
            info("Есть обновление — установить: ovpnctl update")
        return 0

    ok("ovpnctl обновлён: %s → %s (сборка %s → %s)."
       % (current["version"], latest["version"], current["build"], latest["build"]))
    if result["changed"]:
        info("Обновлены файлы сервера: %s — OpenVPN перезапущен, клиенты переподключатся."
             % ", ".join(result["changed"]))
    elif cfgmod.config_exists():
        info("Конфигурация сервера не изменилась, подключения не прерывались.")
    return 0


def cmd_doctor(args) -> int:
    """Самодиагностика: зависимости, служба, сеть, PKI."""
    from .system import verify_dependencies

    problems = []
    try:
        facts = verify_dependencies(install=False)
        ok("Зависимости: OpenVPN %s, OpenSSL %s" % (facts["openvpn"], facts["openssl"]))
    except OvpnError as exc:
        problems.append(str(exc))
        err("Зависимости: %s" % exc)

    cfg = cfgmod.load()
    for name, path in (("конфиг сервера", cfgmod.server_conf_path()),
                       ("CA", pki.CA_CRT), ("сертификат сервера", pki.cert_path(pki.SERVER_NAME)),
                       ("CRL", pki.CRL), ("ключ tls-crypt", pki.TC_KEY)):
        if os.path.exists(path):
            ok("%s: %s" % (name, path))
        else:
            problems.append("отсутствует %s (%s)" % (name, path))
            err("отсутствует %s: %s" % (name, path))

    if service_active(cfgmod.SERVICE):
        ok("Служба %s работает" % cfgmod.SERVICE)
    else:
        problems.append("служба %s не запущена" % cfgmod.SERVICE)
        err("Служба %s не запущена (journalctl -u %s -n 50)" % (cfgmod.SERVICE, cfgmod.SERVICE))

    if service_active(cfgmod.RENEW_TIMER):
        ok("Таймер автопродления активен")
    else:
        problems.append("таймер %s выключен" % cfgmod.RENEW_TIMER)
        err("Таймер %s выключен — включить: systemctl enable --now %s"
            % (cfgmod.RENEW_TIMER, cfgmod.RENEW_TIMER))

    forward = "0"
    try:
        forward = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    except OSError:
        pass
    if forward == "1":
        ok("IP-форвардинг включён")
    else:
        problems.append("net.ipv4.ip_forward = 0")
        err("IP-форвардинг выключен — 'ovpnctl server rebuild' исправит")

    nat = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", cfgmod.network_cidr(cfg),
               "-o", cfg["nic"], "-j", "MASQUERADE"], check=False)
    if nat.returncode == 0:
        ok("Правило NAT на месте")
    else:
        problems.append("нет правила MASQUERADE для %s" % cfgmod.network_cidr(cfg))
        err("Нет правила NAT — 'systemctl restart %s'" % cfgmod.FIREWALL_UNIT)

    report = renew_mod.check(cfg)
    for item in report["items"]:
        if item["needs_renew"]:
            warn("Требует продления: %s %s (осталось %s дн.)"
                 % (item["kind"], item["name"], item["days_left"]))

    print()
    if problems:
        err("Найдено проблем: %d" % len(problems))
        return 1
    ok("Проблем не найдено.")
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
        (1, "Добавить клиента"),
        (2, "Список клиентов и выгрузка .ovpn"),
        (3, "Клиенты онлайн"),
        (4, "Продлить сертификат клиента"),
        (5, "Удалить клиента"),
        (6, "Закрепить IP за клиентом"),
    ],
    [
        (7, "Статус сервера"),
        (8, "Перезапустить OpenVPN"),
        (9, "Логи сервера"),
        (10, "Пересобрать конфигурацию"),
        (11, "Изменить адрес, порт или DNS"),
    ],
    [
        (12, "Проверить сроки сертификатов"),
        (13, "Продлить всё, чему пора"),
    ],
    [
        (14, "Диагностика (doctor)"),
        (15, "Резервная копия"),
        (16, "Открыть порт VPN в ufw"),
        (17, "Обновить ovpnctl"),
    ],
]

MENU_TITLE = "ovpnctl — управление OpenVPN"
MENU_WIDTH = 52
MENU_MAX = max(num for section in MENU_SECTIONS for num, _ in section)


def _box_row(text: str) -> str:
    return "%s│ %s │%s" % (C_GREEN, text.ljust(MENU_WIDTH), C_RESET)


def render_menu() -> str:
    edge = "─" * (MENU_WIDTH + 2)
    lines = ["%s┌%s┐%s" % (C_GREEN, edge, C_RESET)]
    lines.append(_box_row("  " + MENU_TITLE))
    lines.append(_box_row("  0. Выход"))
    for section in MENU_SECTIONS:
        lines.append("%s├%s┤%s" % (C_GREEN, edge, C_RESET))
        for num, text in section:
            lines.append(_box_row("%s. %s" % (str(num).rjust(3), text)))
    lines.append("%s└%s┘%s" % (C_GREEN, edge, C_RESET))
    return "\n".join(lines)


def render_state(cfg: dict) -> str:
    """Сводка состояния под меню — аналог строк Panel state у 3x-ui."""
    def mark(flag, yes="работает", no="остановлен"):
        return "%s%s%s" % (C_GREEN if flag else C_RED, yes if flag else no, C_RESET)

    online = len(srv.online_clients())
    total = len([c for c in clients.listing(cfg) if c["status"] != "отозван"])
    return "\n".join([
        "Служба OpenVPN: %s" % mark(service_active(cfgmod.SERVICE)),
        "Автозапуск: %s" % mark(service_enabled(cfgmod.SERVICE), "включён", "выключен"),
        "Автопродление: %s" % mark(service_active(cfgmod.RENEW_TIMER), "активно", "выключено"),
        "Точка входа: %s%s:%d/%s%s" % (C_GREEN, cfg["endpoint"], cfg["port"], cfg["proto"], C_RESET),
        "Клиентов: %d, онлайн: %d" % (total, online),
    ])


def menu(args) -> int:
    if not sys.stdin.isatty():
        raise OvpnError("интерактивное меню требует терминал — используйте подкоманды "
                        "(ovpnctl --help).")
    if not cfgmod.config_exists():
        raise OvpnError("сервер не настроен — выполните: ovpnctl setup")

    while True:
        cfg = cfgmod.load()
        clear_screen()
        print(render_menu())
        print()
        print(render_state(cfg))
        print()
        try:
            choice = input("Выберите пункт [0-%d] (0 — выход): " % MENU_MAX).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "0":
            return 0

        # результат команды остаётся на экране, меню возвращается по Enter
        print()
        handler = MENU_ACTIONS.get(choice)
        if handler is None:
            warn("Нет такого пункта: %s" % (choice or "—"))
        else:
            try:
                handler(cfg)
            except OvpnError as exc:
                err("Ошибка: %s" % exc)
            except KeyboardInterrupt:
                print()
        pause()


CANCEL_WORDS = ("", "0", "q", "b", "назад", "выход", "отмена")


def _ask_or_back(prompt: str, default=None, cast=None):
    """Запрос значения с возможностью вернуться в меню (Enter или 0)."""
    hint = " [%s]" % default if default not in (None, "") else ""
    try:
        raw = input("%s%s (Enter или 0 — вернуться): " % (prompt, hint)).strip()
    except EOFError:
        return None
    if raw.lower() in CANCEL_WORDS:
        if raw == "" and default not in (None, ""):
            raw = str(default)
        else:
            info("Возврат в меню.")
            return None
    if cast:
        try:
            return cast(raw)
        except (ValueError, OvpnError) as exc:
            err("  %s" % exc)
            return None
    return raw


def _pick_client(cfg: dict, include_revoked: bool = False, prompt: str = "Номер или имя клиента",
                 show_list: bool = True):
    """Выбор клиента: можно ввести номер из списка или имя. Enter — вернуться."""
    rows = [r for r in clients.listing(cfg)
            if include_revoked or r["status"] != "отозван"]
    if not rows:
        info("Клиентов пока нет. Создайте первого пунктом 1.")
        return None
    if show_list:
        print(bold("Клиенты:"))
        for index, row in enumerate(rows, 1):
            print("  %2d) %-24s %-8s до %s" % (index, row["name"], row["status"], row["expires"]))
        print()
    raw = _ask_or_back(prompt)
    if raw is None:
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(rows):
        return rows[int(raw) - 1]["name"]
    if any(row["name"] == raw for row in rows):
        return raw
    warn("Клиент '%s' не найден." % raw)
    return None


def _menu_client_add(cfg: dict) -> None:
    name = _ask_or_back("Имя нового клиента")
    if name is None:
        return
    cmd_client_add(_Args(name=name, days=None, ip=None, print_profile=False))
    if ask_yes_no("Вывести профиль на экран?", False):
        print()
        cmd_client_show(_Args(name=name, path=False))


def _menu_client_list(cfg: dict) -> None:
    """Список клиентов, а следом — возможность вывести чей-нибудь .ovpn."""
    cmd_client_list(_Args(json=False))
    if not clients.listing(cfg):
        return
    print()
    name = _pick_client(cfg, prompt="Вывести .ovpn клиента — номер или имя", show_list=False)
    if name is None:
        return
    print()
    cmd_client_show(_Args(name=name, path=False))


def _menu_client_action(cfg: dict, action) -> None:
    name = _pick_client(cfg)
    if name is None:
        return
    action(name)


def _menu_client_ip(cfg: dict) -> None:
    name = _pick_client(cfg)
    if name is None:
        return
    address = _ask_or_back("Адрес в подсети %s" % cfgmod.network_cidr(cfg))
    if address is None:
        return
    cmd_client_ip(_Args(name=name, address=address))


def _menu_change_settings(cfg: dict) -> None:
    endpoint = ask_optional("Адрес сервера (домен или IP)", cfg["endpoint"])
    port = ask_optional("Порт", cfg["port"])
    proto = ask_optional("Протокол (udp/tcp)", cfg["proto"])
    dns = ask_optional("DNS через запятую", ", ".join(cfg["dns"]))
    if not any([endpoint, port, proto, dns]):
        info("Ничего не изменено, возврат в меню.")
        return
    cmd_set(_Args(endpoint=endpoint, port=int(port) if port else None,
                  proto=proto, dns=dns, nic=None))


def _menu_ufw(cfg: dict) -> None:
    install_ufw = False
    if not srv.ufw_available():
        warn("ufw не установлен.")
        install_ufw = ask_yes_no("Установить ufw сейчас?", True)
        if not install_ufw:
            info("Возврат в меню.")
            return
    with_ssh = ask_yes_no("Заодно разрешить SSH (чтобы не потерять доступ)?", True)
    cmd_ufw(_Args(install=install_ufw, remove=False, ssh=with_ssh))


def _menu_update(cfg: dict) -> None:
    result = update_mod.run()
    current, latest = result["current"], result["latest"]
    if not result["updated"]:
        ok("Обновлять нечего — установлена актуальная версия %s (сборка %s)."
           % (current["version"], current["build"]))
        return
    ok("ovpnctl обновлён: %s → %s (сборка %s → %s)."
       % (current["version"], latest["version"], current["build"], latest["build"]))
    if result["changed"]:
        info("Обновлены файлы сервера: %s — OpenVPN перезапущен." % ", ".join(result["changed"]))
    # в памяти этого процесса старый код — перезапускаем меню уже новым
    pause("Нажмите Enter, чтобы открыть меню новой версии")
    os.execv(sys.executable, [sys.executable, "-m", "ovpnctl"])


MENU_ACTIONS = {
    "1": _menu_client_add,
    "2": _menu_client_list,
    "3": lambda cfg: cmd_online(_Args(json=False)),
    "4": lambda cfg: _menu_client_action(
        cfg, lambda name: cmd_client_renew(_Args(name=name, days=None, new_key=False))),
    "5": lambda cfg: _menu_client_action(
        cfg, lambda name: cmd_client_delete(_Args(name=name, yes=False))),
    "6": _menu_client_ip,
    "7": lambda cfg: cmd_status(_Args(json=False)),
    "8": lambda cfg: cmd_server(_Args(action="restart", lines=50)),
    "9": lambda cfg: cmd_server(_Args(action="logs", lines=50)),
    "10": lambda cfg: cmd_server(_Args(action="rebuild", lines=50)),
    "11": _menu_change_settings,
    "12": lambda cfg: cmd_pki_check(_Args(json=False)),
    "13": lambda cfg: cmd_pki_renew(_Args(force=False, quiet=False)),
    "14": lambda cfg: cmd_doctor(_Args()),
    "15": lambda cfg: cmd_backup(_Args(output=None)),
    "16": _menu_ufw,
    "17": _menu_update,
}


# --------------------------------------------------------------------------- #
# Разбор аргументов
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ovpnctl",
        description="Установка и управление OpenVPN-сервером (Debian 10/11/12/13, Ubuntu 20.04+).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Без аргументов открывается интерактивное меню.",
    )
    parser.add_argument("--version", action="version", version="ovpnctl %s" % __version__)
    sub = parser.add_subparsers(dest="command")

    # setup
    setup_parser = sub.add_parser(
        "setup", help="первичная настройка сервера (вызывается установщиком)")
    setup_parser.set_defaults(func=provision.setup)

    # client
    client_parser = sub.add_parser("client", help="управление клиентами (сертификаты и профили)")
    client_sub = client_parser.add_subparsers(dest="subcommand")

    add_parser = client_sub.add_parser("add", help="создать клиента и профиль .ovpn")
    add_parser.add_argument("name", metavar="certname", help="имя клиента: латиница, цифры, . _ -")
    add_parser.add_argument("--days", type=int, help="срок действия сертификата")
    add_parser.add_argument("--ip", help="закрепить статический адрес в VPN-подсети")
    add_parser.add_argument("--print", dest="print_profile", action="store_true", help="сразу вывести .ovpn")
    add_parser.set_defaults(func=cmd_client_add)

    list_parser = client_sub.add_parser("list", help="список клиентов и сроков")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=cmd_client_list)

    show_parser = client_sub.add_parser("show", help="вывести .ovpn клиента в консоль")
    show_parser.add_argument("name", metavar="certname")
    show_parser.add_argument("--path", action="store_true", help="показать только путь к файлу")
    show_parser.set_defaults(func=cmd_client_show)

    revoke_parser = client_sub.add_parser("revoke", help="отозвать доступ (сертификат в CRL)")
    revoke_parser.add_argument("name", metavar="certname")
    revoke_parser.add_argument("-y", "--yes", action="store_true")
    revoke_parser.set_defaults(func=cmd_client_revoke)

    del_parser = client_sub.add_parser("delete", help="отозвать и удалить все файлы клиента")
    del_parser.add_argument("name", metavar="certname")
    del_parser.add_argument("-y", "--yes", action="store_true")
    del_parser.set_defaults(func=cmd_client_delete)

    renew_parser = client_sub.add_parser("renew", help="продлить сертификат клиента")
    renew_parser.add_argument("name", metavar="certname")
    renew_parser.add_argument("--days", type=int)
    renew_parser.add_argument("--new-key", action="store_true", help="сгенерировать новый ключ")
    renew_parser.set_defaults(func=cmd_client_renew)

    ip_parser = client_sub.add_parser("ip", help="закрепить статический адрес за клиентом")
    ip_parser.add_argument("name", metavar="certname")
    ip_parser.add_argument("address", metavar="адрес")
    ip_parser.set_defaults(func=cmd_client_ip)

    # status / online
    status_parser = sub.add_parser("status", help="сводное состояние сервера и PKI")
    status_parser.add_argument("--json", action="store_true")
    status_parser.set_defaults(func=cmd_status)

    online_parser = sub.add_parser("online", help="активные подключения")
    online_parser.add_argument("--json", action="store_true")
    online_parser.set_defaults(func=cmd_online)

    # server
    server_parser = sub.add_parser("server", help="управление службой и конфигурацией")
    server_parser.add_argument("action", choices=["start", "stop", "restart", "rebuild", "config", "logs"])
    server_parser.add_argument("-n", "--lines", type=int, default=50, help="строк лога")
    server_parser.set_defaults(func=cmd_server)

    # set
    set_parser = sub.add_parser("set", help="изменить параметры (endpoint/порт/протокол/DNS/интерфейс)")
    set_parser.add_argument("--endpoint")
    set_parser.add_argument("--port", type=int)
    set_parser.add_argument("--proto", choices=["udp", "tcp"])
    set_parser.add_argument("--dns")
    set_parser.add_argument("--nic")
    set_parser.set_defaults(func=cmd_set)

    # pki
    pki_parser = sub.add_parser("pki", help="сертификаты и автопродление")
    pki_sub = pki_parser.add_subparsers(dest="subcommand")

    check_parser = pki_sub.add_parser("check", help="сроки всех сертификатов")
    check_parser.add_argument("--json", action="store_true")
    check_parser.set_defaults(func=cmd_pki_check)

    prenew_parser = pki_sub.add_parser("renew", help="продлить всё, чему пора (вызывается таймером)")
    prenew_parser.add_argument("--force", action="store_true", help="продлить принудительно")
    prenew_parser.add_argument("--quiet", action="store_true", help="без вывода (для systemd)")
    prenew_parser.set_defaults(func=cmd_pki_renew)

    pinfo_parser = pki_sub.add_parser("info", help="подробности по CA/серверу/CRL")
    pinfo_parser.set_defaults(func=cmd_pki_info)

    # ufw
    ufw_parser = sub.add_parser("ufw", help="разрешить порт VPN в ufw")
    ufw_parser.add_argument("--install", action="store_true", help="установить ufw, если его нет")
    ufw_parser.add_argument("--remove", action="store_true", help="убрать добавленные правила")
    ufw_parser.add_argument("--ssh", action="store_true",
                            help="заодно разрешить порты sshd (чтобы не потерять доступ)")
    ufw_parser.set_defaults(func=cmd_ufw)

    # backup / uninstall / doctor / menu
    backup_parser = sub.add_parser("backup", help="архив PKI, профилей и конфигурации")
    backup_parser.add_argument("-o", "--output", help="каталог для архива")
    backup_parser.set_defaults(func=cmd_backup)

    update_parser = sub.add_parser(
        "update", help="обновить ovpnctl из GitHub (без переустановки сервера)")
    update_parser.add_argument("--check", action="store_true",
                               help="только проверить, есть ли новая версия")
    update_parser.add_argument("--force", action="store_true",
                               help="переустановить код, даже если версия та же")
    update_parser.add_argument("--repo", help="репозиторий (по умолчанию — откуда ставили)")
    update_parser.add_argument("--branch", help="ветка (по умолчанию master, затем main)")
    update_parser.add_argument("--from", dest="source", metavar="PATH",
                               help="обновить из локального каталога или .tar.gz")
    update_parser.add_argument("--finish", action="store_true", help=argparse.SUPPRESS)
    update_parser.set_defaults(func=cmd_update)

    doctor_parser = sub.add_parser("doctor", help="самодиагностика установки")
    doctor_parser.set_defaults(func=cmd_doctor)

    uninstall_parser = sub.add_parser("uninstall", help="удалить конфигурацию и службы")
    uninstall_parser.add_argument("-y", "--yes", action="store_true")
    uninstall_parser.add_argument("--keep-pki", action="store_true", help="сохранить PKI и профили")
    uninstall_parser.add_argument("--purge", action="store_true", help="удалить и пакет openvpn")
    uninstall_parser.set_defaults(func=cmd_uninstall)

    menu_parser = sub.add_parser("menu", help="интерактивное меню")
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
        err("Ошибка: %s" % exc)
        return 1
    except KeyboardInterrupt:
        print()
        return 130
