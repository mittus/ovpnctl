"""Первичная установка/переустановка сервера и удаление."""
from __future__ import annotations

import datetime
import os
import shutil
import sys

from . import config as cfgmod
from . import pki
from . import renew
from . import server as srv
from .system import (
    check_supported,
    running_openvpn_units,
    daemon_reload,
    default_nic,
    is_private_ip,
    pick_subnet,
    port_in_use,
    public_ip,
    run,
    service_active,
    systemctl,
    verify_dependencies,
)
from .util import (
    OvpnError,
    ask,
    ask_yes_no,
    bold,
    ensure_dir,
    info,
    ok,
    require_root,
    warn,
    write_file,
)

UNIT_DIR = cfgmod.ROOT + "/etc/systemd/system"

UNIT_FIREWALL = """[Unit]
Description=ovpnctl: правила файрвола и NAT для OpenVPN
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={script} up
ExecStop={script} down

[Install]
WantedBy=multi-user.target
"""

UNIT_RENEW = """[Unit]
Description=ovpnctl: проверка и автопродление сертификатов OpenVPN
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ovpnctl pki renew --quiet
Nice=10
"""

UNIT_RENEW_TIMER = """[Unit]
Description=ovpnctl: ежедневная проверка сроков сертификатов

[Timer]
OnBootSec=10min
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true
Unit=ovpnctl-renew.service

[Install]
WantedBy=timers.target
"""

def write_units() -> None:
    write_file(os.path.join(UNIT_DIR, cfgmod.FIREWALL_UNIT),
               UNIT_FIREWALL.format(script=srv.FIREWALL_SCRIPT), 0o644)
    write_file(os.path.join(UNIT_DIR, "ovpnctl-renew.service"), UNIT_RENEW, 0o644)
    write_file(os.path.join(UNIT_DIR, cfgmod.RENEW_TIMER), UNIT_RENEW_TIMER, 0o644)
    daemon_reload()


# --------------------------------------------------------------------------- #
# Параметры сервера
# --------------------------------------------------------------------------- #
def resolve_settings(cfg: dict) -> dict:
    """Все параметры сервера выбираются автоматически по разумным умолчаниям.

    Наружу вынесено только то, что нельзя угадать: имя первого клиента. Всё
    остальное меняется после установки командой 'ovpnctl set' — тогда конфиг и
    профили пересобираются согласованно.
    """
    cfg["endpoint"] = public_ip()
    if not cfg["endpoint"]:
        raise OvpnError(
            "не удалось определить адрес сервера. Проверьте сеть и задайте его "
            "после установки: ovpnctl set --endpoint <домен или IP>")
    if is_private_ip(cfg["endpoint"]):
        warn("Определён приватный адрес %s (сервер за NAT). Если клиенты подключаются "
             "снаружи, задайте внешний адрес: ovpnctl set --endpoint <домен или IP>"
             % cfg["endpoint"])

    cfg["nic"] = default_nic()

    net = pick_subnet()
    cfg["subnet"] = str(net.network_address)
    cfg["netmask"] = str(net.netmask)

    if port_in_use(cfg["port"], cfg["proto"]):
        warn("Порт %d/%s уже занят другим процессом — после установки смените его: "
             "ovpnctl set --port <порт>" % (cfg["port"], cfg["proto"]))

    return srv.validate_cfg(cfg)


# --------------------------------------------------------------------------- #
# Установка
# --------------------------------------------------------------------------- #
def preexisting_openvpn() -> dict:
    """Следы ранее установленного вручную OpenVPN на этом сервере."""
    import glob

    configs = sorted(
        set(glob.glob("/etc/openvpn/*.conf"))
        | (set(glob.glob(os.path.join(cfgmod.SERVER_DIR, "*.conf")))
           - {cfgmod.server_conf_path()})
    )
    return {"configs": configs, "units": running_openvpn_units(exclude=cfgmod.SERVICE)}


def backup_openvpn_dir() -> str:
    """Архив /etc/openvpn целиком — на случай, если там была чужая конфигурация."""
    import tempfile

    ensure_dir(cfgmod.BACKUP_DIR, 0o700)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    tmp = tempfile.mkdtemp(prefix="ovpnctl-preexisting-")
    try:
        built = shutil.make_archive(os.path.join(tmp, "openvpn-before-ovpnctl-%s" % stamp),
                                    "gztar", root_dir="/etc/openvpn", base_dir=".", logger=None)
        target = os.path.join(cfgmod.BACKUP_DIR, os.path.basename(built))
        shutil.move(built, target)
        os.chmod(target, 0o600)
        return target
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def purge_previous_openvpn(found: dict) -> dict:
    """Отключает прежний сервер: службы — disable --now, конфиги — в архив.

    После этого порт и подсеть свободны, и установка идёт на стандартных параметрах.
    """
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    moved_to = os.path.join(cfgmod.BACKUP_DIR, "previous-openvpn-%s" % stamp)
    result = {"units": [], "configs": [], "dir": moved_to}

    for unit in found["units"]:
        systemctl("disable", "--now", unit, check=False)
        result["units"].append(unit)
    # старые юниты могли быть неактивны, но включены в автозапуск
    for unit in ("openvpn.service", "openvpn@server.service"):
        if unit != cfgmod.SERVICE:
            systemctl("disable", "--now", unit, check=False)

    if found["configs"]:
        ensure_dir(moved_to, 0o700)
        for path in found["configs"]:
            if not os.path.exists(path):
                continue
            target = os.path.join(moved_to, path.lstrip("/").replace("/", "_"))
            shutil.move(path, target)
            result["configs"].append(path)
    return result


def handle_preexisting(cfg: dict) -> dict:
    """Что делать с ранее установленным OpenVPN: спрашиваем пользователя."""
    found = preexisting_openvpn()
    if not (found["configs"] or found["units"]):
        return cfg

    warn("Обнаружена прежняя конфигурация OpenVPN на этом сервере:")
    for path in found["configs"]:
        warn("  конфиг: %s" % path)
    for unit in found["units"]:
        warn("  активная служба: %s" % unit)
    archive = backup_openvpn_dir()
    ok("Резервная копия /etc/openvpn: %s" % archive)

    if not sys.stdin.isatty():
        warn("Терминала нет — прежний сервер оставлен как есть. Если он занимает порт, "
             "остановите его и выполните: ovpnctl set --port <порт>")
        return cfg

    if ask_yes_no("Удалить прежний сервер (службы отключить, конфиги убрать в архив)?", True):
        purged = purge_previous_openvpn(found)
        ok("Прежний сервер отключён%s. Установка пойдёт на стандартных параметрах."
           % (", конфиги перенесены в %s" % purged["dir"] if purged["configs"] else ""))
        return cfg

    if found["units"] and ask_yes_no(
            "Тогда остановить его сейчас, чтобы освободить порт (автозапуск останется)?", True):
        for unit in found["units"]:
            systemctl("stop", unit, check=False)
        ok("Прежние службы остановлены: %s" % ", ".join(found["units"]))
        return cfg

    cfg["port"] = ask("Порт для нового сервера (прежний остаётся работать)", 1195,
                      lambda v: int(v) if 1 <= int(v) <= 65535 else (_ for _ in ()).throw(
                          ValueError("порт должен быть 1–65535")))
    return cfg


def setup(args) -> None:
    require_root()
    dist = check_supported()
    facts = verify_dependencies()
    ok("Система: %s | OpenVPN %s | OpenSSL %s"
       % (dist["pretty"], facts["openvpn"], facts["openssl"]))

    if cfgmod.config_exists():
        raise OvpnError(
            "сервер уже настроен (%s).\n"
            "  Состояние:            ovpnctl status\n"
            "  Поставить заново:     ovpnctl uninstall -y  (сохранит архив в /root), затем установка"
            % cfgmod.CONFIG_PATH)

    cfg = cfgmod.load(required=False)
    cfgmod.init_dirs()
    cfg = handle_preexisting(cfg)
    cfg = resolve_settings(cfg)
    cfg["installed_at"] = pki.now_iso()

    cfgmod.init_dirs()
    cfgmod.save(cfg)

    ok("Параметры: %s:%d/%s | подсеть %s | интерфейс %s | ключи %s | DNS %s"
       % (cfg["endpoint"], cfg["port"], cfg["proto"], cfgmod.network_cidr(cfg),
          cfg["nic"], cfg["key_type"].upper(), ", ".join(cfg["dns"])))

    info("Создаю PKI (CA на %d дней)…" % cfg["ca_days"])
    if not os.path.exists(pki.CA_CRT):
        pki.create_ca(cfg)
    else:
        pki.ensure_layout(cfg)
    if not pki.exists(pki.SERVER_NAME):
        pki.issue(pki.SERVER_NAME, "server_cert", int(cfg["server_days"]), cfg)
    pki.ensure_tc_key()
    pki.gen_crl(cfg)
    ok("PKI готов: CA до %s, сертификат сервера до %s"
       % (pki.not_after(pki.CA_CRT).strftime("%Y-%m-%d"),
          pki.not_after(pki.cert_path(pki.SERVER_NAME)).strftime("%Y-%m-%d")))

    info("Пишу конфигурацию сервера и правила файрвола…")
    srv.deploy_pki_to_server(cfg)
    srv.write_server_conf(cfg)
    srv.setup_networking(cfg)
    write_units()

    info("Запускаю службы…")
    srv.enable_services()
    if not service_active(cfgmod.SERVICE):
        raise OvpnError(
            "служба %s не запустилась. Диагностика: journalctl -u %s -n 50 --no-pager"
            % (cfgmod.SERVICE, cfgmod.SERVICE))
    ok("OpenVPN запущен на %s:%d/%s" % (cfg["endpoint"], cfg["port"], cfg["proto"]))

    print()
    print(bold("Установка завершена."))
    print("  Профили клиентов:   %s" % cfgmod.PROFILE_DIR)
    print("  Сменить параметры:  ovpnctl set --endpoint vpn.example.com --port 443 --dns 9.9.9.9")
    print("  Конфиг сервера:     %s" % cfgmod.server_conf_path())
    print("  Автопродление:      %s (systemd timer, ежедневно)" % cfgmod.RENEW_TIMER)
    print()
    print()
    print(bold("Создайте первого клиента:  ovpnctl client add <certname>"))
    print()
    print("  ovpnctl                          — интерактивное меню")
    print("  ovpnctl client add <certname>    — новый клиент")
    print("  ovpnctl client show <certname>   — вывести .ovpn в консоль")
    print("  ovpnctl client list              — список клиентов и сроков")
    print("  ovpnctl pki check                — сроки всех сертификатов")


def backup(dest_dir: str = None) -> str:
    """Архив всего состояния (PKI + профили + конфиг).

    Собираем во временном каталоге: иначе архив, лежащий внутри /etc/ovpnctl,
    попал бы сам в себя.
    """
    import tempfile

    dest_dir = dest_dir or cfgmod.BACKUP_DIR
    ensure_dir(dest_dir, 0o700)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = "ovpnctl-backup-%s" % stamp
    tmp = tempfile.mkdtemp(prefix="ovpnctl-backup-")
    try:
        built = shutil.make_archive(os.path.join(tmp, name), "gztar",
                                    root_dir=cfgmod.ETC_DIR, base_dir=".", logger=None)
        target = os.path.join(dest_dir, os.path.basename(built))
        shutil.move(built, target)
        os.chmod(target, 0o600)
        return target
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Удаление
# --------------------------------------------------------------------------- #
def uninstall(keep_pki: bool = False, purge_packages: bool = False) -> None:
    require_root()
    info("Останавливаю службы…")
    for unit in (cfgmod.SERVICE, cfgmod.RENEW_TIMER, "ovpnctl-renew.service", cfgmod.FIREWALL_UNIT):
        systemctl("disable", "--now", unit, check=False)

    if os.path.exists(srv.FIREWALL_SCRIPT):
        run([srv.FIREWALL_SCRIPT, "down"], check=False)

    # снимаем правила ufw, если мы их ставили (до удаления config.json)
    if cfgmod.config_exists():
        cfg = cfgmod.load(required=False)
        if cfg.get("ufw_configured") and srv.ufw_available():
            info("Убираю правила ufw…")
            for step in srv.setup_ufw(cfg, remove=True):
                info("  • %s" % step)

    archive = None
    if os.path.exists(cfgmod.PKI_DIR):
        archive = backup("/root")
        ok("Состояние сохранено в %s" % archive)

    for path in (
        os.path.join(UNIT_DIR, cfgmod.FIREWALL_UNIT),
        os.path.join(UNIT_DIR, "ovpnctl-renew.service"),
        os.path.join(UNIT_DIR, cfgmod.RENEW_TIMER),
        "/etc/sysctl.d/99-ovpnctl.conf",
        os.path.join(cfgmod.SERVER_DIR, "server.conf"),
        os.path.join(cfgmod.SERVER_DIR, "ca.crt"),
        os.path.join(cfgmod.SERVER_DIR, "server.crt"),
        os.path.join(cfgmod.SERVER_DIR, "server.key"),
        os.path.join(cfgmod.SERVER_DIR, "crl.pem"),
        os.path.join(cfgmod.SERVER_DIR, "tc.key"),
        os.path.join(cfgmod.SERVER_DIR, "ipp.txt"),
        srv.TRAFFIC_SCRIPT,
    ):
        if os.path.exists(path):
            os.unlink(path)
    for directory in (srv.DROPIN_DIR, srv.CCD_DIR, srv.TRAFFIC_DIR):
        if os.path.isdir(directory):
            shutil.rmtree(directory, ignore_errors=True)
    daemon_reload()

    if not keep_pki:
        # всё состояние уже сохранено в архив выше — каталог удаляем целиком
        shutil.rmtree(cfgmod.ETC_DIR, ignore_errors=True)

    if purge_packages:
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        run(["apt-get", "remove", "-y", "-qq", "openvpn"], check=False, env=env)

    ok("ovpnctl удалён." + (" PKI сохранён в %s." % cfgmod.PKI_DIR if keep_pki else ""))
    if archive:
        print("Резервная копия: %s" % archive)
