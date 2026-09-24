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
Description=ovpnctl: firewall and NAT rules for OpenVPN
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
Description=ovpnctl: OpenVPN certificate check and auto-renewal
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ovpnctl pki renew --quiet
Nice=10
"""

UNIT_RENEW_TIMER = """[Unit]
Description=ovpnctl: daily certificate expiry check

[Timer]
OnBootSec=10min
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true
Unit=ovpnctl-renew.service

[Install]
WantedBy=timers.target
"""

UNIT_TRAFFIC = """[Unit]
Description=ovpnctl: OpenVPN client traffic accounting by day

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ovpnctl traffic --collect
Nice=10
"""

UNIT_TRAFFIC_TIMER = """[Unit]
Description=ovpnctl: collect client traffic every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=ovpnctl-traffic.service

[Install]
WantedBy=timers.target
"""


def write_units() -> None:
    write_file(os.path.join(UNIT_DIR, cfgmod.FIREWALL_UNIT),
               UNIT_FIREWALL.format(script=srv.FIREWALL_SCRIPT), 0o644)
    write_file(os.path.join(UNIT_DIR, "ovpnctl-renew.service"), UNIT_RENEW, 0o644)
    write_file(os.path.join(UNIT_DIR, cfgmod.RENEW_TIMER), UNIT_RENEW_TIMER, 0o644)
    write_file(os.path.join(UNIT_DIR, "ovpnctl-traffic.service"), UNIT_TRAFFIC, 0o644)
    write_file(os.path.join(UNIT_DIR, cfgmod.TRAFFIC_TIMER), UNIT_TRAFFIC_TIMER, 0o644)
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
            "could not detect the server address. Check the network and set it "
            "after installation: ovpnctl set --endpoint <domain or IP>")
    if is_private_ip(cfg["endpoint"]):
        warn("Detected private address %s (server behind NAT). If clients connect "
             "from outside, set the public address: ovpnctl set --endpoint <domain or IP>"
             % cfg["endpoint"])

    cfg["nic"] = default_nic()

    net = pick_subnet()
    cfg["subnet"] = str(net.network_address)
    cfg["netmask"] = str(net.netmask)

    if port_in_use(cfg["port"], cfg["proto"]):
        warn("Port %d/%s is already in use by another process — change it after installation: "
             "ovpnctl set --port <port>" % (cfg["port"], cfg["proto"]))

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

    warn("Found an existing OpenVPN configuration on this server:")
    for path in found["configs"]:
        warn("  config: %s" % path)
    for unit in found["units"]:
        warn("  active service: %s" % unit)
    archive = backup_openvpn_dir()
    ok("Backup of /etc/openvpn: %s" % archive)

    if not sys.stdin.isatty():
        warn("No terminal — the existing server is left as is. If it occupies the port, "
             "stop it and run: ovpnctl set --port <port>")
        return cfg

    if ask_yes_no("Remove the existing server (disable services, archive configs)?", True):
        purged = purge_previous_openvpn(found)
        ok("Existing server disabled%s. Installing with default settings."
           % (", configs moved to %s" % purged["dir"] if purged["configs"] else ""))
        return cfg

    if found["units"] and ask_yes_no(
            "Then stop it now to free the port (autostart stays enabled)?", True):
        for unit in found["units"]:
            systemctl("stop", unit, check=False)
        ok("Existing services stopped: %s" % ", ".join(found["units"]))
        return cfg

    cfg["port"] = ask("Port for the new server (the existing one keeps running)", 1195,
                      lambda v: int(v) if 1 <= int(v) <= 65535 else (_ for _ in ()).throw(
                          ValueError("port must be 1–65535")))
    return cfg


def setup(args) -> None:
    require_root()
    dist = check_supported()
    facts = verify_dependencies()
    ok("System: %s | OpenVPN %s | OpenSSL %s"
       % (dist["pretty"], facts["openvpn"], facts["openssl"]))

    if cfgmod.config_exists():
        raise OvpnError(
            "server is already set up (%s).\n"
            "  Status:               ovpnctl status\n"
            "  Reinstall:            ovpnctl uninstall -y  (saves an archive to /root), then install"
            % cfgmod.CONFIG_PATH)

    cfg = cfgmod.load(required=False)
    cfgmod.init_dirs()
    cfg = handle_preexisting(cfg)
    cfg = resolve_settings(cfg)
    cfg["installed_at"] = pki.now_iso()

    cfgmod.init_dirs()
    cfgmod.save(cfg)

    ok("Settings: %s:%d/%s | subnet %s | interface %s | keys %s | DNS %s"
       % (cfg["endpoint"], cfg["port"], cfg["proto"], cfgmod.network_cidr(cfg),
          cfg["nic"], cfg["key_type"].upper(), ", ".join(cfg["dns"])))

    info("Creating PKI (CA for %d days)…" % cfg["ca_days"])
    if not os.path.exists(pki.CA_CRT):
        pki.create_ca(cfg)
    else:
        pki.ensure_layout(cfg)
    if not pki.exists(pki.SERVER_NAME):
        pki.issue(pki.SERVER_NAME, "server_cert", int(cfg["server_days"]), cfg)
    pki.ensure_tc_key()
    pki.gen_crl(cfg)
    ok("PKI ready: CA until %s, server certificate until %s"
       % (pki.not_after(pki.CA_CRT).strftime("%Y-%m-%d"),
          pki.not_after(pki.cert_path(pki.SERVER_NAME)).strftime("%Y-%m-%d")))

    info("Writing server configuration and firewall rules…")
    srv.deploy_pki_to_server(cfg)
    srv.write_server_conf(cfg)
    srv.setup_networking(cfg)
    write_units()

    info("Starting services…")
    srv.enable_services()
    if not service_active(cfgmod.SERVICE):
        raise OvpnError(
            "service %s failed to start. Diagnostics: journalctl -u %s -n 50 --no-pager"
            % (cfgmod.SERVICE, cfgmod.SERVICE))
    ok("OpenVPN running on %s:%d/%s" % (cfg["endpoint"], cfg["port"], cfg["proto"]))

    print()
    print(bold("Installation complete."))
    print("  Client profiles:    %s" % cfgmod.PROFILE_DIR)
    print("  Change settings:    ovpnctl set --endpoint vpn.example.com --port 443 --dns 9.9.9.9")
    print("  Server config:      %s" % cfgmod.server_conf_path())
    print("  Auto-renewal:       %s (systemd timer, daily)" % cfgmod.RENEW_TIMER)
    print()
    print()
    print(bold("Create the first client:  ovpnctl client add <certname>"))
    print()
    print("  ovpnctl                          — interactive menu")
    print("  ovpnctl client add <certname>    — new client")
    print("  ovpnctl client show <certname>   — print .ovpn to the console")
    print("  ovpnctl client list              — list clients and expiry dates")
    print("  ovpnctl pki check                — expiry of all certificates")


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
    info("Stopping services…")
    for unit in (cfgmod.SERVICE, cfgmod.RENEW_TIMER, "ovpnctl-renew.service",
                 cfgmod.TRAFFIC_TIMER, "ovpnctl-traffic.service", cfgmod.FIREWALL_UNIT):
        systemctl("disable", "--now", unit, check=False)

    if os.path.exists(srv.FIREWALL_SCRIPT):
        run([srv.FIREWALL_SCRIPT, "down"], check=False)

    # снимаем правила ufw, если мы их ставили (до удаления config.json)
    if cfgmod.config_exists():
        cfg = cfgmod.load(required=False)
        if cfg.get("ufw_configured") and srv.ufw_available():
            info("Removing ufw rules…")
            for step in srv.setup_ufw(cfg, remove=True):
                info("  • %s" % step)

    archive = None
    if os.path.exists(cfgmod.PKI_DIR):
        archive = backup("/root")
        ok("State saved to %s" % archive)

    for path in (
        os.path.join(UNIT_DIR, cfgmod.FIREWALL_UNIT),
        os.path.join(UNIT_DIR, "ovpnctl-renew.service"),
        os.path.join(UNIT_DIR, cfgmod.RENEW_TIMER),
        os.path.join(UNIT_DIR, "ovpnctl-traffic.service"),
        os.path.join(UNIT_DIR, cfgmod.TRAFFIC_TIMER),
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

    ok("ovpnctl removed." + (" PKI kept in %s." % cfgmod.PKI_DIR if keep_pki else ""))
    if archive:
        print("Backup: %s" % archive)
