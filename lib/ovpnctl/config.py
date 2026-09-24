"""Конфигурация и пути ovpnctl (состояние в /etc/ovpnctl/config.json)."""
from __future__ import annotations

import json
import os

from . import __version__
from .util import OvpnError, ensure_dir, write_file

# Префикс путей: используется тестами (OVPNCTL_ROOT=/tmp/sandbox), в бою пустой.
ROOT = os.environ.get("OVPNCTL_ROOT", "").rstrip("/")

ETC_DIR = ROOT + "/etc/ovpnctl"
CONFIG_PATH = os.path.join(ETC_DIR, "config.json")
PKI_DIR = os.path.join(ETC_DIR, "pki")
PROFILE_DIR = os.path.join(ETC_DIR, "profiles")
BACKUP_DIR = os.path.join(ETC_DIR, "backup")
SERVER_DIR = ROOT + "/etc/openvpn/server"
LOG_DIR = ROOT + "/var/log/ovpnctl"
RENEW_LOG = os.path.join(LOG_DIR, "renew.log")
STATUS_FILE = ROOT + "/run/openvpn-server/status-server.log"
MGMT_SOCKET = ROOT + "/run/openvpn-server/ovpnctl.sock"
SERVICE = "openvpn-server@server.service"
FIREWALL_UNIT = "ovpnctl-firewall.service"
RENEW_TIMER = "ovpnctl-renew.timer"

CONFIG_VERSION = 1

DEFAULTS = {
    "config_version": CONFIG_VERSION,
    "endpoint": "",
    "port": 1194,
    "proto": "udp",
    "dev": "tun",
    "nic": "",
    "subnet": "10.8.0.0",
    "netmask": "255.255.255.0",
    "ipv6": False,
    "subnet6": "fd42:42:42:42::/112",
    "dns": ["1.1.1.1", "1.0.0.1"],
    "redirect_gateway": True,
    "key_type": "ec",            # ec | rsa
    "ec_curve": "prime256v1",
    "rsa_bits": 3072,
    "digest": "sha256",
    "cn_prefix": "ovpnctl",
    # Сроки жизни (дни)
    "ca_days": 7300,             # 20 лет
    "server_days": 3650,         # 10 лет
    "client_days": 3650,         # 10 лет
    "crl_days": 3650,            # 10 лет (перевыпускается ежедневно)
    # Пороги автопродления (дни до истечения)
    "renew_ca_before": 365,
    "renew_server_before": 90,
    "renew_client_before": 30,
    "renew_crl_before": 365,
    "auto_renew_clients": True,
    "installed_at": "",
    "version": __version__,
}


def config_exists() -> bool:
    return os.path.exists(CONFIG_PATH)


def load(required: bool = True) -> dict:
    if not config_exists():
        if required:
            raise OvpnError("сервер ещё не настроен — выполните: ovpnctl setup")
        return dict(DEFAULTS)
    with open(CONFIG_PATH) as fh:
        try:
            data = json.load(fh)
        except ValueError as exc:
            raise OvpnError("повреждён %s: %s" % (CONFIG_PATH, exc))
    merged = dict(DEFAULTS)
    merged.update(data)
    return merged


def save(cfg: dict) -> None:
    ensure_dir(ETC_DIR, 0o700)
    cfg = dict(cfg)
    cfg["config_version"] = CONFIG_VERSION
    write_file(CONFIG_PATH, json.dumps(cfg, indent=2, ensure_ascii=False, sort_keys=True) + "\n", 0o600)


def init_dirs() -> None:
    ensure_dir(ETC_DIR, 0o700)
    ensure_dir(PKI_DIR, 0o700)
    ensure_dir(PROFILE_DIR, 0o700)
    ensure_dir(BACKUP_DIR, 0o700)
    ensure_dir(LOG_DIR, 0o750)
    ensure_dir(SERVER_DIR, 0o755)   # openvpn читает crl.pem уже как nobody


def server_conf_path() -> str:
    return os.path.join(SERVER_DIR, "server.conf")


def network_cidr(cfg: dict) -> str:
    import ipaddress

    net = ipaddress.IPv4Network("%s/%s" % (cfg["subnet"], cfg["netmask"]), strict=False)
    return str(net)
