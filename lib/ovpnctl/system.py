"""Работа с ОС: дистрибутив, пакеты, сервисы, сеть, версии OpenVPN/OpenSSL."""
from __future__ import annotations

import json
import os
import re
import socket
import urllib.request

from .util import OvpnError, info, run, run_ok, warn, which, write_file

SUPPORTED = {
    "debian": (10, 13),
    "ubuntu": (20, 26),
}


# --------------------------------------------------------------------------- #
# Дистрибутив
# --------------------------------------------------------------------------- #
def os_release() -> dict:
    data = {}
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if "=" in line:
                    key, _, val = line.strip().partition("=")
                    data[key] = val.strip('"')
    except OSError:
        raise OvpnError("cannot read /etc/os-release — unsupported system.")
    return data


def distro():
    rel = os_release()
    ident = rel.get("ID", "unknown")
    like = rel.get("ID_LIKE", "")
    version = rel.get("VERSION_ID", "0")
    try:
        major = int(version.split(".")[0])
    except ValueError:
        major = 0
    return {
        "id": ident,
        "like": like,
        "version": version,
        "major": major,
        "codename": rel.get("VERSION_CODENAME", ""),
        "pretty": rel.get("PRETTY_NAME", "%s %s" % (ident, version)),
    }


def check_supported() -> dict:
    dist = distro()
    ident = dist["id"]
    if ident in SUPPORTED:
        low, high = SUPPORTED[ident]
        if dist["major"] < low:
            raise OvpnError(
                "%s %s is not supported (%s %d+ required)." % (ident, dist["version"], ident, low)
            )
        if dist["major"] > high:
            warn("%s is newer than tested versions — continuing." % dist["pretty"])
    elif "debian" in dist["like"] or "ubuntu" in dist["like"]:
        warn("Distribution '%s' is untested, but Debian-compatible." % ident)
    else:
        raise OvpnError("distribution '%s' is not supported (Debian/Ubuntu required)." % ident)
    return dist


# --------------------------------------------------------------------------- #
# Пакеты
# --------------------------------------------------------------------------- #
def pkg_installed(name: str) -> bool:
    proc = run(["dpkg-query", "-W", "-f=${db:Status-Status}", name], check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "installed"


def apt_install(packages) -> None:
    missing = [p for p in packages if not pkg_installed(p)]
    if not missing:
        return
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    info("Installing packages: %s" % " ".join(missing))
    run(["apt-get", "update", "-qq"], check=False, env=env)
    run(["apt-get", "install", "-y", "-qq", "--no-install-recommends"] + missing, env=env)
    still = [p for p in missing if not pkg_installed(p)]
    if still:
        raise OvpnError("failed to install packages: %s" % " ".join(still))


def verify_dependencies(install: bool = True) -> dict:
    """Перепроверка всех зависимостей: пакеты, бинарники, версии.

    install=False — только проверка (используется в 'ovpnctl doctor').
    """
    required_pkgs = ["openvpn", "openssl", "iproute2", "iptables", "python3"]
    missing = [p for p in required_pkgs if not pkg_installed(p)]
    if missing:
        if not install:
            raise OvpnError("packages not installed: %s" % " ".join(missing))
        apt_install(missing)

    for binary in ("openvpn", "openssl", "ip", "iptables"):
        if not which(binary):
            raise OvpnError("binary '%s' not found in PATH." % binary)

    ovpn = openvpn_version()
    if ovpn < (2, 4):
        raise OvpnError("OpenVPN 2.4+ required, found %s." % ".".join(map(str, ovpn)))
    ossl = openssl_version()
    if ossl < (1, 1):
        raise OvpnError("OpenSSL 1.1+ required, found %s." % ".".join(map(str, ossl)))

    unit_paths = ["/lib/systemd/system/openvpn-server@.service",
                  "/usr/lib/systemd/system/openvpn-server@.service"]
    if not any(os.path.exists(path) for path in unit_paths):
        raise OvpnError(
            "no openvpn-server@.service unit on this system — the openvpn package is too old "
            "or built differently; upgrade the distribution or the openvpn package.")

    if not os.path.exists("/dev/net/tun"):
        run(["modprobe", "tun"], check=False)
    if not os.path.exists("/dev/net/tun"):
        raise OvpnError("/dev/net/tun is missing — enable TUN/TAP with your hosting provider (OpenVZ/LXC).")

    return {
        "openvpn": ".".join(map(str, ovpn)),
        "openssl": ".".join(map(str, ossl)),
        "distro": distro()["pretty"],
    }


# --------------------------------------------------------------------------- #
# Версии
# --------------------------------------------------------------------------- #
def _parse_version(text: str):
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        return (0, 0, 0)
    return tuple(int(match.group(i) or 0) for i in (1, 2, 3))


_ovpn_ver_cache = None


def openvpn_version():
    global _ovpn_ver_cache
    if _ovpn_ver_cache is None:
        proc = run(["openvpn", "--version"], check=False)
        head = (proc.stdout or "").splitlines()
        _ovpn_ver_cache = _parse_version(head[0] if head else "")
    return _ovpn_ver_cache


def openssl_version():
    proc = run(["openssl", "version"], check=False)
    return _parse_version(proc.stdout or "")


def openvpn_genkey(path: str) -> None:
    """`openvpn --genkey` меняет синтаксис между 2.4 и 2.5+ — поддерживаем оба."""
    if openvpn_version() >= (2, 5):
        run(["openvpn", "--genkey", "secret", path])
    else:
        run(["openvpn", "--genkey", "--secret", path])
    os.chmod(path, 0o600)


def openvpn_group() -> str:
    """nogroup в Debian/Ubuntu, но подстрахуемся."""
    import grp

    for candidate in ("nogroup", "nobody"):
        try:
            grp.getgrnam(candidate)
            return candidate
        except KeyError:
            continue
    return "nogroup"


# --------------------------------------------------------------------------- #
# systemd
# --------------------------------------------------------------------------- #
def systemctl(*args, check=True):
    return run(["systemctl"] + list(args), check=check)


def service_active(unit: str) -> bool:
    return run_ok(["systemctl", "is-active", "--quiet", unit])


def service_enabled(unit: str) -> bool:
    return run_ok(["systemctl", "is-enabled", "--quiet", unit])


def daemon_reload() -> None:
    systemctl("daemon-reload", check=False)


# --------------------------------------------------------------------------- #
# Сеть
# --------------------------------------------------------------------------- #
def default_nic() -> str:
    proc = run(["ip", "-4", "route", "show", "default"], check=False)
    match = re.search(r"\bdev\s+(\S+)", proc.stdout or "")
    if match:
        return match.group(1)
    proc = run(["ip", "-6", "route", "show", "default"], check=False)
    match = re.search(r"\bdev\s+(\S+)", proc.stdout or "")
    if match:
        return match.group(1)
    raise OvpnError("cannot detect the default network interface (use --nic).")


def nic_exists(name: str) -> bool:
    return os.path.exists("/sys/class/net/%s" % name)


def local_ipv4() -> str:
    proc = run(["ip", "-4", "-o", "addr", "show", "scope", "global"], check=False)
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", proc.stdout or "")
    return match.group(1) if match else ""


def is_private_ip(addr: str) -> bool:
    try:
        import ipaddress

        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def public_ip(timeout: int = 5) -> str:
    """Определяем внешний адрес; при отсутствии сети — локальный."""
    for url in (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
    ):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                addr = resp.read().decode().strip()
            socket.inet_aton(addr)
            return addr
        except Exception:
            continue
    return local_ipv4()


def port_in_use(port: int, proto: str) -> bool:
    flag = "-u" if proto == "udp" else "-t"
    proc = run(["ss", "-Hln", flag, "sport", "=", ":%d" % port], check=False)
    if proc.returncode != 0:
        return False
    return bool((proc.stdout or "").strip())


# Кандидаты для VPN-подсети: берём первую, не пересекающуюся с сетями сервера.
SUBNET_CANDIDATES = [
    "10.8.0.0/24", "10.9.0.0/24", "10.18.0.0/24", "10.28.0.0/24",
    "10.38.0.0/24", "172.27.0.0/24", "192.168.77.0/24", "192.168.87.0/24",
]


def used_networks():
    """Сети, уже занятые на сервере (адреса интерфейсов и таблица маршрутов)."""
    import ipaddress

    nets = []
    for cmd in (["ip", "-4", "-o", "addr", "show"], ["ip", "-4", "route", "show"]):
        out = run(cmd, check=False).stdout or ""
        for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+/\d+)", out):
            try:
                nets.append(ipaddress.IPv4Network(match.group(1), strict=False))
            except ValueError:
                continue
    return nets


def pick_subnet():
    """Свободная подсеть для VPN: не конфликтует с сетями хостинга/docker."""
    import ipaddress

    busy = used_networks()
    for candidate in SUBNET_CANDIDATES:
        net = ipaddress.IPv4Network(candidate)
        if not any(net.overlaps(existing) for existing in busy):
            return net
    warn("All standard VPN subnets are in use — using %s, check for conflicts."
         % SUBNET_CANDIDATES[0])
    return ipaddress.IPv4Network(SUBNET_CANDIDATES[0])


def enable_ip_forward(ipv6: bool = False) -> None:
    conf = ["net.ipv4.ip_forward = 1"]
    if ipv6:
        conf.append("net.ipv6.conf.all.forwarding = 1")
    write_file("/etc/sysctl.d/99-ovpnctl.conf", "\n".join(conf) + "\n", 0o644)
    run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"], check=False)
    if ipv6:
        run(["sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"], check=False)


# --------------------------------------------------------------------------- #
# Каталог выгрузки профилей: ~/ovpnctl у того, кто вызвал команду
# --------------------------------------------------------------------------- #
def target_user():
    """Пользователь, которому предназначены выгружаемые файлы.

    Под sudo это не root, а тот, кто запустил команду (SUDO_USER).
    """
    import pwd

    for name in (os.environ.get("SUDO_USER"), os.environ.get("USER")):
        if not name:
            continue
        try:
            return pwd.getpwnam(name)
        except KeyError:
            continue
    return pwd.getpwuid(os.getuid())


def user_output_dir() -> str:
    """~/ovpnctl вызвавшего пользователя; создаётся при необходимости."""
    entry = target_user()
    home = entry.pw_dir or "/root"
    path = os.path.join(home, "ovpnctl")
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
        os.chown(path, entry.pw_uid, entry.pw_gid)
    except OSError:
        pass
    return path


def give_to_user(path: str) -> str:
    """Отдать файл вызвавшему пользователю, чтобы его можно было забрать без sudo."""
    entry = target_user()
    try:
        os.chown(path, entry.pw_uid, entry.pw_gid)
    except OSError:
        pass
    return path


def is_openvpn_server_unit(name: str) -> bool:
    """Юнит серверного OpenVPN? Клиентские (openvpn-client@…) не трогаем:
    на сервере может стоять свой VPN-клиент, и он к нашей установке не относится."""
    if not name.endswith(".service"):
        return False
    if name.startswith("openvpn-client@"):
        return False
    return (name == "openvpn.service"
            or name.startswith("openvpn@")
            or name.startswith("openvpn-server@"))


def running_openvpn_units(exclude: str = "") -> list:
    """Активные службы серверного OpenVPN, кроме нашей — признак прежней установки."""
    proc = run(["systemctl", "list-units", "--type=service", "--state=active",
                "--plain", "--no-legend", "openvpn*.service"], check=False)
    units = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        name = parts[0] if parts else ""
        if name and name != exclude and is_openvpn_server_unit(name):
            units.append(name)
    return units


def system_facts() -> dict:
    dist = distro()
    return {
        "distro": dist["pretty"],
        "kernel": os.uname().release,
        "arch": os.uname().machine,
        "openvpn": ".".join(map(str, openvpn_version())),
        "openssl": ".".join(map(str, openssl_version())),
        "hostname": socket.gethostname(),
    }


def json_dump(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True)
