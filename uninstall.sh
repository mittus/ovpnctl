#!/usr/bin/env bash
# Полное удаление ovpnctl и конфигурации OpenVPN.
#   sudo bash uninstall.sh [-y] [--keep-pki] [--purge]
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "root privileges required" >&2; exit 1; }

if command -v ovpnctl >/dev/null 2>&1; then
    ovpnctl uninstall "$@"
else
    echo "ovpnctl not found — removing files manually" >&2
    systemctl disable --now openvpn-server@server.service ovpnctl-renew.timer \
        ovpnctl-firewall.service ovpnctl-traffic.timer 2>/dev/null || true
    [ -x /etc/ovpnctl/firewall.sh ] && /etc/ovpnctl/firewall.sh down || true
    rm -rf /etc/ovpnctl /etc/systemd/system/ovpnctl-*.service \
           /etc/systemd/system/ovpnctl-*.timer \
           /etc/systemd/system/openvpn-server@server.service.d \
           /etc/sysctl.d/99-ovpnctl.conf
    systemctl daemon-reload
fi

rm -rf /opt/ovpnctl /usr/local/bin/ovpnctl
echo "ovpnctl removed."
