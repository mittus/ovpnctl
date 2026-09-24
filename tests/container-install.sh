#!/usr/bin/env bash
# Проверка установки «одной командой»: скрипт запускается через process substitution,
# исходников рядом нет — он должен сам скачать архив репозитория и всё развернуть.
# Роль GitHub играет локальный http.server, отдающий тот же путь archive/refs/heads/<ветка>.tar.gz.
set -u
export DEBIAN_FRONTEND=noninteractive
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  [ok]   $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
skip(){ echo "  [skip] $1"; }

echo "=== система: $(. /etc/os-release; echo "$PRETTY_NAME") ==="
# Заглушки systemd: в контейнере его нет, а postinst пакета openvpn его дёргает.
# Кладём в /usr/sbin — dpkg-скрипты не видят /usr/local/bin.
mkdir -p /run/systemd/system
for b in systemctl systemd-tmpfiles; do
    printf '#!/bin/sh\nexit 0\n' > "/usr/sbin/$b"; chmod +x "/usr/sbin/$b"
done
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
hash -r
# На снятых с поддержки выпусках (Debian 10) пакеты живут в archive.debian.org
fix_eol_repos() {
    apt-get update -qq >/dev/null 2>&1 && return 0
    if [ -f /etc/apt/sources.list ] && grep -qE 'deb\.debian\.org|security\.debian\.org' /etc/apt/sources.list; then
        sed -i -e 's|deb.debian.org|archive.debian.org|g' \
               -e 's|security.debian.org|archive.debian.org|g' \
               -e '/-updates/d' /etc/apt/sources.list
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive
        apt-get update -qq >/dev/null 2>&1
    fi
}
fix_eol_repos
apt-get install -y -qq --no-install-recommends python3 tar iproute2 >/dev/null 2>&1

# занимаем 10.8.0.0/24, чтобы проверить автоподбор свободной VPN-подсети
ip link add dummy0 type dummy 2>/dev/null && ip addr add 10.8.0.1/24 dev dummy0 2>/dev/null \
  && ip link set dummy0 up 2>/dev/null && echo "  (подсеть 10.8.0.0/24 занята искусственно)"

# собираем «репозиторий» так же, как его отдаёт GitHub: openvpn-master/<файлы>
mkdir -p /srv/repo/archive/refs/heads /build/openvpn-master
cp -a /src/lib /src/install.sh /src/uninstall.sh /src/VERSION /build/openvpn-master/ 2>/dev/null
tar -czf /srv/repo/archive/refs/heads/master.tar.gz -C /build openvpn-master
( cd /srv && python3 -m http.server 8000 >/dev/null 2>&1 & ) ; sleep 2
chk "локальный «GitHub» отвечает" "python3 -c \"import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/repo/archive/refs/heads/master.tar.gz')\""

echo; echo "=== запуск: bash <(cat install.sh) из пустого каталога ==="
cd /root
OVPN_REPO_URL=http://127.0.0.1:8000/repo OVPN_REPO_BRANCH=master \
  bash <(cat /src/install.sh) > /var/log/install.log 2>&1 </dev/null \
  && ok "установка одной командой прошла" || { bad "установка"; tail -25 /var/log/install.log; }
grep -E 'Downloading sources|Sources extracted' /var/log/install.log | sed 's/^/    /'

chk "исходники скачаны, а не взяты локально" "grep -q 'Downloading sources' /var/log/install.log"
chk "менеджер установлен"        "command -v ovpnctl"
chk "PKI создан"                 "test -f /etc/ovpnctl/pki/ca.crt"
chk "конфиг сервера на месте"    "test -f /etc/openvpn/server/server.conf"
chk "клиенты не создаются сами"  "[ -z \"$(ls -A /etc/ovpnctl/profiles 2>/dev/null)\" ]"
chk "в выводе есть подсказка про клиента" "grep -q 'ovpnctl client add' /var/log/install.log"
ovpnctl client add first >/dev/null 2>&1
chk "клиент создаётся командой"  "test -s /etc/ovpnctl/profiles/first.ovpn"
chk "адрес сервера определён автоматически" \
    "grep -qE 'remote ([0-9]{1,3}\.){3}[0-9]{1,3} 1194' /etc/ovpnctl/profiles/first.ovpn"
chk "протокол udp по умолчанию"    "grep -q '^proto udp' /etc/openvpn/server/server.conf"
chk "EC-ключи по умолчанию"        "openssl x509 -in /etc/ovpnctl/pki/ca.crt -noout -text | grep -q 'id-ecPublicKey'"
chk "DNS Cloudflare по умолчанию"  "grep -q 'dhcp-option DNS 1.1.1.1' /etc/openvpn/server/server.conf"
SUBNET=$(python3 -c "import json;print(json.load(open('/etc/ovpnctl/config.json'))['subnet'])")
[ "$SUBNET" != "10.8.0.0" ] && ok "занятая подсеть 10.8.0.0/24 обойдена, выбрана $SUBNET" \
    || bad "выбрана занятая подсеть 10.8.0.0/24"
chk "конфиг сервера использует выбранную подсеть" "grep -q \"server $SUBNET\" /etc/openvpn/server/server.conf"
chk "код разложен в /opt/ovpnctl" "test -f /opt/ovpnctl/lib/ovpnctl/cli.py"

echo; echo "=== повторный запуск = обновление ==="
CA_BEFORE=$(openssl x509 -in /etc/ovpnctl/pki/ca.crt -noout -fingerprint)
OVPN_REPO_URL=http://127.0.0.1:8000/repo OVPN_REPO_BRANCH=master \
  bash <(cat /src/install.sh) > /var/log/install2.log 2>&1 </dev/null \
  && ok "повторный запуск отработал" || { bad "повторный запуск"; tail -15 /var/log/install2.log; }
chk "сообщение про повторный запуск" "grep -q 'server was not recreated' /var/log/install2.log"
chk "видно, что код той же сборки"   "grep -q 'Code is already up to date' /var/log/install2.log"

# реальное обновление кода: портим установленный файл и ставим заново
sed -i 's/OpenVPN Management Script/ЗАМЕНЁННЫЙ ЗАГОЛОВОК/' /opt/ovpnctl/lib/ovpnctl/cli.py
OVPN_REPO_URL=http://127.0.0.1:8000/repo OVPN_REPO_BRANCH=master \
  bash <(cat /src/install.sh) > /var/log/install-upd.log 2>&1 </dev/null
chk "изменённый файл заменён свежим" \
    "! grep -q 'ЗАМЕНЁННЫЙ ЗАГОЛОВОК' /opt/ovpnctl/lib/ovpnctl/cli.py"
chk "в выводе видно обновление сборки" "grep -q 'Code updated: build' /var/log/install-upd.log"
chk "ovpnctl работает после обновления" "ovpnctl --version"
[ "$CA_BEFORE" = "$(openssl x509 -in /etc/ovpnctl/pki/ca.crt -noout -fingerprint)" ] \
  && ok "PKI не тронут" || bad "PKI перезаписан"
chk "профиль клиента на месте" "test -s /etc/ovpnctl/profiles/first.ovpn"
chk "повторный запуск применил конфиг без ошибок" "! grep -q 'Failed to apply' /var/log/install-upd.log"

echo; echo "=== ovpnctl update (без переустановки) ==="
chk "install.sh запомнил источник" "grep -q 'repo=http://127.0.0.1:8000/repo' /opt/ovpnctl/SOURCE"
ovpnctl update > /var/log/update1.log 2>&1 && ok "ovpnctl update отработал" \
    || { bad "ovpnctl update"; tail -15 /var/log/update1.log; }
chk "та же сборка — обновлять нечего" "grep -q 'Nothing to update' /var/log/update1.log"
sed -i 's/OpenVPN Management Script/ЗАМЕНЁННЫЙ ЗАГОЛОВОК/' /opt/ovpnctl/lib/ovpnctl/cli.py
ovpnctl update --check > /var/log/update2.log 2>&1
chk "--check видит новую сборку" "grep -q 'An update is available' /var/log/update2.log"
chk "--check ничего не меняет" "grep -q 'ЗАМЕНЁННЫЙ ЗАГОЛОВОК' /opt/ovpnctl/lib/ovpnctl/cli.py"
ovpnctl update > /var/log/update3.log 2>&1 && ok "ovpnctl update поставил сборку" \
    || { bad "ovpnctl update"; tail -15 /var/log/update3.log; }
sed 's/^/    /' /var/log/update3.log
chk "изменённый файл заменён из репозитория" "! grep -q 'ЗАМЕНЁННЫЙ ЗАГОЛОВОК' /opt/ovpnctl/lib/ovpnctl/cli.py"
chk "конфиг не менялся — сервер не перезапускали" "grep -q 'unchanged' /var/log/update3.log"
chk "временных каталогов не осталось" "[ ! -e /opt/ovpnctl/lib.new ] && [ ! -e /opt/ovpnctl/lib.old ]"
[ "$CA_BEFORE" = "$(openssl x509 -in /etc/ovpnctl/pki/ca.crt -noout -fingerprint)" ] \
  && ok "PKI не тронут обновлением" || bad "PKI перезаписан обновлением"

echo; echo "=== сервер, где OpenVPN уже стоял вручную ==="
cp /src/install.sh /tmp/install.sh
ENVV="OVPN_REPO_URL=http://127.0.0.1:8000/repo OVPN_REPO_BRANCH=master"
make_old() {
    mkdir -p /etc/openvpn/server
    printf 'port 1194\nproto udp\ndev tun\n' > /etc/openvpn/server/manual.conf
    printf 'port 1194\n' > /etc/openvpn/old-style.conf
}

# --- без терминала: ничего не трогаем, только предупреждаем ---
ovpnctl uninstall -y >/dev/null 2>&1; make_old
env $ENVV bash /tmp/install.sh > /var/log/install-over.log 2>&1 </dev/null \
  && ok "установка поверх ручной прошла" || { bad "установка поверх ручной"; tail -15 /var/log/install-over.log; }
chk "предупреждение про прежнюю конфигурацию" \
    "grep -q 'Found an existing OpenVPN configuration' /var/log/install-over.log"
chk "чужие конфиги перечислены"        "grep -q 'manual.conf' /var/log/install-over.log"
chk "сделана резервная копия /etc/openvpn" \
    "ls /etc/ovpnctl/backup/openvpn-before-ovpnctl-*.tar.gz"
chk "без терминала чужой конфиг не тронут" "test -f /etc/openvpn/server/manual.conf"
chk "наш сервер настроен"              "test -f /etc/openvpn/server/server.conf"

if command -v script >/dev/null 2>&1; then
    # --- ответ Y: прежний сервер убираем, ставим на стандартных параметрах ---
    ip link delete dummy0 2>/dev/null || true   # освобождаем 10.8.0.0/24, занятый в начале теста
    ovpnctl uninstall -y >/dev/null 2>&1; make_old
    printf 'y\n' | script -qec "env $ENVV bash /tmp/install.sh" /dev/null > /var/log/install-y.log 2>&1
    chk "предложено удалить прежний сервер" \
        "grep -q 'Remove the existing server' /var/log/install-y.log"
    chk "прежние конфиги убраны из /etc/openvpn" \
        "! test -f /etc/openvpn/server/manual.conf -o -f /etc/openvpn/old-style.conf"
    chk "конфиги сохранены в архиве"   "ls -d /etc/ovpnctl/backup/previous-openvpn-*"
    chk "порт стандартный 1194"        "grep -q '\"port\": 1194' /etc/ovpnctl/config.json"
    chk "подсеть стандартная 10.8.0.0" "grep -q '\"subnet\": \"10.8.0.0\"' /etc/ovpnctl/config.json"
    chk "сервер поставлен"             "test -f /etc/openvpn/server/server.conf"
    ovpnctl client add clean >/dev/null 2>&1
    chk "клиент выпускается после переезда" "test -s /etc/ovpnctl/profiles/clean.ovpn"

    # --- ответ N, затем смена порта у нового сервера ---
    ovpnctl uninstall -y >/dev/null 2>&1; make_old
    printf 'n\nn\n1195\n' | script -qec "env $ENVV bash /tmp/install.sh" /dev/null > /var/log/install-n.log 2>&1
    chk "предложена смена порта"       "grep -q 'Port for the new server' /var/log/install-n.log"
    chk "новый сервер встал на 1195"   "grep -q '\"port\": 1195' /etc/ovpnctl/config.json"
    chk "прежние конфиги остались на месте" "test -f /etc/openvpn/server/manual.conf"
    rm -f /etc/openvpn/server/manual.conf /etc/openvpn/old-style.conf
else
    skip "утилита script недоступна — интерактивные ветки не проверены"
fi

echo; echo "=== установка поверх настроенного сервера запрещена ==="
ovpnctl setup >/var/log/setup-again.log 2>&1 && bad "setup согласился поставить поверх" \
    || ok "setup отказывается ставить поверх"
chk "в отказе есть подсказка про uninstall" "grep -q 'ovpnctl uninstall' /var/log/setup-again.log"

echo; echo "=== чистая переустановка: uninstall + установка ==="
CA_OLD=$(openssl x509 -in /etc/ovpnctl/pki/ca.crt -noout -fingerprint)
ovpnctl uninstall -y >/var/log/uninstall.log 2>&1 && ok "uninstall отработал" || bad "uninstall"
chk "состояние сохранено в архив /root" "ls /root/ovpnctl-backup-*.tar.gz"
chk "каталог /etc/ovpnctl удалён"       "! test -d /etc/ovpnctl"
OVPN_REPO_URL=http://127.0.0.1:8000/repo OVPN_REPO_BRANCH=master \
  bash <(cat /src/install.sh) > /var/log/install3.log 2>&1 </dev/null \
  && ok "повторная установка с нуля прошла" || { bad "повторная установка"; tail -15 /var/log/install3.log; }
[ "$CA_OLD" != "$(openssl x509 -in /etc/ovpnctl/pki/ca.crt -noout -fingerprint)" ] \
  && ok "создан новый CA (чистая установка)" || bad "CA остался прежним"
chk "свой прежний конфиг не считается чужим" \
    "! grep -q 'Found an existing OpenVPN configuration' /var/log/install3.log"

echo; echo "============================================================"
echo "ИТОГ: пройдено $PASS, провалено $FAIL"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
