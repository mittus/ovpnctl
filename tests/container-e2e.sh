#!/usr/bin/env bash
# End-to-end проверка ovpnctl внутри контейнера: установка, запуск демона,
# подключение настоящего клиента по .ovpn, отзыв доступа.
set -u
export DEBIAN_FRONTEND=noninteractive
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  [ok]   $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }
skip(){ echo "  [skip] $1"; }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
# меню в псевдотерминале цветное — для grep снимаем ANSI-коды
strip_ansi(){ sed -i 's/\x1b\[[0-9;]*m//g' "$1"; }

echo "=== система: $(. /etc/os-release; echo "$PRETTY_NAME") ==="
# Заглушки systemd: в контейнере его нет, а postinst пакета openvpn его дёргает.
# Кладём в /usr/sbin — dpkg-скрипты не видят /usr/local/bin.
mkdir -p /run/systemd/system
for b in systemctl systemd-tmpfiles; do
    printf '#!/bin/sh\nexit 0\n' > "/usr/sbin/$b"; chmod +x "/usr/sbin/$b"
done
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
hash -r
# вспомогательные утилиты для самого теста (не зависимости ovpnctl)
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
apt-get install -y -qq --no-install-recommends iputils-ping procps iproute2 >/dev/null 2>&1

# systemd в контейнере нет: подсовываем заглушку, службы поднимем вручную

echo; echo "=== 1. install.sh ==="
cd /src || exit 1
if bash install.sh > /var/log/install.log 2>&1 </dev/null; then
    ok "install.sh отработал"
else
    bad "install.sh упал"; tail -30 /var/log/install.log
fi
# клиент и сервер в одном контейнере — переключаем точку входа на loopback
ovpnctl set --endpoint 127.0.0.1 >/dev/null 2>&1 && ok "ovpnctl set --endpoint 127.0.0.1" \
    || bad "ovpnctl set --endpoint"
chk "после установки клиентов нет" "[ -z \"$(ls -A /etc/ovpnctl/profiles 2>/dev/null)\" ]"
ovpnctl client add tester >/dev/null 2>&1 && ok "ovpnctl client add tester" || bad "ovpnctl client add tester"
grep -E '^\[ovpnctl-install\]' /var/log/install.log | tail -12

echo; echo "=== 2. артефакты ==="
chk "бинарь ovpnctl"            "command -v ovpnctl"
chk "config.json"               "test -f /etc/ovpnctl/config.json"
chk "CA"                        "test -f /etc/ovpnctl/pki/ca.crt"
chk "server.conf"               "test -f /etc/openvpn/server/server.conf"
if command -v runuser >/dev/null 2>&1; then
    chk "crl.pem читается пользователем nobody" "runuser -u nobody -- test -r /etc/openvpn/server/crl.pem"
else
    chk "crl.pem читается пользователем nobody" "su -s /bin/sh nobody -c 'test -r /etc/openvpn/server/crl.pem'"
fi
chk "профиль клиента создан"    "test -f /etc/ovpnctl/profiles/tester.ovpn"
chk "юнит-файлы созданы"        "test -f /etc/systemd/system/ovpnctl-renew.timer -a -f /etc/systemd/system/ovpnctl-firewall.service"
chk "drop-in создаёт /run/openvpn-server" "grep -q RuntimeDirectory=openvpn-server /etc/systemd/system/openvpn-server@server.service.d/ovpnctl.conf"
chk "drop-in требует ovpnctl-firewall" "grep -q 'Requires=ovpnctl-firewall.service' /etc/systemd/system/openvpn-server@server.service.d/ovpnctl.conf"
chk "каталог /run/openvpn-server создан" "test -d /run/openvpn-server"
echo "  версия openvpn: $(openvpn --version | head -1 | awk '{print $2}'), openssl: $(openssl version | awk '{print $2}')"

echo; echo "=== 3. правила файрвола ==="
if /etc/ovpnctl/firewall.sh up >/dev/null 2>&1; then
    chk "MASQUERADE добавлен" "iptables -t nat -S POSTROUTING | grep -q MASQUERADE"
else
    bad "firewall.sh up (нет NET_ADMIN?)"
fi

echo; echo "=== 4. запуск сервера с нашим server.conf ==="
mkdir -p /run/openvpn-server
openvpn --config /etc/openvpn/server/server.conf --daemon --log /var/log/ovpn-server.log
sleep 4
chk "процесс openvpn жив"       "pgrep -f 'openvpn --config /etc/openvpn/server' >/dev/null"
chk "интерфейс tun0 поднят"     "ip addr show tun0"
chk "нет ошибок в логе сервера" "! grep -qiE '^Options error|Fatal|cannot|error:' /var/log/ovpn-server.log"
grep -E 'Initialization Sequence|OpenVPN 2|Diffie|Control Channel' /var/log/ovpn-server.log | tail -4

echo; echo "=== 5. подключение настоящего клиента по .ovpn ==="
ovpnctl client add phone > /var/log/add.log 2>&1 && ok "ovpnctl client add phone" || bad "ovpnctl client add phone"
sed 's/^/    /' /var/log/add.log
chk "в выводе один путь — в каталоге пользователя" "grep -q 'Profile: /root/ovpnctl/phone.ovpn' /var/log/add.log"
chk "лишних подсказок нет" "! grep -qE 'Storage|scp|cat ' /var/log/add.log"
chk "в выводе ровно одна строка с путём" "[ \"$(grep -c '/root/ovpnctl/phone.ovpn' /var/log/add.log)\" = 1 ]"
cp /etc/ovpnctl/profiles/phone.ovpn /root/phone-backup.ovpn
openvpn --config /etc/ovpnctl/profiles/phone.ovpn --route-nopull --daemon \
        --log /var/log/ovpn-client.log
sleep 8
if grep -q "Initialization Sequence Completed" /var/log/ovpn-client.log; then
    ok "клиент подключился (Initialization Sequence Completed)"
else
    bad "клиент не подключился"; tail -20 /var/log/ovpn-client.log
fi
chk "у клиента есть tun-интерфейс с адресом 10.8.0.x" "ip -4 addr | grep -q '10\.8\.0\.'"
chk "пинг до сервера VPN 10.8.0.1" "ping -c 2 -W 3 10.8.0.1"
echo "  --- закреплённые адреса не пересекаются с пулом ---"
chk "обычный клиент получил первый адрес пула 10.8.0.10" "ip -4 addr | grep -q 'inet 10\\.8\\.0\\.10/'"
chk "адрес из пула не закрепляется (client add --ip 10.8.0.50)" "! ovpnctl client add badpin --ip 10.8.0.50 >/dev/null 2>&1 && test ! -e /etc/ovpnctl/pki/issued/badpin.crt"
ovpnctl client add pinned --ip 10.8.0.3 >/dev/null 2>&1 && ok "ovpnctl client add pinned --ip 10.8.0.3" || bad "ovpnctl client add pinned --ip 10.8.0.3"
chk "занятый адрес не закрепляется за другим" "! ovpnctl client ip phone 10.8.0.3 >/dev/null 2>&1"
openvpn --config /etc/ovpnctl/profiles/pinned.ovpn --dev tun7 --route-nopull --daemon \
        --log /var/log/ovpn-pinned.log
sleep 8
chk "закреплённый клиент получил свой 10.8.0.3" "ip -4 addr show tun7 | grep -q 'inet 10\\.8\\.0\\.3/'"
pkill -f ovpn-pinned.log; sleep 1
ovpnctl client delete pinned -y >/dev/null 2>&1
echo "  --- выгрузка профиля в личный каталог пользователя ---"
chk "client add кладёт профиль в ~/ovpnctl" "test -s /root/ovpnctl/phone.ovpn"
chk "содержимое совпадает с хранилищем" \
    "[ \"$(md5sum < /root/ovpnctl/phone.ovpn)\" = \"$(md5sum < /etc/ovpnctl/profiles/phone.ovpn)\" ]"
chk "права профиля 0600" "[ \"$(stat -c %a /root/ovpnctl/phone.ovpn)\" = 600 ]"
chk "каталог ~/ovpnctl закрыт (0700)" "[ \"$(stat -c %a /root/ovpnctl)\" = 700 ]"

# под sudo профиль должен уходить вызвавшему пользователю, а не root
useradd -m vpnuser >/dev/null 2>&1
SUDO_USER=vpnuser ovpnctl client add fromsudo >/dev/null 2>&1
chk "под sudo профиль уходит в /home/vpnuser/ovpnctl" "test -s /home/vpnuser/ovpnctl/fromsudo.ovpn"
chk "владелец файла — вызвавший пользователь" \
    "[ \"$(stat -c %U /home/vpnuser/ovpnctl/fromsudo.ovpn)\" = vpnuser ]"
chk "владелец каталога — вызвавший пользователь" \
    "[ \"$(stat -c %U /home/vpnuser/ovpnctl)\" = vpnuser ]"
ovpnctl client delete fromsudo -y >/dev/null 2>&1

chk "в списке клиентов виден адрес подключённого" \
    "ovpnctl client list | grep phone | grep -qE '10\\.8\\.0\\.[0-9]+'"
chk "в списке клиентов есть колонка трафика" "ovpnctl client list | grep -q 'TRAFFIC'"
chk "ovpnctl traffic: у подключённого клиента трафик текущей сессии" \
    "ovpnctl traffic | grep phone | grep -qE '[0-9.]+ (KiB|MiB)'"
chk "ovpnctl traffic phone: разбивка по периодам" \
    "ovpnctl traffic phone | grep -q 'Last hour' && ovpnctl traffic phone | grep -q 'Last 12 hours' && ovpnctl traffic phone | grep -q 'All time'"
chk "таймер сбора трафика создан" "test -f /etc/systemd/system/ovpnctl-traffic.timer"
echo "  --- ovpnctl traffic ---"; ovpnctl traffic
echo "  --- ovpnctl traffic phone ---"; ovpnctl traffic phone
echo "  --- ovpnctl client list ---"; ovpnctl client list
echo "  --- ovpnctl online ---"; ovpnctl online
echo "  --- ovpnctl status (фрагмент) ---"; ovpnctl status 2>&1 | head -14

echo; echo "=== 5б. интерактивное меню (через псевдотерминал) ==="
if command -v script >/dev/null 2>&1; then
    printf '2\n0\n6\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu.log 2>&1; strip_ansi /var/log/menu.log
    chk "меню отрисовано рамкой"          "grep -q 'OpenVPN Management Script' /var/log/menu.log"
    chk "есть сводка состояния"           "grep -q 'OpenVPN state' /var/log/menu.log"
    chk "над OpenVPN state — версия и сборка ovpnctl" \
        "grep -B1 'OpenVPN state' /var/log/menu.log | grep -qE \"ovpnctl version: $(cat /src/VERSION) \\(build [0-9a-f]{8}\\)\""
    chk "приглашение с диапазоном 0-16"   "grep -q 'enter your selection \[0-16\]' /var/log/menu.log"
    chk "пункт 2 показал список клиентов" "grep -q 'STATUS' /var/log/menu.log"
    chk "в списке есть колонки ADDRESS, FROM, LAST CONNECTED, TRAFFIC" \
        "grep 'ADDRESS' /var/log/menu.log | grep 'FROM' | grep 'LAST CONNECTED' | grep -q 'TRAFFIC'"
    chk "в списке у онлайн-клиента виден трафик" \
        "grep -E 'phone +online' /var/log/menu.log | grep -qE '[0-9.]+ (B|KiB|MiB)'"
    chk "из списка предлагают открыть карточку клиента" \
        "grep -q 'Client number or name for details' /var/log/menu.log"
    chk "пункт 2 называется «Client List»" "grep -qE '2\\. Client List +│' /var/log/menu.log"
    chk "пункт 3 называется «Client Certificates»" "grep -qE '3\\. Client Certificates +│' /var/log/menu.log"
    chk "отдельных пунктов Online Clients и Traffic нет" \
        "! grep -qE '[0-9]\\. (Online Clients|Traffic) ' /var/log/menu.log"
    chk "пункт 6 показал статус сервера"  "grep -q 'Endpoint:' /var/log/menu.log"
    chk "результат ждёт Enter, а не затирается меню" \
        "grep -q 'return to the menu' /var/log/menu.log"
    chk "пункта показа .ovpn в меню больше нет" \
        "! grep -q 'Show .ovpn' /var/log/menu.log"
    chk "отзыва в меню нет"               "! grep -q 'Revoke Client' /var/log/menu.log"
    chk "команда revoke осталась в CLI"   "ovpnctl client revoke --help"

    # карточка клиента по номеру: сессия, периоды трафика, p выводит профиль
    printf '2\n1\np\n\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu3.log 2>&1; strip_ansi /var/log/menu3.log
    chk "карточка клиента открывается по номеру" "grep -q 'Client phone — online' /var/log/menu3.log"
    chk "в карточке текущая сессия"       "grep -q 'This session:' /var/log/menu3.log"
    chk "в карточке трафик по периодам"   "grep -q 'Week (7 days)' /var/log/menu3.log"
    chk "p в карточке выводит профиль"    "grep -q 'BEGIN CERTIFICATE' /var/log/menu3.log"

    # создание клиента спрашивает только имя
    printf '1\nmenuclient\nn\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu5.log 2>&1; strip_ansi /var/log/menu5.log
    chk "клиент создан из меню"           "test -s /etc/ovpnctl/profiles/menuclient.ovpn"
    chk "при создании спрашивают только имя" \
        "! grep -qE 'lifetime|Pin address' /var/log/menu5.log"
    chk "после создания предлагают вывести профиль" \
        "grep -q 'Print the profile' /var/log/menu5.log"

    # Client Certificates: продление и приостановка
    printf '3\nmenuclient\n0\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu-cert.log 2>&1; strip_ansi /var/log/menu-cert.log
    chk "экран сертификатов: таблица со сроками" \
        "grep -q 'Client certificates' /var/log/menu-cert.log && grep -q 'EXPIRES' /var/log/menu-cert.log"
    chk "экран сертификатов: действия продлить и приостановить" \
        "grep -q 'Renew certificate' /var/log/menu-cert.log && grep -q 'Suspend access' /var/log/menu-cert.log"
    printf '3\nmenuclient\n2\ny\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu-cert2.log 2>&1; strip_ansi /var/log/menu-cert2.log
    chk "приостановка из меню"            "ovpnctl client list | grep -qE 'menuclient +suspended'"
    chk "в сводке под меню видно приостановленных" "grep -q 'suspended: 1' /var/log/menu-cert2.log"
    printf '3\nmenuclient\n2\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu-cert3.log 2>&1; strip_ansi /var/log/menu-cert3.log
    chk "для приостановленного предлагают Resume access" "grep -q 'Resume access' /var/log/menu-cert3.log"
    chk "включение из меню"               "! ovpnctl client list | grep -qE 'menuclient +suspended'"
    printf '3\nmenuclient\n1\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu-cert4.log 2>&1; strip_ansi /var/log/menu-cert4.log
    chk "продление из меню"               "grep -q \"Certificate 'menuclient' renewed\" /var/log/menu-cert4.log"
    ovpnctl client delete menuclient -y >/dev/null 2>&1

    printf '4\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu4.log 2>&1; strip_ansi /var/log/menu4.log
    chk "Enter в запросе сразу возвращает в меню" \
        "[ \"$(grep -c 'enter your selection' /var/log/menu4.log)\" -ge 2 ]"
    chk "без лишнего «Нажмите Enter»"     "! grep -q 'Press Enter' /var/log/menu4.log"
    printf '2\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu6.log 2>&1; strip_ansi /var/log/menu6.log
    chk "0 после списка клиентов сразу возвращает в меню" \
        "[ \"$(grep -c 'enter your selection' /var/log/menu6.log)\" -ge 2 ] && ! grep -q 'Press Enter' /var/log/menu6.log"
    # r обновляет оба экрана; Enter с карточки — к списку, 0 из списка — в главное меню
    printf '2\nr\nphone\nr\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu8.log 2>&1; strip_ansi /var/log/menu8.log
    chk "список: r обновляет, Enter с карточки возвращает к списку" \
        "[ \"$(grep -c 'online first, then by last connection' /var/log/menu8.log)\" -eq 3 ]"
    chk "карточка: r обновляет"           "[ \"$(grep -c 'Client phone — online' /var/log/menu8.log)\" -eq 2 ]"
    chk "список: 0 — сразу в главное меню" \
        "[ \"$(grep -c 'enter your selection' /var/log/menu8.log)\" -eq 2 ] && ! grep -q 'Press Enter' /var/log/menu8.log"

    printf '4\nphone\nn\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu2.log 2>&1; strip_ansi /var/log/menu2.log
    chk "подтверждение предлагает Y/n"  "grep -q '\[Y/n\]\|\[y/N\]' /var/log/menu2.log"
    chk "ответ n отменил удаление"      "ovpnctl client list | grep -q 'phone .*offline\|phone .*online'"
else
    skip "утилита script недоступна — меню не проверено"
fi

echo; echo "=== 5в. приостановка доступа с живым подключением ==="
SRV_LOG_MARK=$(wc -l < /var/log/ovpn-server.log)
ovpnctl client suspend phone > /var/log/suspend.log 2>&1 && ok "ovpnctl client suspend phone" || bad "ovpnctl client suspend phone"
chk "активная сессия разорвана сразу" "grep -q 'session terminated' /var/log/suspend.log"
pkill -f 'openvpn --config /etc/ovpnctl/profiles/phone.ovpn'; sleep 2
: > /var/log/ovpn-client-susp.log
openvpn --config /etc/ovpnctl/profiles/phone.ovpn --route-nopull --daemon --log /var/log/ovpn-client-susp.log
sleep 12
chk "приостановленный клиент не подключается тем же профилем" \
    "! grep -q 'Initialization Sequence Completed' /var/log/ovpn-client-susp.log"
chk "сервер отклонил его директивой disable" \
    "tail -n +$SRV_LOG_MARK /var/log/ovpn-server.log | grep -q \"rejected due to 'disable' directive\""
tail -n +$SRV_LOG_MARK /var/log/ovpn-server.log | grep -i 'disable' | tail -2 | sed 's/^/    /'
# отклонённый висит в status-файле до delayed-exit (~5 с), файл пишется раз в 10 с
sleep 12
chk "приостановленный не в списке онлайн" "! ovpnctl online | grep -q phone"
chk "статус suspended в списке клиентов" "ovpnctl client list | grep -qE 'phone +suspended'"
pkill -f 'openvpn --config /etc/ovpnctl/profiles/phone.ovpn'; sleep 2
ovpnctl client resume phone >/dev/null 2>&1 && ok "ovpnctl client resume phone" || bad "ovpnctl client resume phone"
: > /var/log/ovpn-client.log
openvpn --config /etc/ovpnctl/profiles/phone.ovpn --route-nopull --daemon --log /var/log/ovpn-client.log
sleep 8
chk "после resume тот же профиль снова подключается" \
    "grep -q 'Initialization Sequence Completed' /var/log/ovpn-client.log"


echo; echo "=== 6. отзыв доступа ==="
ovpnctl client revoke phone -y >/dev/null 2>&1 && ok "client revoke отработал" || bad "client revoke"
chk "серийник в CRL" "openssl crl -in /etc/openvpn/server/crl.pem -noout -text | grep -q 'Serial Number'"
sleep 1
chk "openvpn (от nobody) записал трафик завершённой сессии" \
    "ovpnctl traffic >/dev/null && grep -q '\"phone\"' /etc/ovpnctl/traffic.json"
chk "у отозванного клиента трафик за последний час = за сегодня = за всё время" \
    "ovpnctl traffic phone --json | python3 -c 'import json,sys; r={p[\"period\"]: p for p in json.load(sys.stdin)}; sys.exit(0 if r[\"1h\"][\"total\"] > 0 and r[\"1h\"][\"total\"] == r[\"day\"][\"total\"] and r[\"day\"][\"total\"] == r[\"all\"][\"total\"] else 1)'"
pkill -f 'openvpn --config /etc/ovpnctl/profiles/phone.ovpn'; sleep 2
SRV_LOG_MARK=$(wc -l < /var/log/ovpn-server.log)
: > /var/log/ovpn-client2.log
openvpn --config /root/phone-backup.ovpn --route-nopull --daemon --log /var/log/ovpn-client2.log 2>/dev/null
sleep 12
tail -n +$SRV_LOG_MARK /var/log/ovpn-server.log > /tmp/srv-after-revoke.log
if grep -qiE 'CRL|revoked' /tmp/srv-after-revoke.log; then
    ok "сервер отверг отозванный сертификат по CRL"
    grep -iE 'CRL|revoked' /tmp/srv-after-revoke.log | head -3 | sed 's/^/    /'
else
    bad "в логе сервера нет отказа по CRL"; tail -15 /tmp/srv-after-revoke.log
fi
if grep -q "Initialization Sequence Completed" /var/log/ovpn-client2.log; then
    bad "отозванный клиент всё-таки подключился"
else
    ok "отозванный клиент туннель не поднял"
fi
pkill -f 'openvpn --config /root/phone-backup.ovpn' 2>/dev/null

echo; echo "=== 7. автопродление и диагностика ==="
cp /etc/ovpnctl/profiles/tester.ovpn /root/tester-before-rotation.ovpn
ovpnctl pki check 2>&1 | head -8
ovpnctl pki renew --force >/dev/null 2>&1 && ok "pki renew --force отработал" || bad "pki renew --force"
chk "лог продления записан" "test -s /var/log/ovpnctl/renew.log"
tail -4 /var/log/ovpnctl/renew.log
ovpnctl doctor 2>&1 | tail -12

echo; echo "=== 8. ротация CA не рвёт уже выданные профили ==="
# systemd-заглушка службу не перезапускает — делаем это руками
pkill -f "openvpn --config /etc/openvpn/server" ; sleep 2
: > /var/log/ovpn-server2.log
openvpn --config /etc/openvpn/server/server.conf --daemon --log /var/log/ovpn-server2.log
sleep 4
if pgrep -f 'openvpn --config /etc/openvpn/server' >/dev/null; then
    ok "сервер поднялся с перевыпущенным сертификатом"
else
    bad "сервер не поднялся после ротации PKI"
    echo "    --- лог сервера ---"; tail -25 /var/log/ovpn-server2.log | sed 's/^/    /'
    echo "    --- файлы ---"; ls -l /etc/openvpn/server/ | sed 's/^/    /'
    echo "    --- проверка пары ключ/сертификат ---"
    openssl x509 -in /etc/openvpn/server/server.crt -noout -pubkey | md5sum | sed 's/^/    cert: /'
    openssl pkey -in /etc/openvpn/server/server.key -pubout | md5sum | sed 's/^/    key:  /'
    openssl verify -CAfile /etc/openvpn/server/ca.crt /etc/openvpn/server/server.crt | sed 's/^/    /'
fi
: > /var/log/ovpn-old-profile.log
openvpn --config /root/tester-before-rotation.ovpn --route-nopull --daemon --log /var/log/ovpn-old-profile.log
sleep 10
if grep -q "Initialization Sequence Completed" /var/log/ovpn-old-profile.log; then
    ok "СТАРЫЙ профиль (выданный до ротации CA) продолжает подключаться"
else
    bad "старый профиль перестал работать после ротации CA"
    tail -15 /var/log/ovpn-old-profile.log
fi
grep -E "VERIFY OK: depth=1|Initialization Sequence" /var/log/ovpn-old-profile.log | head -3 | sed "s/^/    /"
pkill -f "openvpn --config /root/tester-before-rotation.ovpn"; sleep 1
: > /var/log/ovpn-new-profile.log
openvpn --config /etc/ovpnctl/profiles/tester.ovpn --route-nopull --daemon --log /var/log/ovpn-new-profile.log
sleep 10
if grep -q "Initialization Sequence Completed" /var/log/ovpn-new-profile.log; then
    ok "обновлённый профиль тоже подключается"
else
    bad "обновлённый профиль не подключается"; tail -15 /var/log/ovpn-new-profile.log
fi
pkill -f "openvpn --config /etc/ovpnctl/profiles/tester.ovpn"

echo; echo "=== 8б. сброс статистики трафика ==="
if command -v script >/dev/null 2>&1; then
    # карточка клиента: c → подтверждение y → Enter → Enter (к списку) → 0 (в главное меню)
    printf '2\ntester\nc\ny\n\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu9.log 2>&1; strip_ansi /var/log/menu9.log
    chk "меню: сброс клиента с подтверждением" \
        "grep -q \"Reset traffic statistics of client 'tester'\" /var/log/menu9.log && grep -q \"statistics of client 'tester' reset\" /var/log/menu9.log"
    printf '2\nc\nn\n\n0\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu10.log 2>&1; strip_ansi /var/log/menu10.log
    chk "меню: общий сброс спрашивает, ответ n ничего не сбрасывает" \
        "grep -q 'Reset traffic statistics of ALL clients' /var/log/menu10.log && grep -q 'Nothing was reset' /var/log/menu10.log"
fi
chk "без -y команда не сбрасывает молча" "! ovpnctl traffic --reset </dev/null"
chk "ovpnctl traffic --reset -y сбрасывает всех" "ovpnctl traffic --reset -y | grep -q 'reset for'"
chk "после общего сброса всё по нулям" \
    "ovpnctl traffic --json | python3 -c 'import json,sys; sys.exit(0 if all(r[\"total\"] == 0 for r in json.load(sys.stdin)) else 1)'"
chk "сброс неизвестного клиента — ошибка" "! ovpnctl traffic nosuch --reset -y"

echo; echo "=== 9. selftest в контейнере ==="
python3 /src/tests/selftest.py 2>&1 | tail -3

echo; echo "============================================================"
echo "ИТОГ: пройдено $PASS, провалено $FAIL"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
