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
chk "в выводе один путь — в каталоге пользователя" "grep -q 'Профиль: /root/ovpnctl/phone.ovpn' /var/log/add.log"
chk "лишних подсказок нет" "! grep -qE 'Хранилище|scp|cat ' /var/log/add.log"
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
chk "в списке клиентов есть колонка ТРАФИК" "ovpnctl client list | grep -q 'ТРАФИК'"
chk "у подключённого клиента трафик текущей сессии" \
    "ovpnctl client list | grep phone | grep -qE '[0-9.]+ (КиБ|МиБ)'"
echo "  --- ovpnctl client list ---"; ovpnctl client list
echo "  --- ovpnctl online ---"; ovpnctl online
echo "  --- ovpnctl status (фрагмент) ---"; ovpnctl status 2>&1 | head -14

echo; echo "=== 5б. интерактивное меню (через псевдотерминал) ==="
if command -v script >/dev/null 2>&1; then
    printf '2\n\n\n7\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu.log 2>&1
    chk "меню отрисовано рамкой"          "grep -q 'управление OpenVPN' /var/log/menu.log"
    chk "есть сводка состояния"           "grep -q 'Служба OpenVPN' /var/log/menu.log"
    chk "приглашение с диапазоном"        "grep -q 'Выберите пункт \[0-' /var/log/menu.log"
    chk "пункт 2 показал список клиентов" "grep -q 'СТАТУС' /var/log/menu.log"
    chk "в списке есть колонка АДРЕС"     "grep -q 'АДРЕС' /var/log/menu.log"
    chk "после списка предлагают вывести .ovpn" \
        "grep -q 'Вывести .ovpn клиента' /var/log/menu.log"
    chk "пункт 7 показал статус сервера"  "grep -q 'Точка входа' /var/log/menu.log"
    chk "результат ждёт Enter, а не затирается меню" \
        "grep -q 'вернуться в меню' /var/log/menu.log"
    chk "пункта показа .ovpn в меню больше нет" \
        "! grep -q 'Показать .ovpn в консоли' /var/log/menu.log"
    chk "пункт 'Клиенты онлайн' на третьем месте" \
        "grep -qE '3\\. Клиенты онлайн' /var/log/menu.log"
    chk "отзыва в меню нет"               "! grep -q 'Отозвать клиента' /var/log/menu.log"
    chk "команда revoke осталась в CLI"   "ovpnctl client revoke --help"

    # выбор клиента номером прямо из списка выводит его профиль
    printf '2\n1\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu3.log 2>&1
    chk "профиль выводится по номеру из списка" "grep -q 'BEGIN CERTIFICATE' /var/log/menu3.log"

    # создание клиента спрашивает только имя
    printf '1\nmenuclient\nn\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu5.log 2>&1
    chk "клиент создан из меню"           "test -s /etc/ovpnctl/profiles/menuclient.ovpn"
    chk "при создании спрашивают только имя" \
        "! grep -qE 'Срок сертификата|Закрепить адрес' /var/log/menu5.log"
    chk "после создания предлагают вывести профиль" \
        "grep -q 'Вывести профиль на экран' /var/log/menu5.log"
    ovpnctl client delete menuclient -y >/dev/null 2>&1

    printf '5\n\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu4.log 2>&1
    chk "пустой ввод возвращает в меню"   "grep -q 'Возврат в меню' /var/log/menu4.log"
    chk "после возврата меню снова на экране" \
        "[ \"$(grep -c 'Выберите пункт' /var/log/menu4.log)\" -ge 2 ]"

    printf '5\nphone\nn\n\n0\n' | script -qec "ovpnctl" /dev/null > /var/log/menu2.log 2>&1
    chk "подтверждение предлагает Y/n"  "grep -q '\[Y/n\]\|\[y/N\]' /var/log/menu2.log"
    chk "ответ n отменил удаление"      "ovpnctl client list | grep -q 'phone .*офлайн\|phone .*онлайн'"
else
    skip "утилита script недоступна — меню не проверено"
fi

echo; echo "=== 6. отзыв доступа ==="
ovpnctl client revoke phone -y >/dev/null 2>&1 && ok "client revoke отработал" || bad "client revoke"
chk "серийник в CRL" "openssl crl -in /etc/openvpn/server/crl.pem -noout -text | grep -q 'Serial Number'"
sleep 1
chk "openvpn (от nobody) записал трафик завершённой сессии" \
    "ovpnctl client list >/dev/null && grep -q '\"phone\"' /etc/ovpnctl/traffic.json"
chk "у отозванного клиента в списке ненулевой трафик" \
    "ovpnctl client list --json | python3 -c 'import json,sys; r=[c for c in json.load(sys.stdin) if c[\"name\"]==\"phone\"]; sys.exit(0 if r and r[0][\"traffic_total\"] > 0 else 1)'"
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

echo; echo "=== 9. selftest в контейнере ==="
python3 /src/tests/selftest.py 2>&1 | tail -3

echo; echo "============================================================"
echo "ИТОГ: пройдено $PASS, провалено $FAIL"
exit $([ "$FAIL" -eq 0 ] && echo 0 || echo 1)
