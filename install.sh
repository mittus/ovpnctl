#!/usr/bin/env bash
#
# ovpnctl bootstrap installer
# ---------------------------
# Разворачивает OpenVPN + собственный PKI + CLI-менеджер (ovpnctl) одной командой.
# Поддержка: Debian 10/11/12/13, Ubuntu 20.04/22.04/24.04+ (amd64/arm64).
#
#   Установка одной командой:
#       sudo bash <(wget -qO- https://raw.githubusercontent.com/mittus/ovpnctl/master/install.sh)
#
# Параметры сервера выбираются автоматически (внешний IP, свободная подсеть, udp/1194,
# EC-ключи, DNS Cloudflare) и меняются потом командой 'ovpnctl set'.
# Клиенты создаются отдельно: ovpnctl client add <certname>
#
set -euo pipefail

REPO_URL="${OVPN_REPO_URL:-https://github.com/mittus/ovpnctl}"
REPO_BRANCH="${OVPN_REPO_BRANCH:-}"     # пусто = пробуем master, затем main
REPO_SUBDIR="${OVPN_REPO_SUBDIR:-}"     # пусто = исходники лежат в корне репозитория

SRC_DIR="/opt/ovpnctl"
BIN_PATH="/usr/local/bin/ovpnctl"
ETC_DIR="/etc/ovpnctl"
LOG_TAG="[ovpnctl-install]"
TMP_DIR=""                              # временный каталог для скачанных исходников
CODE_FP_BEFORE=""                       # отпечаток установленного кода до обновления
SOURCE_BRANCH=""                        # ветка, из которой скачаны исходники (пусто — локальные)

C_OK=$'\033[1;32m'; C_ERR=$'\033[1;31m'; C_WARN=$'\033[1;33m'; C_INFO=$'\033[1;36m'; C_OFF=$'\033[0m'
if [ ! -t 1 ]; then C_OK=; C_ERR=; C_WARN=; C_INFO=; C_OFF=; fi

cleanup() { [ -n "${TMP_DIR:-}" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

info()  { printf '%s %s%s%s\n' "$LOG_TAG" "$C_INFO" "$*" "$C_OFF"; }
ok()    { printf '%s %s%s%s\n' "$LOG_TAG" "$C_OK"   "$*" "$C_OFF"; }
warn()  { printf '%s %s%s%s\n' "$LOG_TAG" "$C_WARN" "$*" "$C_OFF" >&2; }
die()   { printf '%s %s%s%s\n' "$LOG_TAG" "$C_ERR"  "ОШИБКА: $*" "$C_OFF" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 1. Предполётные проверки
# --------------------------------------------------------------------------- #
require_root() {
    [ "$(id -u)" -eq 0 ] || die "нужны права root (запустите через sudo)."
}

detect_os() {
    [ -r /etc/os-release ] || die "не найден /etc/os-release — дистрибутив не поддерживается."
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    OS_VER="${VERSION_ID:-0}"
    OS_CODENAME="${VERSION_CODENAME:-}"
    OS_NAME="${PRETTY_NAME:-$OS_ID $OS_VER}"

    case "$OS_ID" in
        debian)
            MAJOR="${OS_VER%%.*}"
            if [ "${MAJOR:-0}" -lt 10 ] 2>/dev/null; then
                die "Debian $OS_VER не поддерживается (нужен 10+)."
            fi
            if [ "${MAJOR:-0}" -eq 10 ] 2>/dev/null; then
                warn "Debian 10 снят с поддержки: обновления безопасности не выходят,"
                warn "а пакеты доступны только из archive.debian.org. Рекомендуется обновиться до 12."
            fi
            if [ "${MAJOR:-0}" -gt 13 ] 2>/dev/null; then
                warn "Debian $OS_VER новее протестированных — продолжаю."
            fi
            ;;
        ubuntu)
            MAJOR="${OS_VER%%.*}"
            if [ "${MAJOR:-0}" -lt 20 ] 2>/dev/null; then
                die "Ubuntu $OS_VER не поддерживается (нужен 20.04+)."
            fi
            ;;
        *)
            case " $OS_LIKE " in
                *debian*) warn "Дистрибутив '$OS_ID' не тестировался, но он debian-совместимый — продолжаю." ;;
                *) die "дистрибутив '$OS_ID' не поддерживается (нужен Debian/Ubuntu или производный)." ;;
            esac
            ;;
    esac
    ok "Система: $OS_NAME ($(uname -m), ядро $(uname -r))"
}

preflight() {
    command -v apt-get >/dev/null 2>&1 || die "не найден apt-get — поддерживаются только apt-based системы."

    # TUN/TAP
    if [ ! -c /dev/net/tun ]; then
        info "Устройство /dev/net/tun отсутствует, пробую загрузить модуль tun…"
        modprobe tun 2>/dev/null || true
        sleep 1
    fi
    if [ ! -c /dev/net/tun ]; then
        die "нет /dev/net/tun. На OpenVZ/LXC включите TUN/TAP у провайдера (KVM работает из коробки)."
    fi

    # systemd
    [ -d /run/systemd/system ] || die "systemd не обнаружен — установка рассчитана на systemd-хосты."

    # свободное место (нужно ~200 МБ на пакеты)
    local avail
    avail=$(df -Pk / | awk 'NR==2 {print $4}')
    if [ "${avail:-0}" -lt 204800 ]; then
        warn "На / меньше 200 МБ свободно — установка может не пройти."
    fi

    ok "Предполётные проверки пройдены (/dev/net/tun, systemd, apt)."
}

# --------------------------------------------------------------------------- #
# 2. Пакеты и зависимости (с перепроверкой)
# --------------------------------------------------------------------------- #
# На снятых с поддержки Debian (10 и старше) пакеты живут в archive.debian.org,
# а обычные зеркала отдают 404 — предлагаем переключить источники.
fix_archived_repos() {
    local list=/etc/apt/sources.list
    [ -f "$list" ] || return 1
    grep -qE 'deb\.debian\.org|security\.debian\.org' "$list" || return 1

    warn "Репозитории этого выпуска Debian переехали в archive.debian.org."
    if [ -t 0 ]; then
        printf '%s Переключить %s на archive.debian.org? [Y/n]: ' "$LOG_TAG" "$list" >&2
        read -r answer </dev/tty || answer=""
        case "${answer:-y}" in [Nn]*) return 1 ;; esac
    else
        # без терминала не трогаем системные источники — показываем готовую команду
        warn "Нет терминала: источники не меняю. Выполните вручную и повторите установку:"
        warn "  sed -i -e 's|deb.debian.org|archive.debian.org|g' \\"
        warn "         -e 's|security.debian.org|archive.debian.org|g' \\"
        warn "         -e '/-updates/d' $list && apt-get update"
        return 1
    fi

    cp -a "$list" "$list.ovpnctl.bak"
    sed -i -e 's|http://deb.debian.org/debian-security|http://archive.debian.org/debian-security|g' \
           -e 's|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g' \
           -e 's|http://security.debian.org|http://archive.debian.org|g' \
           -e 's|http://deb.debian.org|http://archive.debian.org|g' \
           -e 's|https://deb.debian.org|http://archive.debian.org|g' \
           -e '/-updates/d' "$list"
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99ovpnctl-archive
    ok "Источники переключены на archive.debian.org (оригинал: $list.ovpnctl.bak)."
    return 0
}

apt_update_once() {
    if [ -z "${_APT_UPDATED:-}" ]; then
        info "apt-get update…"
        if ! DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null; then
            if fix_archived_repos; then
                DEBIAN_FRONTEND=noninteractive apt-get update -qq \
                    || warn "apt-get update снова с ошибкой, продолжаю с текущими индексами."
            else
                warn "apt-get update завершился с ошибкой, продолжаю с текущими индексами."
            fi
        fi
        _APT_UPDATED=1
    fi
}

# Отпечаток кода: по нему видно, обновились ли исходники на самом деле
code_fingerprint() {
    local dir="$1"
    [ -d "$dir" ] || { echo "нет"; return; }
    find "$dir" -type f -name '*.py' -print0 2>/dev/null \
        | LC_ALL=C sort -z | xargs -0 cat 2>/dev/null | md5sum | cut -c1-8
}

pkg_installed() { dpkg-query -W -f='${db:Status-Status}\n' "$1" 2>/dev/null | grep -q '^installed$'; }

install_packages() {
    # базовый набор: openvpn сам тянет openssl/liblzo и т.п., остальное — наши инструменты
    local pkgs=(openvpn openssl ca-certificates iproute2 iptables python3 curl)
    # opensslшный `openssl` бинарь в Debian 13 живёт в пакете openssl — тот же
    local to_install=()

    apt_update_once
    for p in "${pkgs[@]}"; do
        if pkg_installed "$p"; then
            info "пакет уже установлен: $p"
        else
            to_install+=("$p")
        fi
    done

    if [ "${#to_install[@]}" -gt 0 ]; then
        info "Устанавливаю: ${to_install[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${to_install[@]}" \
            || die "не удалось установить пакеты: ${to_install[*]}"
    fi

    # ПЕРЕПРОВЕРКА: каждый пакет реально в системе
    local failed=()
    for p in "${pkgs[@]}"; do pkg_installed "$p" || failed+=("$p"); done
    if [ "${#failed[@]}" -gt 0 ]; then
        die "после установки отсутствуют пакеты: ${failed[*]}"
    fi

    # ПЕРЕПРОВЕРКА: бинарники на месте и запускаются
    local bins=(openvpn openssl python3 ip iptables)
    for b in "${bins[@]}"; do
        command -v "$b" >/dev/null 2>&1 || die "бинарник '$b' не найден в PATH после установки."
    done

    # ПЕРЕПРОВЕРКА версий
    # openvpn --version в ветке 2.4 завершается с кодом 1 — под set -e/pipefail
    # это уронило бы установщик, поэтому гасим код возврата явно
    OPENVPN_VER=$( { openvpn --version 2>/dev/null || true; } | head -1 | awk '{print $2}')
    OPENSSL_VER=$( { openssl version 2>/dev/null || true; } | awk '{print $2}')
    PY_VER=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')

    local py_major py_minor
    py_major=${PY_VER%%.*}; py_minor=${PY_VER##*.}
    if [ "$py_major" -lt 3 ] || { [ "$py_major" -eq 3 ] && [ "$py_minor" -lt 7 ]; }; then
        die "нужен Python 3.7+, найден $PY_VER."
    fi
    case "$OPENVPN_VER" in
        2.[4-9]*|2.[1-9][0-9]*|[3-9].*) : ;;
        *) die "нужен OpenVPN 2.4+, найден '${OPENVPN_VER:-неизвестно}'." ;;
    esac

    ok "Зависимости проверены: openvpn $OPENVPN_VER, openssl $OPENSSL_VER, python3 $PY_VER"
}

# --------------------------------------------------------------------------- #
# 3. Получение исходников (локально или с гита)
# --------------------------------------------------------------------------- #
fetch_sources() {
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo '')"

    if [ -n "$here" ] && [ -d "$here/lib/ovpnctl" ]; then
        PAYLOAD_DIR="$here"
        info "Использую локальные исходники: $PAYLOAD_DIR"
        return
    fi

    [ -n "$REPO_URL" ] || die "не задан OVPN_REPO_URL (например https://github.com/mittus/ovpnctl)."

    local branches branch tarball got=0 tmp
    TMP_DIR="$(mktemp -d)"; tmp="$TMP_DIR"
    if [ -n "$REPO_BRANCH" ]; then branches="$REPO_BRANCH"; else branches="master main"; fi

    for branch in $branches; do
        tarball="$REPO_URL/archive/refs/heads/$branch.tar.gz"
        info "Скачиваю исходники: $tarball"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL "$tarball" -o "$tmp/src.tgz" && got=1 && SOURCE_BRANCH="$branch" && break
        else
            wget -qO "$tmp/src.tgz" "$tarball" && got=1 && SOURCE_BRANCH="$branch" && break
        fi
        warn "Ветка '$branch' недоступна, пробую следующую."
    done
    [ "$got" -eq 1 ] || die "не удалось скачать исходники из $REPO_URL (ветки: $branches)."

    tar -xzf "$tmp/src.tgz" -C "$tmp" || die "битый архив исходников."

    # исходники могут лежать в корне архива или в подкаталоге (OVPN_REPO_SUBDIR)
    if [ -n "$REPO_SUBDIR" ]; then
        PAYLOAD_DIR="$(find "$tmp" -maxdepth 3 -type d -path "*/$REPO_SUBDIR" -print -quit)"
    else
        PAYLOAD_DIR="$(dirname "$(find "$tmp" -maxdepth 4 -type d -path "*/lib/ovpnctl" -print -quit)" 2>/dev/null)"
        PAYLOAD_DIR="${PAYLOAD_DIR%/lib}"
    fi
    [ -n "$PAYLOAD_DIR" ] && [ -d "$PAYLOAD_DIR/lib/ovpnctl" ] \
        || die "в архиве не найден каталог lib/ovpnctl."
    ok "Исходники распакованы: ${PAYLOAD_DIR#$tmp/}"
}

# --------------------------------------------------------------------------- #
# 4. Раскладка файлов
# --------------------------------------------------------------------------- #
deploy() {
    info "Разворачиваю в $SRC_DIR…"
    CODE_FP_BEFORE="$(code_fingerprint "$SRC_DIR/lib")"
    install -d -m 0755 "$SRC_DIR" "$ETC_DIR"
    rm -rf "$SRC_DIR/lib"
    cp -a "$PAYLOAD_DIR/lib" "$SRC_DIR/lib"
    for extra in VERSION README.md uninstall.sh install.sh; do
        if [ -f "$PAYLOAD_DIR/$extra" ]; then
            cp -a "$PAYLOAD_DIR/$extra" "$SRC_DIR/$extra"
        fi
    done
    if [ -d "$PAYLOAD_DIR/tests" ]; then
        rm -rf "$SRC_DIR/tests"
        cp -a "$PAYLOAD_DIR/tests" "$SRC_DIR/tests"
    fi
    # откуда ставили — туда же потом смотрит 'ovpnctl update'
    if [ -n "$SOURCE_BRANCH" ]; then
        printf 'repo=%s\nbranch=%s\n' "$REPO_URL" "$SOURCE_BRANCH" > "$SRC_DIR/SOURCE"
    fi
    chmod -R go-w "$SRC_DIR"

    cat > "$BIN_PATH" <<'WRAP'
#!/usr/bin/env bash
# Обёртка запуска менеджера ovpnctl
exec /usr/bin/env PYTHONPATH="/opt/ovpnctl/lib${PYTHONPATH:+:$PYTHONPATH}" python3 -m ovpnctl "$@"
WRAP
    chmod 0755 "$BIN_PATH"

    # systemd-юниты генерирует сам ovpnctl на этапе setup (единый источник правды)
    systemctl daemon-reload

    # ПЕРЕПРОВЕРКА: менеджер реально запускается
    "$BIN_PATH" --version >/dev/null 2>&1 || die "менеджер ovpnctl не запускается после установки."

    local fp_after
    fp_after="$(code_fingerprint "$SRC_DIR/lib")"
    if [ "$CODE_FP_BEFORE" = "нет" ]; then
        ok "Файлы разложены ($("$BIN_PATH" --version), сборка $fp_after)"
    elif [ "$CODE_FP_BEFORE" = "$fp_after" ]; then
        ok "Код уже актуален — та же сборка $fp_after, обновлять нечего."
    else
        ok "Код обновлён: сборка $CODE_FP_BEFORE → $fp_after"
    fi
}

# --------------------------------------------------------------------------- #
# 5. Настройка сервера
# --------------------------------------------------------------------------- #
run_setup() {
    # Повторный запуск на уже настроенном сервере = обновление кода без переустановки
    if [ -f "$ETC_DIR/config.json" ]; then
        ok "Найдена существующая конфигурация ($ETC_DIR/config.json) — сервер не пересоздавался."
        local output changed
        if output="$("$BIN_PATH" update --finish 2>&1)"; then
            changed="$(printf '%s\n' "$output" | sed -n 's/^\* //p' | paste -sd, - | sed 's/,/, /g')"
            if [ -n "$changed" ]; then
                ok "Обновлены файлы сервера: $changed — OpenVPN перезапущен."
            else
                ok "Конфигурация сервера не изменилась, подключения не прерывались."
            fi
        else
            warn "Не удалось применить конфигурацию: $output"
            warn "Повторите: ovpnctl update --finish"
        fi
        info "Меню открыто в другой сессии? Выйдите из него (0) и запустите 'ovpnctl' заново —"
        info "уже запущенный процесс работает со старым кодом."
        info "Дальнейшие обновления:    ovpnctl update"
        info "Поставить заново с нуля:  ovpnctl uninstall -y, затем эта же команда"
        "$BIN_PATH" status || true
        return 0
    fi

    info "Запускаю настройку сервера…"
    "$BIN_PATH" setup
}

main() {
    require_root
    detect_os
    preflight
    install_packages
    fetch_sources
    deploy
    run_setup
    echo
    ok "Готово. Управление: ovpnctl (интерактивное меню) или ovpnctl --help"
}

main "$@"
