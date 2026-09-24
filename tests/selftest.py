#!/usr/bin/env python3
"""Автотесты ovpnctl: PKI, ротация CA, профили, отзыв, автопродление.

Ничего не устанавливает и не трогает систему — вся работа идёт в песочнице
(OVPNCTL_ROOT), из системных утилит нужен только openssl.

    python3 tests/selftest.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

SANDBOX = tempfile.mkdtemp(prefix="ovpnctl-selftest-")
os.environ["OVPNCTL_ROOT"] = SANDBOX
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from ovpnctl import clients, pki, renew as renew_mod, server as srv  # noqa: E402
from ovpnctl import traffic, update as update_mod  # noqa: E402
from ovpnctl import config as cfgmod  # noqa: E402
from ovpnctl.util import run  # noqa: E402

PASSED = []
FAILED = []

TC_KEY_STUB = ("#\n-----BEGIN OpenVPN Static key V1-----\n"
               + ("a" * 32 + "\n") * 16 + "-----END OpenVPN Static key V1-----\n")


def check(title, condition, detail=""):
    if condition:
        PASSED.append(title)
        print("  [ok]   %s" % title)
    else:
        FAILED.append("%s %s" % (title, detail))
        print("  [FAIL] %s %s" % (title, detail))


def verify(cert_file, ca_file):
    return run(["openssl", "verify", "-CAfile", ca_file, cert_file], check=False).returncode == 0


def stub_system():
    """Заглушки на всё, что требует root, systemd или запущенный OpenVPN."""
    srv.restart = lambda: None
    srv.kill_client = lambda name: False
    srv.openvpn_version = lambda: (2, 6, 0)
    srv.openvpn_group = lambda: "nogroup"
    srv.enable_ip_forward = lambda ipv6=False: None
    srv.configure_ufw = lambda cfg: None
    srv.daemon_reload = lambda: None
    srv.systemctl = lambda *a, **k: None
    renew_mod.service_active = lambda unit: True
    renew_mod.systemctl = lambda *a, **k: None
    pki.ensure_tc_key = _stub_tc_key


def _stub_tc_key():
    with open(pki.TC_KEY, "w") as fh:
        fh.write(TC_KEY_STUB)
    os.chmod(pki.TC_KEY, 0o600)
    return pki.TC_KEY


def main():
    stub_system()
    cfg = dict(cfgmod.DEFAULTS)
    cfg.update({"endpoint": "vpn.example.com", "nic": "eth0"})
    cfgmod.init_dirs()
    cfgmod.save(cfg)

    print("\n== PKI ==")
    pki.create_ca(cfg)
    pki.issue(pki.SERVER_NAME, "server_cert", cfg["server_days"], cfg)
    pki.ensure_tc_key()
    pki.gen_crl(cfg)
    check("CA создан", os.path.exists(pki.CA_CRT))
    check("срок CA ≈ ca_days", abs(pki.days_left(pki.CA_CRT) - cfg["ca_days"]) <= 2,
          "(%d дн.)" % pki.days_left(pki.CA_CRT))
    check("сертификат сервера подписан CA", verify(pki.cert_path("server"), pki.CA_CRT))
    server_text = run(["openssl", "x509", "-in", pki.cert_path("server"), "-noout", "-text"]).stdout
    check("у сервера EKU serverAuth", "TLS Web Server Authentication" in server_text)
    check("AKID без серийника издателя", "DirName" not in server_text)
    check("CRL валиден дольше порога", pki.crl_days_left() > cfg["renew_crl_before"])

    print("\n== Конфигурация сервера ==")
    srv.deploy_pki_to_server(cfg)
    conf = open(srv.write_server_conf(cfg)).read()
    for directive in ("tls-crypt", "crl-verify", "dh none", "topology subnet",
                      "server 10.8.0.0 255.255.255.0", "data-ciphers"):
        check("server.conf содержит '%s'" % directive, directive in conf)
    check("server.conf вызывает скрипт учёта трафика",
          "client-disconnect %s" % srv.TRAFFIC_SCRIPT in conf and "script-security 2" in conf)
    check("скрипт учёта трафика исполняемый", os.access(srv.TRAFFIC_SCRIPT, os.X_OK))
    fw = open(srv.write_firewall_script(cfg)).read()
    check("правило MASQUERADE в firewall.sh", "MASQUERADE" in fw and "10.8.0.0/24" in fw)

    print("\n== Клиенты ==")
    clients.add("alice", cfg)
    clients.add("bob", cfg, days=365, static_ip="10.8.0.50")
    profile = open(clients.profile_path("alice")).read()
    for tag in ("<ca>", "<cert>", "<key>", "<tls-crypt>", "remote vpn.example.com 1194"):
        check("в профиле есть %s" % tag, tag in profile)
    check("права профиля 0600", oct(os.stat(clients.profile_path("alice")).st_mode & 0o777) == "0o600")
    check("статический IP записан в ccd",
          "10.8.0.50" in open(os.path.join(srv.CCD_DIR, "bob")).read())
    check("клиент виден в списке", any(r["name"] == "alice" for r in clients.listing(cfg)))

    print("\n== Отзыв ==")
    bob_serial = pki.serial_of(pki.cert_path("bob"))
    clients.revoke("bob", cfg)
    crl_text = run(["openssl", "crl", "-in", pki.CRL, "-noout", "-text"]).stdout.replace(" ", "")
    check("серийник отозванного в CRL", bob_serial in crl_text)
    check("профиль отозванного удалён", not os.path.exists(clients.profile_path("bob")))
    check("статус в списке — отозван",
          [r["status"] for r in clients.listing(cfg) if r["name"] == "bob"] == ["отозван"])

    print("\n== Ротация CA (главная проверка «VPN не отвалится») ==")
    alice_before = open(pki.cert_path("alice")).read()
    ca_key_before = run(["openssl", "pkey", "-in", pki.CA_KEY, "-pubout"]).stdout
    result = pki.renew_ca(cfg)
    ca_key_after = run(["openssl", "pkey", "-in", pki.CA_KEY, "-pubout"]).stdout
    check("ключ CA не изменился", ca_key_before == ca_key_after)
    check("subject CA не изменился", pki.subject_of(pki.CA_CRT) == "CN=ovpnctl CA",
          pki.subject_of(pki.CA_CRT))
    check("клиентский сертификат не тронут", open(pki.cert_path("alice")).read() == alice_before)
    check("старый клиентский сертификат проходит проверку новым CA",
          verify(pki.cert_path("alice"), pki.CA_CRT))
    check("сертификат сервера проходит проверку новым CA",
          verify(pki.cert_path("server"), pki.CA_CRT))
    check("в ca.crt ровно один сертификат (OpenVPN не грузит два CA с одним subject)",
          open(pki.CA_CRT).read().count("BEGIN CERTIFICATE") == 1)
    check("старая копия CA из уже розданных профилей доверяет новому серверному сертификату",
          pki.old_ca_still_trusts(pki.SERVER_NAME))
    check("старый CA сохранён в архиве", os.path.exists(result["archived"]))

    print("\n== Автопродление ==")
    report = renew_mod.check(cfg)
    check("отчёт без проблем", not report["problems"], str(report["problems"]))
    check("продление не требуется на свежем PKI", not report["action_needed"])
    server_serial = pki.serial_of(pki.cert_path("server"))
    actions = renew_mod.run(cfg, force=True, quiet=True)
    check("форс-продление затронуло CA, сервер, CRL и клиентов",
          actions["ca"] and actions["server"] and actions["crl"] and "alice" in actions["clients"])
    check("серийник сервера обновился", pki.serial_of(pki.cert_path("server")) != server_serial)
    check("после форс-продления цепочка цела", verify(pki.cert_path("alice"), pki.CA_CRT))
    check("профиль клиента перегенерирован", os.path.exists(clients.profile_path("alice")))
    check("журнал продления пишется", os.path.exists(cfgmod.RENEW_LOG))

    print("\n== Пороговое продление (без --force) ==")
    pki.issue(pki.SERVER_NAME, "server_cert", 10, cfg, reuse_key=True)      # «почти истёк»
    clients.add("carol", cfg, days=10)
    short_cfg = dict(cfg)
    short_cfg["crl_days"] = 3650
    check("сервер помечен к продлению",
          any(i["kind"] == "server" and i["needs_renew"] for i in renew_mod.check(short_cfg)["items"]))
    actions = renew_mod.run(short_cfg, quiet=True)
    check("сервер продлён по порогу", actions["server"])
    check("новый срок сервера — из политики",
          pki.days_left(pki.cert_path("server")) > short_cfg["renew_server_before"],
          "(%d дн.)" % pki.days_left(pki.cert_path("server")))
    check("клиент carol продлён по порогу", "carol" in actions["clients"])
    check("короткий клиентский сертификат продлён минимум на два порога",
          pki.days_left(pki.cert_path("carol")) >= short_cfg["renew_client_before"] * 2 - 1,
          "(%d дн.)" % pki.days_left(pki.cert_path("carol")))
    check("повторный прогон ничего не делает",
          not renew_mod.run(short_cfg, quiet=True)["clients"])
    check("CA не трогали без нужды", not actions["ca"])

    print("\n== Срок сертификата не переживает CA ==")
    long_client = pki.issue("longlived", "client_cert", 999999, cfg)
    check("срок подрезан сроком CA",
          pki.days_left(long_client["crt"]) <= pki.days_left(pki.CA_CRT),
          "(клиент %d, CA %d)" % (pki.days_left(long_client["crt"]), pki.days_left(pki.CA_CRT)))

    print("\n== Определение чужих служб OpenVPN ==")
    from ovpnctl.system import is_openvpn_server_unit
    check("openvpn@server.service считается серверной", is_openvpn_server_unit("openvpn@server.service"))
    check("openvpn.service считается серверной", is_openvpn_server_unit("openvpn.service"))
    check("openvpn-server@vpn.service считается серверной",
          is_openvpn_server_unit("openvpn-server@vpn.service"))
    check("клиентская openvpn-client@work.service не трогается",
          not is_openvpn_server_unit("openvpn-client@work.service"))
    check("посторонний юнит не считается", not is_openvpn_server_unit("openvpn-monitor.timer"))

    print("\n== Разбор status-файла ==")
    os.makedirs(os.path.dirname(cfgmod.STATUS_FILE), exist_ok=True)
    with open(cfgmod.STATUS_FILE, "w") as fh:
        fh.write("TITLE,OpenVPN 2.6.0\n"
                 "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,"
                 "Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,"
                 "Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\n"
                 "CLIENT_LIST,alice,203.0.113.5:51820,10.8.0.2,,12345,6789,"
                 "Mon Sep  1 10:00:00 2026,1756713600,UNDEF,0,0,AES-256-GCM\n")
    online = srv.online_clients()
    check("клиент распознан в status-файле",
          online and online[0]["name"] == "alice" and online[0]["bytes_received"] == 12345,
          str(online))

    print("\n== Учёт трафика ==")
    # сессия, завершённая openvpn: прогоняем настоящий client-disconnect-скрипт
    env = dict(os.environ, common_name="alice", bytes_received="1000", bytes_sent="5000")
    run([srv.TRAFFIC_SCRIPT], env=env)
    env.update(bytes_received="24", bytes_sent="16")
    run([srv.TRAFFIC_SCRIPT], env=env)
    with open(srv.TRAFFIC_LOG, "a") as fh:
        fh.write("битая строка\n")
    usage = traffic.totals([])
    check("прошлые сессии сложены", usage.get("alice", {}).get("total") == 6040, str(usage))
    check("журнал сессий свёрнут", not os.path.exists(srv.TRAFFIC_LOG))
    check("повторный сбор не удваивает", traffic.totals([])["alice"]["total"] == 6040)
    row = [r for r in clients.listing(cfg) if r["name"] == "alice"][0]
    check("в списке клиентов трафик = прошлые + текущая сессия",
          row["traffic_total"] == 6040 + 12345 + 6789 and row["traffic_rx"] == 1024 + 12345,
          str(row))
    run([srv.TRAFFIC_SCRIPT], env=dict(env, common_name="carol"))
    clients.delete("carol", cfg)
    check("после удаления клиента его статистика сброшена", "carol" not in traffic.totals([]))

    print("\n== Обновление ovpnctl ==")
    repo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    finished = []
    real_new_code = update_mod._new_code

    def fake_new_code(*args, **kwargs):
        if "--finish" in args:              # применение конфигов требует root — имитируем
            finished.append(args)
            return run(["echo", "* server.conf"], check=False)
        return real_new_code(*args, **kwargs)

    update_mod._new_code = fake_new_code
    result = update_mod.run(local=repo)
    check("первое обновление ставит код", result["updated"]
          and os.path.exists(os.path.join(update_mod.SRC_DIR, "lib", "ovpnctl", "update.py")))
    check("сборка установленного кода совпадает с источником",
          update_mod.fingerprint(os.path.join(update_mod.SRC_DIR, "lib"))
          == update_mod.fingerprint(os.path.join(repo, "lib")))
    check("версия берётся из VERSION", result["latest"]["version"] == open(
        os.path.join(repo, "VERSION")).read().strip())
    check("после подмены конфиги применяет новый код", finished and result["changed"] == ["server.conf"])
    check("повторный запуск ничего не делает", not update_mod.run(local=repo)["updated"])
    check("--check не ставит", not update_mod.run(local=repo, check_only=True, force=True)["updated"])
    broken = os.path.join(SANDBOX, "broken")
    shutil.copytree(repo, broken, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    with open(os.path.join(broken, "lib", "ovpnctl", "__main__.py"), "w") as fh:
        fh.write("raise SystemExit(3)\n")
    try:
        update_mod.run(local=broken)
        refused = False
    except Exception:
        refused = True
    check("неработающая версия не ставится", refused and update_mod.fingerprint(
        os.path.join(update_mod.SRC_DIR, "lib")) == update_mod.fingerprint(os.path.join(repo, "lib")))
    tarball = shutil.make_archive(os.path.join(SANDBOX, "ovpnctl-master"), "gztar",
                                  root_dir=os.path.dirname(broken), base_dir="broken")
    check("из архива тоже читается", update_mod.run(local=tarball, check_only=True)["latest"]["build"]
          == update_mod.fingerprint(os.path.join(broken, "lib")))
    update_mod._new_code = real_new_code
    check("по умолчанию источник — github.com/mittus/ovpnctl",
          update_mod.source()["repo"] == "https://github.com/mittus/ovpnctl")

    print("\n== Резервная копия ==")
    from ovpnctl import provision
    archive = provision.backup()
    check("архив создан", os.path.exists(archive) and os.path.getsize(archive) > 1000)
    check("архив лежит вне копируемого каталога или не рекурсивен",
          os.path.getsize(archive) < 5 * 1024 * 1024)

    print("\n== Удаление клиента ==")
    clients.delete("alice", cfg)
    check("клиент удалён из базы", not any(r["name"] == "alice" for r in clients.listing(cfg)))
    check("файлы клиента удалены", not os.path.exists(pki.cert_path("alice")))

    print("\n" + "=" * 60)
    print("Пройдено: %d, провалено: %d" % (len(PASSED), len(FAILED)))
    for failure in FAILED:
        print("  FAIL: %s" % failure)
    return 1 if FAILED else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        shutil.rmtree(SANDBOX, ignore_errors=True)
    sys.exit(code)
