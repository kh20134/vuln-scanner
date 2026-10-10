import socket
import threading
from pathlib import Path

from vulnscan.assess.endpoint import (
    kernel_comparable,
    kernel_item,
    parse_os_release,
    parse_uninstall_json,
)
from vulnscan.assess.network import (
    ensure_authorized,
    expand_targets,
    identify_banner,
    parse_nmap_xml,
    parse_ports,
    probe_tcp,
    scan_hosts,
)
from vulnscan.assess.server import audit_sshd, parse_package_lines, parse_sshd_config
from vulnscan.cli import main
from vulnscan.errors import AuthorizationError, ScopeError

ROOT = Path(__file__).resolve().parents[1]


def test_banner_and_nmap_and_scope():
    item = identify_banner("10.0.0.1:22/tcp", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")
    assert item is not None
    assert item.version == "8.9p1"
    assert ("a", "openbsd", "openssh") in item.candidates
    nginx = identify_banner("h:80/tcp", "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n")
    assert nginx is not None and nginx.version == "1.18.0"
    apache = identify_banner("h:80/tcp", "Server: Apache/2.4.49 (Unix)")
    assert apache is not None and apache.candidates[0][2] == "http_server"
    items = parse_nmap_xml((ROOT / "examples" / "nmap-sample.xml").read_text(encoding="utf-8"))
    assert len(items) == 3
    assert {item.component for item in items} == {"OpenSSH", "nginx", "Apache httpd"}
    try:
        expand_targets(["0.0.0.0/0"], 256)
        raise AssertionError("expected scope error")
    except ScopeError:
        pass
    assert expand_targets(["203.0.113.10", "203.0.113.10"], 10) == ["203.0.113.10"]
    assert parse_ports("22,80-82") == [22, 80, 81, 82]


def test_network_requires_authorization_and_does_not_probe(tmp_path, capsys):
    called = {"n": 0}

    def boom(host, port, timeout):
        called["n"] += 1
        return False, ""

    code = main(["--db", str(tmp_path / "v.db"), "network", "--targets", "203.0.113.10", "--ports", "22"])
    assert code == 2
    captured = capsys.readouterr()
    assert "인가" in captured.err
    assert called["n"] == 0
    try:
        ensure_authorized(False)
        raise AssertionError("expected")
    except AuthorizationError:
        pass
    # injected probe is not used unless authorized path calls scan_hosts
    scan_hosts(
        ["203.0.113.10"],
        [22],
        timeout=0.1,
        max_hosts=10,
        max_probes=10,
        workers=1,
        probe=boom,
    )
    assert called["n"] == 1


def test_local_tcp_banner_only():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _addr = server.accept()
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
        try:
            conn.recv(32)
        except OSError:
            pass
        conn.close()

    thread = threading.Thread(target=serve)
    thread.start()
    opened, banner = probe_tcp("127.0.0.1", port, 2.0)
    thread.join(timeout=3)
    server.close()
    assert opened
    assert "OpenSSH_8.9p1" in banner


def test_sshd_audit_ignores_match_block():
    text = (ROOT / "examples" / "sshd-sample.conf").read_text(encoding="utf-8")
    settings = parse_sshd_config(text)
    assert settings["permitrootlogin"] == "yes"
    findings = audit_sshd(text)
    titles = " ".join(item.title for item in findings)
    assert "root" in titles
    assert "빈 비밀번호" in titles
    assert "3des" in titles or "암호" in titles
    assert any(item.cwe_id == "CWE-250" for item in findings)
    packages = parse_package_lines((ROOT / "examples" / "packages-sample.txt").read_text(encoding="utf-8"))
    assert ("openssh-server", "1:8.9p1-3ubuntu0.10") in packages


def test_endpoint_parsers():
    assert kernel_comparable("5.15.12") == "5.15.12"
    assert kernel_comparable("5.15.0-119-generic") is None
    item = kernel_item("5.15.0-119-generic", "host")
    assert item.candidates == []
    release = parse_os_release((ROOT / "examples" / "os-release-sample").read_text(encoding="utf-8"))
    assert release["VERSION_ID"] == "22.04"
    apps = parse_uninstall_json((ROOT / "examples" / "windows-uninstall-sample.json").read_text(encoding="utf-8"))
    log4j = next(item for item in apps if "Log4j" in item.component)
    assert ("a", "apache", "log4j") in log4j.candidates
    chrome = next(item for item in apps if "Chrome" in item.component)
    assert chrome.candidates
