import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from vulnscan.cli import main
from vulnscan.dashboard import _handler_factory, serve
from vulnscan.errors import ScopeError
from vulnscan.report.render import render_html

ROOT = Path(__file__).resolve().parents[1]


def test_sample_assessment_and_report(tmp_path):
    db = tmp_path / "v.db"
    assert main(["--db", str(db), "update", "--sample"]) == 0
    assert (
        main(
            [
                "--db",
                str(db),
                "network",
                "--nmap-xml",
                str(ROOT / "examples" / "nmap-sample.xml"),
                "--i-am-authorized",
                "--sample",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--db",
                str(db),
                "server",
                "--no-local",
                "--packages-file",
                str(ROOT / "examples" / "packages-sample.txt"),
                "--pip-file",
                str(ROOT / "examples" / "pip-sample.json"),
                "--sshd-config",
                str(ROOT / "examples" / "sshd-sample.conf"),
                "--sample",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--db",
                str(db),
                "endpoint",
                "--no-local",
                "--os-release-file",
                str(ROOT / "examples" / "os-release-sample"),
                "--kernel",
                "5.15.12",
                "--uninstall-json",
                str(ROOT / "examples" / "windows-uninstall-sample.json"),
                "--apps-json",
                str(ROOT / "examples" / "macos-apps-sample.json"),
                "--sw-vers-file",
                str(ROOT / "examples" / "sw-vers-sample.txt"),
                "--sample",
            ]
        )
        == 0
    )
    out = tmp_path / "report.json"
    assert main(["--db", str(db), "report", "--scan-id", "all", "--format", "json", "--out", str(out), "--sample"]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    found = {(item["component"], item["cve_id"]) for item in report["findings"]}
    assert ("OpenSSH", "CVE-2024-6387") in found
    assert ("OpenSSH", "CVE-2023-38408") in found
    assert ("nginx", "CVE-2021-23017") in found
    assert ("Apache httpd", "CVE-2021-41773") in found
    assert ("openssl", "CVE-2022-0778") in found
    assert ("xz-utils", "CVE-2024-3094") in found
    assert ("libc6", "CVE-2023-4911") in found
    assert ("liblog4j2-java", "CVE-2021-44228") in found
    assert ("linux-kernel", "CVE-2022-0847") in found
    assert any(item["cve_id"] == "CVE-2021-44228" and item["kev"] for item in report["findings"])
    assert any(item["cve_id"] is None and "root" in item["title"] for item in report["findings"])
    # fixed OpenSSH must not match the regreSSHion upper bound
    assert ("OpenSSH", "CVE-2024-6387") in found
    html_path = tmp_path / "report.html"
    assert (
        main(
            [
                "--db",
                str(db),
                "report",
                "--scan-id",
                "all",
                "--format",
                "html",
                "--out",
                str(html_path),
                "--sample",
            ]
        )
        == 0
    )
    html = html_path.read_text(encoding="utf-8")
    assert "취약점 점검 보고서" in html
    assert "This product uses data from the NVD API but is not endorsed or certified by the NVD." in html
    assert "표본 보고서" in html
    assert "<script>" not in html
    nasty = render_html(
        {
            "generated_at": "t",
            "scan_id": "s",
            "scope": "<script>",
            "sample": True,
            "inventory": 0,
            "summary": {"total": 1, "critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0, "info": 1},
            "disclaimer": "x",
            "findings": [
                {
                    "asset": "<img src=x onerror=alert(1)>",
                    "asset_kind": "server",
                    "asset_kind_ko": "서버",
                    "component": "<b>",
                    "installed_version": "1",
                    "cve_id": "CVE-1",
                    "cwe_ids": ["CWE-79"],
                    "cwe_names": ["XSS"],
                    "title": "<script>alert(1)</script>",
                    "cvss_score": 1.0,
                    "cvss_vector": None,
                    "cvss_severity": "LOW",
                    "cvss_severity_ko": "낮음",
                    "cvss_version": "3.1",
                    "cvss_v4_score": None,
                    "kev": False,
                    "epss_score": None,
                    "epss_percentile": None,
                    "remediation": "패치",
                    "evidence": "x",
                    "risk_score": 1,
                    "scan_id": "s",
                }
            ],
        }
    )
    assert "<script>alert" not in nasty
    assert "&lt;script&gt;" in nasty
    csv_path = tmp_path / "report.csv"
    assert main(["--db", str(db), "report", "--scan-id", "all", "--format", "csv", "--out", str(csv_path)]) == 0
    assert "CVE-2024-6387" in csv_path.read_text(encoding="utf-8-sig")
    export_path = tmp_path / "cves.json"
    assert main(["--db", str(db), "export", "--kind", "cve", "--out", str(export_path)]) == 0
    exported = json.loads(export_path.read_text(encoding="utf-8"))
    assert len(exported) == 10


def test_dashboard_localhost_and_remote_guard(tmp_path):
    db = tmp_path / "v.db"
    assert main(["--db", str(db), "update", "--sample"]) == 0
    try:
        serve(db, "0.0.0.0", 9, allow_remote=False)
        raise AssertionError("remote bind should be refused")
    except ScopeError:
        pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(db))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health") as response:
            assert response.read() == b"ok"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as response:
            page = response.read().decode("utf-8")
        assert "취약점 점검 보고서" in page
        assert "NVD" in page
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_negative_version_not_matched(tmp_path):
    db = tmp_path / "v.db"
    packages = tmp_path / "packages.txt"
    packages.write_text("openssh-server\t9.8p1\nnginx\t1.26.0\napache2\t2.4.50\n", encoding="utf-8")
    assert main(["--db", str(db), "update", "--sample"]) == 0
    assert (
        main(
            [
                "--db",
                str(db),
                "server",
                "--no-local",
                "--packages-file",
                str(packages),
                "--sample",
            ]
        )
        == 0
    )
    out = tmp_path / "r.json"
    main(["--db", str(db), "report", "--format", "json", "--out", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    pairs = {(item["component"], item["cve_id"]) for item in report["findings"]}
    assert ("openssh-server", "CVE-2024-6387") not in pairs
    assert ("openssh-server", "CVE-2023-38408") not in pairs
    assert ("nginx", "CVE-2021-23017") not in pairs
    assert ("nginx", "CVE-2023-44487") not in pairs
    assert ("apache2", "CVE-2021-41773") not in pairs
