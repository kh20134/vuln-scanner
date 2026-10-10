"""vulnscan 명령줄 인터페이스."""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import socket
import sys
from pathlib import Path

from vulnscan import NVD_DISCLAIMER, __version__
from vulnscan.assess.endpoint import (
    kernel_item,
    linux_package_items,
    local_kernel,
    local_os_release,
    os_release_item,
    parse_macos_apps,
    parse_os_release,
    parse_sw_vers,
    parse_uninstall_entries,
    parse_uninstall_json,
    read_windows_uninstall,
)
from vulnscan.assess.engine import run_assessment
from vulnscan.assess.models import SoftwareItem
from vulnscan.assess.network import (
    DEFAULT_PORTS,
    ensure_authorized,
    parse_nmap_xml,
    parse_ports,
    scan_hosts,
)
from vulnscan.assess.server import (
    audit_sshd,
    collect_local_packages,
    collect_local_pip,
    packages_to_items,
    parse_package_lines,
    parse_pip_json,
    read_text,
)
from vulnscan.collect.update import run_update
from vulnscan.db import Database
from vulnscan.errors import AuthorizationError, DataError, ScopeError, VulnscanError
from vulnscan.report.render import build_report, render


def resolve_db(path: str | None) -> Path:
    if path:
        return Path(path)
    env = os.environ.get("VULNSCAN_DB")
    if env:
        return Path(env)
    return Path("vulnscan.db")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "인가된 네트워크·서버·엔드포인트에 대한 CVE/CWE 기반 방어적 취약점 점검. "
            "익스플로잇과 무차별 대입은 수행하지 않습니다."
        ),
    )
    parser.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    parser.add_argument("--db", help="SQLite 경로. 기본값은 ./vulnscan.db 또는 VULNSCAN_DB")
    sub = parser.add_subparsers(dest="command", required=True)

    update = sub.add_parser("update", help="NVD, CWE, KEV, EPSS를 로컬 DB에 반영")
    update.add_argument("--source", choices=["all", "nvd", "cwe", "kev", "epss"], default="all")
    update.add_argument("--since", help="NVD lastModified 시작 (YYYY-MM-DD 또는 ISO-8601)")
    update.add_argument("--until", help="NVD lastModified 끝")
    update.add_argument("--days", type=int, help="지금으로부터 N일. --since 가 있으면 무시")
    update.add_argument("--cve-id", action="append", dest="cve_ids", help="특정 CVE만 조회. 반복 가능")
    update.add_argument("--sample", action="store_true", help="네트워크 없이 저장소의 표본 데이터만 적재")
    update.add_argument("--nvd-file", help="NVD API 2.0 JSON 파일")
    update.add_argument("--cwe-file", help="CWE XML 또는 zip")
    update.add_argument("--kev-file", help="CISA KEV JSON")
    update.add_argument("--epss-file", help="EPSS API JSON 또는 CSV")
    update.add_argument("--epss-feed", action="store_true", help="FIRST 일일 EPSS CSV.gz를 받는다")
    update.set_defaults(func=cmd_update)

    export = sub.add_parser("export", help="CVE, CWE 또는 발견 사항을 JSON/CSV로 저장")
    export.add_argument("--kind", choices=["cve", "cwe", "finding"], default="cve")
    export.add_argument("--format", choices=["json", "csv"], default="json")
    export.add_argument("--out", required=True)
    export.add_argument("--scan-id", help="finding일 때 스캔 ID. 기본은 최근 스캔")
    export.set_defaults(func=cmd_export)

    network = sub.add_parser(
        "network",
        help="지정한 호스트의 열린 TCP 포트와 배너를 확인하거나 nmap XML을 반입",
    )
    network.add_argument("--targets", help="호스트, IP, CIDR. 쉼표로 구분")
    network.add_argument("--nmap-xml", help="nmap -oX 결과. 이 경로를 주면 직접 스캔하지 않아도 된다")
    network.add_argument("--ports", default=DEFAULT_PORTS, help=f"기본 {DEFAULT_PORTS}")
    network.add_argument("--timeout", type=float, default=0.8)
    network.add_argument("--max-hosts", type=int, default=256)
    network.add_argument("--max-probes", type=int, default=4096)
    network.add_argument("--workers", type=int, default=20)
    network.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="대상에 대한 점검 권한이 있음을 선언. 없으면 실행하지 않는다",
    )
    network.add_argument("--sample", action="store_true", help="보고서에 표본 표시를 남긴다")
    network.set_defaults(func=cmd_network)

    server = sub.add_parser("server", help="로컬 패키지와 sshd 설정을 점검")
    server.add_argument("--packages-file", help="name<TAB>version 목록. dpkg -l 형식도 가능")
    server.add_argument("--pip-file", help="pip list --format=json 결과")
    server.add_argument("--sshd-config", help="sshd_config 경로")
    server.add_argument("--no-local", action="store_true", help="이 호스트를 자동으로 수집하지 않는다")
    server.add_argument("--sample", action="store_true")
    server.set_defaults(func=cmd_server)

    endpoint = sub.add_parser("endpoint", help="OS, 커널, 설치 소프트웨어를 점검")
    endpoint.add_argument("--os-release-file")
    endpoint.add_argument("--kernel", help="비교할 커널 버전. 배포판 접미사가 있으면 CPE 비교를 생략")
    endpoint.add_argument("--packages-file")
    endpoint.add_argument("--uninstall-json", help="윈도우 제거 항목 JSON 배열")
    endpoint.add_argument("--apps-json", help="macOS system_profiler -json 결과")
    endpoint.add_argument("--sw-vers-file", help="sw_vers 출력")
    endpoint.add_argument("--no-local", action="store_true")
    endpoint.add_argument("--sample", action="store_true")
    endpoint.set_defaults(func=cmd_endpoint)

    report = sub.add_parser("report", help="저장된 발견 사항을 출력")
    report.add_argument("--format", choices=["table", "json", "csv", "html"], default="table")
    report.add_argument("--out")
    report.add_argument("--scan-id", help="기본은 최근 스캔. all 이면 전체")
    report.add_argument("--sample", action="store_true", help="표본 배너를 강제한다")
    report.set_defaults(func=cmd_report)

    dashboard = sub.add_parser("dashboard", help="로컬 HTML 대시보드")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8765)
    dashboard.add_argument("--allow-remote", action="store_true")
    dashboard.set_defaults(func=cmd_dashboard)
    return parser


def cmd_update(args: argparse.Namespace) -> int:
    if args.days is not None and args.days < 1:
        raise DataError("--days 는 1 이상이어야 합니다.")
    api_key = os.environ.get("NVD_API_KEY") or None
    if not args.sample and args.source in {"all", "nvd"} and not args.nvd_file:
        print(NVD_DISCLAIMER, file=sys.stderr)
    with Database(resolve_db(args.db)) as db:
        counts = run_update(
            db,
            source=args.source,
            since=args.since,
            until=args.until,
            days=args.days,
            cve_ids=args.cve_ids,
            sample=args.sample,
            nvd_file=args.nvd_file,
            cwe_file=args.cwe_file,
            kev_file=args.kev_file,
            epss_file=args.epss_file,
            epss_feed=args.epss_feed,
            api_key=api_key,
        )
        print(
            f"CVE {db.cve_count()}건, CWE {db.cwe_count()}건 저장 ({db.path})",
            file=sys.stderr,
        )
    for name, count in counts.items():
        print(f"{name}: {count}", file=sys.stderr)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    with Database(resolve_db(args.db)) as db:
        if args.kind == "cve":
            rows = db.export_cves()
        elif args.kind == "cwe":
            rows = db.export_cwes()
        else:
            rows = build_report(db, args.scan_id, sample=False)["findings"]
    path = Path(args.out)
    if args.format == "json":
        path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        path.write_text(_dicts_to_csv(rows), encoding="utf-8-sig")
    print(f"저장: {path} ({len(rows)}행)", file=sys.stderr)
    return 0


def _dicts_to_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    if not rows:
        return ""
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(str(key))
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        flat = {}
        for key, value in row.items():
            if isinstance(value, (list, dict)):
                flat[key] = json.dumps(value, ensure_ascii=False)
            else:
                flat[key] = value
        writer.writerow(flat)
    return buffer.getvalue()


def _warn_if_empty(db: Database) -> None:
    if db.cve_count() == 0:
        print(
            "로컬 CVE 데이터베이스가 비어 있습니다. "
            "`vulnscan update` 또는 `vulnscan update --sample`을 먼저 실행하세요.",
            file=sys.stderr,
        )


def _finish(db: Database, scan_id: str) -> int:
    findings = db.findings(scan_id)
    inventory = db.inventory_count(scan_id)
    print(f"스캔 {scan_id}: 인벤토리 {inventory}건, 발견 {len(findings)}건", file=sys.stderr)
    print("결과는 `vulnscan report`로 볼 수 있습니다.", file=sys.stderr)
    return 0


def cmd_network(args: argparse.Namespace) -> int:
    ensure_authorized(bool(args.i_am_authorized))
    items = []
    scope_bits: list[str] = []
    if args.nmap_xml:
        items.extend(parse_nmap_xml(read_text(args.nmap_xml)))
        scope_bits.append(f"nmap:{args.nmap_xml}")
    if args.targets:
        targets = [part.strip() for part in args.targets.split(",") if part.strip()]
        ports = parse_ports(args.ports)
        items.extend(
            scan_hosts(
                targets,
                ports,
                timeout=args.timeout,
                max_hosts=args.max_hosts,
                max_probes=args.max_probes,
                workers=args.workers,
            )
        )
        scope_bits.append("targets:" + ",".join(targets))
    if not scope_bits:
        raise ScopeError("--targets 또는 --nmap-xml 이 필요합니다.")
    with Database(resolve_db(args.db)) as db:
        _warn_if_empty(db)
        scan_id = run_assessment(
            db,
            kind="network",
            scope="; ".join(scope_bits),
            sample=bool(args.sample),
            items=items,
        )
        return _finish(db, scan_id)


def cmd_server(args: argparse.Namespace) -> int:
    asset = "server" if args.no_local else socket.gethostname()
    items: list[SoftwareItem] = []
    if args.packages_file:
        items.extend(
            packages_to_items(
                parse_package_lines(read_text(args.packages_file)),
                asset=asset,
                ecosystem="os",
                source="package-file",
            )
        )
    elif not args.no_local:
        for _ecosystem, name, version in collect_local_packages():
            items.extend(packages_to_items([(name, version)], asset=asset, ecosystem="os", source="dpkg/rpm"))
    if args.pip_file:
        items.extend(
            packages_to_items(
                parse_pip_json(read_text(args.pip_file)),
                asset=asset,
                ecosystem="pip",
                source="pip-file",
            )
        )
    elif not args.no_local:
        items.extend(packages_to_items(collect_local_pip(), asset=asset, ecosystem="pip", source="pip"))
    manuals = []
    if args.sshd_config:
        manuals = audit_sshd(read_text(args.sshd_config), asset=asset)
    elif not args.no_local:
        sshd_path = Path("/etc/ssh/sshd_config")
        if sshd_path.is_file():
            try:
                manuals = audit_sshd(sshd_path.read_text(encoding="utf-8", errors="replace"), asset=asset)
            except OSError as exc:
                print(f"sshd_config를 읽지 못했습니다: {exc}", file=sys.stderr)
    scope = "local-server" if not args.no_local else "files"
    with Database(resolve_db(args.db)) as db:
        _warn_if_empty(db)
        scan_id = run_assessment(
            db,
            kind="server",
            scope=scope,
            sample=bool(args.sample),
            items=items,
            manuals=manuals,
        )
        return _finish(db, scan_id)


def cmd_endpoint(args: argparse.Namespace) -> int:
    asset = "endpoint" if args.no_local else socket.gethostname()
    items: list[SoftwareItem] = []
    if args.os_release_file:
        items.append(os_release_item(parse_os_release(read_text(args.os_release_file)), asset))
    elif not args.no_local:
        text = local_os_release()
        if text:
            items.append(os_release_item(parse_os_release(text), asset))
    if args.kernel:
        items.append(kernel_item(args.kernel, asset))
    elif not args.no_local:
        kernel = local_kernel()
        if kernel:
            items.append(kernel_item(kernel, asset))
    if args.packages_file:
        items.extend(linux_package_items(parse_package_lines(read_text(args.packages_file)), asset))
    elif not args.no_local and sys.platform.startswith("linux"):
        rows = [(name, version) for _eco, name, version in collect_local_packages()]
        items.extend(linux_package_items(rows, asset))
    if args.uninstall_json:
        items.extend(parse_uninstall_json(read_text(args.uninstall_json)))
    elif not args.no_local and sys.platform.startswith("win"):
        items.extend(parse_uninstall_entries(read_windows_uninstall()))
    if args.apps_json:
        document = json.loads(read_text(args.apps_json))
        if not isinstance(document, dict):
            raise DataError("macOS 앱 JSON은 객체여야 합니다.")
        items.extend(parse_macos_apps(document))
    if args.sw_vers_file:
        values = parse_sw_vers(read_text(args.sw_vers_file))
        items.append(
            SoftwareItem(
                asset="macos",
                asset_kind="endpoint",
                component=values.get("ProductName") or "macOS",
                version=values.get("ProductVersion") or "",
                candidates=[],
                evidence="sw_vers: " + " ".join(f"{key}={values[key]}" for key in values),
                source="sw_vers",
            )
        )
    with Database(resolve_db(args.db)) as db:
        _warn_if_empty(db)
        scan_id = run_assessment(
            db,
            kind="endpoint",
            scope="endpoint",
            sample=bool(args.sample),
            items=items,
        )
        return _finish(db, scan_id)


def cmd_report(args: argparse.Namespace) -> int:
    with Database(resolve_db(args.db)) as db:
        report = build_report(db, args.scan_id, sample=bool(args.sample))
    text = render(report, args.format)
    if args.out:
        encoding = "utf-8-sig" if args.format == "csv" else "utf-8"
        Path(args.out).write_text(text, encoding=encoding)
        print(f"저장: {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from vulnscan.dashboard import serve

    serve(resolve_db(args.db), args.host, args.port, allow_remote=bool(args.allow_remote))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AuthorizationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except ScopeError as exc:
        print(f"범위 오류: {exc}", file=sys.stderr)
        return 2
    except (DataError, VulnscanError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
