"""비침투 TCP 연결 점검과 nmap XML 반입.

열린 포트에 연결하고 배너를 읽는다. HTTP 계열 포트에는
``HEAD / HTTP/1.0``만 보낸다. 인증 시도, 무차별 대입, 익스플로잇 페이로드는 없다.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from xml.etree import ElementTree as ET

from vulnscan.assess.models import SoftwareItem
from vulnscan.errors import AuthorizationError, DataError, ScopeError
from vulnscan.match.catalog import banner_match, nmap_candidates

AUTHORIZATION_NOTICE = """[인가 확인]
이 네트워크 점검은 TCP 연결로 열린 포트와 서비스 배너만 확인합니다.
익스플로잇, 무차별 대입, 인증 시도, 공격 페이로드 전송은 하지 않습니다.
소유자이거나 명시적 서면 인가를 받은 대상만 지정하세요.
인가 없는 포트 스캔은 정보통신망법 등 관련 법령에 저촉될 수 있습니다.
도구는 인가 사실을 검증하지 못합니다. --i-am-authorized 는 운영자의 확인 선언입니다."""

HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8880, 8888, 3000, 5000}
DEFAULT_PORTS = "22,80,443,8080,8443"

ProbeFunc = Callable[[str, int, float], tuple[bool, str]]


def ensure_authorized(confirmed: bool) -> None:
    if not confirmed:
        raise AuthorizationError(AUTHORIZATION_NOTICE + "\n\n--i-am-authorized 가 없어 네트워크 점검을 중단했습니다.")
    print(AUTHORIZATION_NOTICE, file=sys.stderr)


def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        piece = part.strip()
        if not piece:
            continue
        try:
            if "-" in piece:
                start_text, end_text = piece.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start < 1 or end > 65535 or start > end:
                    raise ScopeError(f"포트 범위가 잘못되었습니다: {piece}")
                ports.extend(range(start, end + 1))
            else:
                port = int(piece)
                if port < 1 or port > 65535:
                    raise ScopeError(f"포트가 잘못되었습니다: {piece}")
                ports.append(port)
        except ValueError as exc:
            raise ScopeError(f"포트가 잘못되었습니다: {piece}") from exc
    unique = list(dict.fromkeys(ports))
    if not unique:
        raise ScopeError("포트가 비어 있습니다.")
    return unique


def _hosts_in_network(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> list[str]:
    if network.version == 4 and network.prefixlen >= 31:
        return [str(address) for address in network]
    if network.num_addresses == 1:
        return [str(network.network_address)]
    return [str(address) for address in network.hosts()]


def expand_targets(raw_targets: list[str], max_hosts: int) -> list[str]:
    hosts: list[str] = []
    for item in raw_targets:
        text = item.strip()
        if not text:
            continue
        if "/" in text:
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError as exc:
                raise ScopeError(f"CIDR이 잘못되었습니다: {text}") from exc
            if network.prefixlen == 0 or network.num_addresses > max_hosts + 2:
                raise ScopeError(
                    f"대상 {text} 이 너무 큽니다. 한 번에 최대 {max_hosts}대입니다. "
                    "범위를 나누거나 --max-hosts 를 조정하세요."
                )
            expanded = _hosts_in_network(network)
            if len(expanded) > max_hosts:
                raise ScopeError(f"대상 {text} 의 호스트 수가 {max_hosts}대를 넘습니다.")
            hosts.extend(expanded)
        else:
            hosts.append(text)
    unique = list(dict.fromkeys(hosts))
    if not unique:
        raise ScopeError("점검 대상이 비어 있습니다.")
    if len(unique) > max_hosts:
        raise ScopeError(f"대상이 {len(unique)}대입니다. 최대 {max_hosts}대입니다.")
    return unique


def probe_tcp(host: str, port: int, timeout: float) -> tuple[bool, str]:
    """포트가 열리면 (True, 배너), 닫혀 있으면 (False, '')."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 1.0))
            chunks: list[bytes] = []
            try:
                data = sock.recv(512)
                if data:
                    chunks.append(data)
            except TimeoutError:
                pass
            if port in HTTP_PORTS:
                try:
                    host_header = host.encode("ascii", "ignore") or b"localhost"
                    request = b"HEAD / HTTP/1.0\r\nHost: " + host_header + b"\r\nConnection: close\r\n\r\n"
                    sock.sendall(request)
                    data = sock.recv(512)
                    if data:
                        chunks.append(data)
                except OSError:
                    pass
            banner = b"".join(chunks)[:1024].decode("utf-8", "replace").replace("\x00", "")
            return True, banner
    except OSError:
        return False, ""


def _item_from_identity(
    asset: str,
    component: str,
    version: str,
    candidates: list[tuple[str, str, str]],
    evidence: str,
    source: str,
) -> SoftwareItem:
    return SoftwareItem(
        asset=asset,
        asset_kind="network",
        component=component,
        version=version,
        candidates=candidates,
        evidence=evidence,
        source=source,
    )


def identify_banner(asset: str, banner: str) -> SoftwareItem | None:
    matched = banner_match(banner)
    if matched is None:
        return None
    version, candidates = matched
    product = candidates[0][2]
    return _item_from_identity(
        asset,
        product,
        version,
        candidates,
        f"banner: {banner.strip()[:240]}",
        "banner",
    )


def scan_hosts(
    targets: list[str],
    ports: list[int],
    *,
    timeout: float,
    max_hosts: int,
    max_probes: int,
    workers: int,
    probe: ProbeFunc = probe_tcp,
) -> list[SoftwareItem]:
    hosts = expand_targets(targets, max_hosts)
    if len(hosts) * len(ports) > max_probes:
        raise ScopeError(
            f"점검 횟수 {len(hosts) * len(ports)}회가 상한 {max_probes}회를 넘습니다. "
            "포트나 대상을 줄이거나 --max-probes 를 조정하세요."
        )
    items: list[SoftwareItem] = []
    jobs = [(host, port) for host in hosts for port in ports]
    if workers <= 1 or len(jobs) <= 1:
        results = [(host, port, probe(host, port, timeout)) for host, port in jobs]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [(host, port, pool.submit(probe, host, port, timeout)) for host, port in jobs]
            for host, port, future in futures:
                results.append((host, port, future.result()))
    for host, port, (is_open, banner) in results:
        if not is_open:
            continue
        asset = f"{host}:{port}/tcp"
        identified = identify_banner(asset, banner) if banner else None
        if identified is not None:
            items.append(identified)
        else:
            items.append(
                _item_from_identity(
                    asset,
                    "unknown",
                    "",
                    [],
                    f"open tcp/{port}" + (f"; banner: {banner.strip()[:180]}" if banner else ""),
                    "tcp",
                )
            )
    return items


def parse_nmap_xml(text: str) -> list[SoftwareItem]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise DataError("nmap XML을 해석하지 못했습니다.") from exc
    items: list[SoftwareItem] = []
    for host in root.findall("host"):
        address = ""
        for node in host.findall("address"):
            if node.get("addrtype") in {None, "ipv4", "ipv6"}:
                address = node.get("addr") or address
                if node.get("addrtype") == "ipv4":
                    break
        if not address:
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid") or "?"
            protocol = port.get("protocol") or "tcp"
            service = port.find("service")
            product = service.get("product") if service is not None else ""
            version = service.get("version") if service is not None else ""
            extra = service.get("extrainfo") if service is not None else ""
            asset = f"{address}:{port_id}/{protocol}"
            candidates = nmap_candidates(product or "")
            banner_item = None
            if extra:
                banner_item = identify_banner(asset, f"{product} {version} {extra}".strip())
            if not candidates and banner_item is not None:
                items.append(banner_item)
                continue
            evidence = f"nmap: {product} {version}".strip()
            if extra:
                evidence = f"{evidence} ({extra})"
            items.append(
                _item_from_identity(
                    asset,
                    product or "unknown",
                    version or "",
                    candidates,
                    evidence,
                    "nmap",
                )
            )
    return items
