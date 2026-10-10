"""MITRE CWE 목록 파서. 공식 XML(또는 그 zip)을 읽는다."""

from __future__ import annotations

import io
import zipfile
from xml.etree import ElementTree as ET

from vulnscan.db import Database
from vulnscan.errors import DataError

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_NS = "http://cwe.mitre.org/cwe-7"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_cwe_xml(data: bytes) -> list[dict[str, str]]:
    """Weakness와 Category를 읽는다. 네임스페이스가 없어도 동작한다."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise DataError("CWE XML을 해석하지 못했습니다.") from exc
    rows: list[dict[str, str]] = []
    for element in root.iter():
        kind = _local(element.tag)
        if kind not in {"Weakness", "Category"}:
            continue
        cwe_id = element.get("ID")
        name = element.get("Name")
        if not cwe_id or not name:
            continue
        description = ""
        for child in list(element):
            if _local(child.tag) in {"Description", "Summary"}:
                description = " ".join("".join(child.itertext()).split())
                if description:
                    break
        rows.append(
            {
                "cwe_id": cwe_id,
                "name": name,
                "description": description,
                "abstraction": element.get("Abstraction") or kind,
                "status": element.get("Status") or "",
            }
        )
    if not rows:
        raise DataError("CWE XML에서 Weakness를 찾지 못했습니다.")
    return rows


def xml_bytes_from_download(payload: bytes) -> bytes:
    """zip이면 안의 XML을, 아니면 본문을 그대로 쓴다."""
    if payload[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                names = [name for name in archive.namelist() if name.endswith(".xml")]
                if not names:
                    raise DataError("CWE zip 안에 XML이 없습니다.")
                return archive.read(names[0])
        except zipfile.BadZipFile as exc:
            raise DataError("CWE zip이 손상되었습니다.") from exc
    return payload


def load_cwe_bytes(db: Database, payload: bytes) -> int:
    rows = parse_cwe_xml(xml_bytes_from_download(payload))
    return db.upsert_cwes(rows)
