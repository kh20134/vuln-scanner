import sqlite3

from vulnscan.match.cpe import cpe_matches_version, parse_cpe23, split_cpe


def _row(**kwargs):
    defaults = {
        "vulnerable": 1,
        "version": "*",
        "update_ver": "*",
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
    }
    defaults.update(kwargs)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    columns = ", ".join(defaults)
    placeholders = ", ".join(f":{key}" for key in defaults)
    connection.execute(f"CREATE TABLE t ({columns})")
    connection.execute(f"INSERT INTO t VALUES ({placeholders})", defaults)
    return connection.execute("SELECT * FROM t").fetchone()


def test_split_respects_escapes():
    parts = split_cpe(r"cpe:2.3:a:vendor:product\:name:1.0:*:*:*:*:*:*:*")
    assert parts[4] == "product:name"


def test_parse_cpe23():
    parsed = parse_cpe23("cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*")
    assert parsed is not None
    assert parsed["vendor"] == "openbsd"
    assert parsed["product"] == "openssh"
    assert parsed["version"] == "8.5"
    assert parsed["update"] == "p1"
    assert parse_cpe23("not-a-cpe") is None


def test_exact_update_and_range_and_unbounded():
    exact = _row(version="8.5", update_ver="p1")
    assert cpe_matches_version("8.5p1", exact)
    assert not cpe_matches_version("8.5p2", exact)
    ranged = _row(version_start_including="8.6", version_end_including="9.8")
    assert cpe_matches_version("8.9p1", ranged)
    assert not cpe_matches_version("9.8p1", ranged)
    unbounded = _row(version="*")
    assert not cpe_matches_version("1.0", unbounded)
    safe = _row(vulnerable=0, version="1.0")
    assert not cpe_matches_version("1.0", safe)
