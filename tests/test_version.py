from vulnscan.match.version import compare_versions, in_range, upstream_version


def test_numeric_and_letter_ordering():
    assert compare_versions("1.2", "1.10") < 0
    assert compare_versions("8.9p1", "9.3") < 0
    assert compare_versions("9.8", "9.8p1") < 0
    assert compare_versions("1.0.2", "1.0.2zd") < 0
    assert compare_versions("1.0.2z", "1.0.2zd") < 0
    assert compare_versions("2.14.1", "2.15.0") < 0
    assert compare_versions("3.0.1", "3.0.2") < 0
    assert compare_versions("5.6.1", "5.6.1") == 0
    assert compare_versions("2.4.49", "2.4.49") == 0


def test_upstream_strips_epoch_and_debian_revision():
    assert upstream_version("1:8.9p1-3ubuntu0.10") == "8.9p1"
    assert upstream_version("3.0.1-0ubuntu1") == "3.0.1"
    assert upstream_version("2.35-0ubuntu3.4") == "2.35"
    assert upstream_version("1.0.0-rc1") == "1.0.0-rc1"
    assert upstream_version("1.18.0") == "1.18.0"


def test_range_bounds():
    assert in_range("8.9p1", "8.6", None, "9.8", None)
    assert not in_range("9.8p1", "8.6", None, "9.8", None)
    assert in_range("3.0.1", "3.0.0", None, None, "3.0.2")
    assert not in_range("3.0.2", "3.0.0", None, None, "3.0.2")
    assert in_range("5.15.12", "5.15", None, None, "5.15.25")
    assert not in_range("2.14.1", "2.0.1", None, None, "2.3.1")
