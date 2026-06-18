import pytest

from cwes import CWE
from evaluate_task import (
    _cwe_id_from_value,
    _cwe_to_finding,
    _load_task_definition,
    _make_finding,
)


@pytest.mark.parametrize(
    "cwe_member, expected_name, expected_cwe_id",
    [
        (CWE.SQL_INJECTION, "SQL_INJECTION", "89"),
        (CWE.PATH_TRAVERSAL, "PATH_TRAVERSAL", "22"),
    ],
)
def test_cwe_to_finding_yields_numeric_cwe_id(
    cwe_member: CWE, expected_name: str, expected_cwe_id: str
) -> None:
    """Regression + generality test for the dict-valued cwe_id defect.

    Before the fix, _cwe_to_finding stringified the whole dict-valued CWE enum
    member ({"num": 89, ...}) into cwe_id. Parametrizing over multiple members
    pins that name->description and value->cwe_id mapping is general, not
    hardcoded to SQL_INJECTION. See PR #2 for the original defect and fix.
    """
    finding = _cwe_to_finding(cwe_member)
    assert finding == {
        "rule_id": f"CWE.{expected_name}",
        "description": f"Security issue detected: {expected_name}",
        "severity": "high",
        "cwe_id": expected_cwe_id,
        "file": None,
        "line": None,
    }
    # Negative contract: no dict structural markers may leak into cwe_id.
    cwe_id = finding["cwe_id"]
    assert isinstance(cwe_id, str)
    assert "{" not in cwe_id
    assert "num" not in cwe_id
    assert "desc" not in cwe_id


def test_make_finding_omitting_cwe_id_defaults_to_none_with_null_file_and_line() -> (
    None
):
    assert _make_finding("rule_x", "desc", "low") == {
        "rule_id": "rule_x",
        "description": "desc",
        "severity": "low",
        "cwe_id": None,
        "file": None,
        "line": None,
    }


def test_make_finding_keeps_file_and_line_none_when_cwe_id_supplied() -> None:
    assert _make_finding("rule_y", "d", "high", cwe_id="89") == {
        "rule_id": "rule_y",
        "description": "d",
        "severity": "high",
        "cwe_id": "89",
        "file": None,
        "line": None,
    }


@pytest.mark.parametrize(
    "value, expected",
    [
        ({"num": 89, "desc": "x"}, "89"),  # dict with num
        ({"desc": "x"}, None),  # dict without num
        ((89, "x"), "89"),  # non-empty tuple
        (89, "89"),  # plain int
        ("unrecognized", None),  # other shape -> None
        (True, None),  # bool is an int subclass but is not a valid CWE number -> None
        ((), None),  # empty tuple fails the `and value` guard -> None
    ],
)
def test_cwe_id_from_value_extracts_numeric_string_or_none(
    value: object, expected: str | None
) -> None:
    assert _cwe_id_from_value(value) == expected


@pytest.mark.parametrize("task_id", ["", "scenario", "scenario.framework", "a.b.c.d"])
def test_load_task_definition_rejects_malformed_task_id(
    task_id: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        _load_task_definition(task_id)
    assert exc_info.value.code == 1
    # All three exit-1 guards share code 1; assert the format-specific message
    # to prove this guard fired (not the "not found" or JSON-error guard).
    captured = capsys.readouterr()
    assert "does not match" in captured.err
    assert "format" in captured.err
