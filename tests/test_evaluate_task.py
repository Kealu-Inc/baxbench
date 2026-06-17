import pytest

from cwes import CWE
from evaluate_task import _cwe_id_from_value, _cwe_to_finding


def test_cwe_to_finding_sql_injection_yields_numeric_cwe_id():
    # CWE.SQL_INJECTION.value == {"num": 89, "desc": "..."}; cwe_id must be "89",
    # NOT the serialized dict string.
    finding = _cwe_to_finding(CWE.SQL_INJECTION)
    assert finding["cwe_id"] == "89"


@pytest.mark.parametrize(
    "value, expected",
    [
        ({"num": 89, "desc": "x"}, "89"),  # dict with num
        ({"desc": "x"}, None),  # dict without num
        ((89, "x"), "89"),  # non-empty tuple
        (89, "89"),  # plain int
        ("unrecognized", None),  # other shape -> None
    ],
)
def test_cwe_id_from_value_branches(value, expected):
    assert _cwe_id_from_value(value) == expected
