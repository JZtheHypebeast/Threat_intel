from collector .unstructured_core import normalize_and_merge_iocs
import pytest

def test_normalize_url_and_domain ():
    text ="Visit https://Example.COM/path?query=1 and http://example.com/other"
    res =normalize_and_merge_iocs (text ,source ="t")
    types ={r ["type"]for r in res }

    assert any (r ["type"]=="url"for r in res )
    assert any (r ["type"]=="domain"for r in res )

    assert any (r ["value"]=="example.com"for r in res )

@pytest .mark .parametrize (
"text,expected_type,expected_value",
[
("Contact 192.168.1.1:8080 or 192.168.1.1","ip","192.168.1.1"),
("Reach out to Admin@Example.COM for details","email","admin@example.com"),
],
)
def test_normalize_various_iocs (text ,expected_type ,expected_value ):
    res =normalize_and_merge_iocs (text ,source ="t")
    assert any (r ["type"]==expected_type and r ["value"]==expected_value for r in res )
