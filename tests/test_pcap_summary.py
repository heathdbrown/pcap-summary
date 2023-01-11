import pcap_summary
import pytest

testdataforvalid_filename = [
    ("test.pcap", True),
    ("test.pcapng", True),
    ("test.cap", True),
    ("test.test", False),
]


@pytest.mark.parametrize("filename, expected", testdataforvalid_filename)
def test_valid_filename(filename, expected):
    assert pcap_summary.valid_filename(filename) is expected
