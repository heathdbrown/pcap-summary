import pcap_summary


def test_valid_filename():
    assert pcap_summary.valid_filename("test.pcap") is True
    assert pcap_summary.valid_filename("test.pcapng") is True
    assert pcap_summary.valid_filename("test.cap") is True
    assert pcap_summary.valid_filename("test.test") is False
