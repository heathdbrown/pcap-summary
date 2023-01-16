"""pcap_summary.report contains logic to report out common findings with network packet captures"""

import pathlib

import pyshark

from . import filters


def valid_filename(file: str) -> bool:
    """Validate filename and return True or False

    Param:
      file (str): File path string

    Returns:
      bool:
    """

    file_extension = pathlib.Path(file).suffix

    if file_extension in [".pcap", ".pcapng", ".cap"]:
        return True
    return False


def pyshark_capture(file: str) -> pyshark.FileCapture:
    """generic wrapper on pyshark.FileCapture

    Args:
      file (str): File path to a valid capture file format

    Returns:
      pyshark.FileCapture (object): pyshark.FileCapture object returned

    """
    if not valid_filename(file):
        raise NameError
    return pyshark.FileCapture(file)


def pyshark_filtered_capture(file: str, display_filter: str) -> pyshark.FileCapture:
    """Generic wrapper on pyshark.FileCapture, allowing for display_filter

    Args:
      file (str): File path to a valid capture file format

      display_filter (str): Wireshark display filter to apply to specified file capture.

    Returns:
      pyshark.FileCapture (object): pyshark.FileCapture object returned
    """
    if not valid_filename(file):
        raise NameError
    return pyshark.FileCapture(file, display_filter=display_filter)


def print_dns_info(pkt):
    """Print DNS conversation Information from packet

    Args:
      pkt (object): Pyshark FileCapture packet object

    Returns:
      None
    """
    if pkt.dns.qry_name:
        print(f"DNS request from {ip_src(pkt)} : {pkt.dns.qry_name}")
    elif pkt.dns.resp_name:
        print(f"DNS Response from {ip_src(pkt)}: {pkt.dns.resp_name}")


def ip_src(pkt) -> str:
    """Extract IP Source information from packet

    Args:
      pkt (object): Pyshark FileCapture packet object

    Returns:
      ip_source (str): Find appropriate layer for IP protocol and returns accordingly
    """
    if "IPV6" not in str(pkt.layers):
        return pkt.ip.src
    return pkt.ipv6.src


def dns_servers_from_capture(capture: pyshark.FileCapture) -> set[str]:
    """Return DNS servers that send a response from capture

    Args:
      capture (pyshark.FileCapture): Pyshark FileCapture packet object

    Returns:
      dns servers (set(str)): DNS Servers that send a response
    """
    return set([ip_src(packet) for packet in capture])


def print_dns_server(capture: pyshark.FileCapture):
    """Print DNS Servers from capture

    Args:
      capture (pyshark.FileCapture): Pyshark FileCapture packet object

    Returns:
      None
    """
    print("DNS Servers:")
    for server in dns_servers_from_capture(capture):
        print("\t - " + server)


def has_packets(capture: pyshark.FileCapture) -> bool:
    """Review if capture length is greater than zero

    Args:
      capture (pyshark.FileCapture): Pyshark FileCapture object

    Return:
      bool
    """
    capture.load_packets()
    if not len(capture) > 0:
        return False
    return True


def dns_analysis(file: str, summary: bool = True) -> None:
    """Analyze DNS traffic and print findings

    Args:
      file (str): Path to capture file
      summary (bool): Summarize or provide details
    """
    filtered_dns = pyshark_filtered_capture(file, filters.BASIC_DNS)

    if not has_packets(filtered_dns):
        print("No DNS packets found")

    if has_packets(filtered_dns):

        print(f"DNS Packets: {len(filtered_dns)}")

        filtered_dns_ptr = pyshark_filtered_capture(file, filters.DNS_PTR)
        filtered_dns_ptr.load_packets()
        print(f"DNS PTR Packets: {len(filtered_dns_ptr)}")

        filtered_dns_query = pyshark_filtered_capture(file, filters.DNS_QUERY)
        filtered_dns_query.load_packets()
        print(f"DNS Query Packets: {len(filtered_dns_query)}")

        filtered_dns_response = pyshark_filtered_capture(file, filters.DNS_RESPONSE)
        filtered_dns_response.load_packets()
        print(f"DNS Response Packets: {len(filtered_dns_response)}")

        filtered_dns_high_answer = pyshark_filtered_capture(
            file, filters.DNS_HIGH_ANSWER
        )
        filtered_dns_high_answer.load_packets()
        print(f"DNS High Answer Packets: {len(filtered_dns_high_answer)}")

        filtered_dns.apply_on_packets(print_dns_info)
        filtered_dns_response = pyshark_filtered_capture(file, filters.DNS_RESPONSE)
        filtered_dns_response.load_packets()
        print_dns_server(filtered_dns_response)
        for server in dns_servers_from_capture(filtered_dns_response):
            filtered_dns_server = pyshark_filtered_capture(
                file, filters.filter_bad_dns_server(server)
            )
            if has_packets(filtered_dns_server):
                print(f"DNS Server has non DNS traffic!!! {server}")


def http_analysis(file: str, summary: bool = True) -> None:
    """Analyze HTTP traffic and print findings

    Args:
        file (str): Path to capture file
        summary (bool, optional): Summarize or detailed results. Defaults to True.
    """
    filtered_http = pyshark_filtered_capture(file, filters.BASIC_HTTP)

    if not has_packets(filtered_http):
        print("No HTTP packets found")

    if has_packets(filtered_http):
        print(f"HTTP Packets: {len(filtered_http)}")

        filtered_http_put_post = pyshark_filtered_capture(file, filters.HTTP_PUT_POST)
        filtered_http_put_post.load_packets()
        print(f"HTTP Packets with Put or POST: {len(filtered_http_put_post)}")

        filtered_file_extension = pyshark_filtered_capture(
            file, filters.HTTP_FILE_EXTENSION
        )
        filtered_file_extension.load_packets()
        print(f"HTTP Packets with exe, zip extensions: {len(filtered_file_extension)}")

        filtered_content_type = pyshark_filtered_capture(
            file, filters.HTTP_CONTENT_TYPE
        )
        filtered_content_type.load_packets()
        print(f"HTTP Packets with content type: {len(filtered_content_type)}")

        filtered_redirects = pyshark_filtered_capture(file, filters.HTTP_REDIRECTS)
        filtered_redirects.load_packets()
        print(f"HTTP Packets with redirects: {len(filtered_redirects)}")

        filtered_http_get_not_on_80 = pyshark_filtered_capture(
            file, filters.HTTP_GET_NOT_ON_80
        )
        filtered_http_get_not_on_80.load_packets()
        print(
            f"HTTP Packets with non standard ports: {len(filtered_http_get_not_on_80)}"
        )

        filtered_nmap_user_agent = pyshark_filtered_capture(
            file, filters.NMAP_USER_AGENT
        )
        filtered_nmap_user_agent.load_packets()
        print(f"HTTP Packets with NMAP User Agent: {len(filtered_nmap_user_agent)}")


def tls_analysis(file: str, summary: bool = True) -> None:
    """Analyze TLS traffic and print findings

    Args:
        file (str): Path to capture file
        summary (bool, optional): Summarize or detailed results. Defaults to True.
    """
    filtered_tls = pyshark_filtered_capture(file, filters.BASIC_TLS)

    if not has_packets(filtered_tls):
        print("No TLS packets found")

    if has_packets(filtered_tls):
        print(f"TLS Packets: {len(filtered_tls)}")

        filtered_tls_handshake = pyshark_filtered_capture(
            file, filters.BASIC_TLS_HANDSHAKE
        )
        filtered_tls_handshake.load_packets()
        print(f"TLS Handshake Packets: {len(filtered_tls_handshake)}")

        filtered_tls_client_hello = pyshark_filtered_capture(
            file, filters.TLS_CLIENT_HELLO
        )
        filtered_tls_client_hello.load_packets()
        print(f"TLS Client Hello Packets: {len(filtered_tls_client_hello)}")

        filtered_tls_server_hello = pyshark_filtered_capture(
            file, filters.TLS_SERVER_HELLO
        )
        filtered_tls_server_hello.load_packets()
        print(f"TLS Server Hello Packets: {len(filtered_tls_server_hello)}")

        filtered_encrypted_alert = pyshark_filtered_capture(
            file, filters.TLS_ENCRYPTED_ALERT
        )
        filtered_encrypted_alert.load_packets()
        print(f"TLS Encrypted Alert Packets: {len(filtered_encrypted_alert)}")


def tcp_analysis(file: str, summary: bool = True) -> None:
    """Analyze TCP traffic and print findings

    Args:
        file (str): Path to capture file
        summary (bool, optional): Summarize or detailed results. Defaults to True.
    """
    filtered_tcp = pyshark_filtered_capture(file, filters.BASIC_TCP)

    if not has_packets(filtered_tcp):
        print("No TCP packets found")

    if has_packets(filtered_tcp):
        print(f"TCP Packets: {len(filtered_tcp)}")

        filtered_tcp_analysis_flag = pyshark_filtered_capture(
            file, filters.TCP_ANALYSIS_FLAGS
        )
        filtered_tcp_analysis_flag.load_packets()
        print(f"TCP Packets with Analysis Flags: {len(filtered_tcp_analysis_flag)}")

        filtered_tcp_analysis_retransmissions = pyshark_filtered_capture(
            file, filters.TCP_RETRANSMISSION
        )
        filtered_tcp_analysis_retransmissions.load_packets()
        print(
            f"TCP Packets with Retransmissions: {len(filtered_tcp_analysis_retransmissions)}"
        )

        filtered_syn = pyshark_filtered_capture(file, filters.TCP_SYN)
        filtered_syn.load_packets()
        print(f"TCP SYN Packets: {len(filtered_syn)}")

        filtered_syn_ack = pyshark_filtered_capture(file, filters.TCP_SYN_ACK)
        filtered_syn_ack.load_packets()
        print(f"TCP SYN ACK Packets: {len(filtered_syn_ack)}")

        filtered_syn_non_zero_ack = pyshark_filtered_capture(
            file, filters.TCP_SYN_NON_ZERO_ACK
        )
        filtered_syn_non_zero_ack.load_packets()
        print(f"TCP SYN Non Zero ACK Packets: {len(filtered_syn_non_zero_ack)}")

        filtered_conn_refusal = pyshark_filtered_capture(file, filters.TCP_CONN_REFUSAL)
        filtered_conn_refusal.load_packets()
        print(f"TCP Connection Refused Packets: {len(filtered_conn_refusal)}")

        filtered_data_in_urgent = pyshark_filtered_capture(
            file, filters.TCP_DATA_IN_URGET
        )
        filtered_data_in_urgent.load_packets()
        print(f"TCP Data in Urgent Packets: {len(filtered_data_in_urgent)}")

        filtered_resets = pyshark_filtered_capture(file, filters.TCP_RESETS)
        filtered_resets.load_packets()
        print(f"TCP Reset Packets: {len(filtered_resets)}")

        filtered_urgent_bit_set = pyshark_filtered_capture(
            file, filters.TCP_URGENT_BIT_SET
        )
        filtered_urgent_bit_set.load_packets()
        print(f"TCP Urgent Bit Set Packets: {len(filtered_urgent_bit_set)}")

        filtered_window_size_scalefactor = pyshark_filtered_capture(
            file, filters.TCP_WINDOW_SIZE_SCALEFACTOR
        )
        filtered_window_size_scalefactor.load_packets()
        print(
            f"TCP Window Size ScaleFactor Packets: {len(filtered_window_size_scalefactor)}"
        )

        filtered_buff_full = pyshark_filtered_capture(file, filters.TCP_BUFFER_FULL)
        filtered_buff_full.load_packets()
        print(f"TCP Buffer Full Packets: {len(filtered_buff_full)}")

        http_analysis(file)
        tls_analysis(file)


def udp_analysis(file: str, summary: bool = True) -> None:
    """Analyze UDP traffic and print findings

    Args:
        file (str): Path to capture file
        summary (bool, optional): Summarize or detailed results. Defaults to True.
    """
    filtered_udp = pyshark_filtered_capture(file, filters.BASIC_UDP)

    if not has_packets(filtered_udp):
        print("No UDP packets found")

    if has_packets(filtered_udp):
        print(f"UDP Packets: {len(filtered_udp)}")

        filtered_udp_home_grown = pyshark_filtered_capture(file, filters.UDP_HOME_GROWN)
        filtered_udp_home_grown.load_packets()
        print(f"UDP Home Grown Packets: {len(filtered_udp_home_grown)}")

        dns_analysis(file)
