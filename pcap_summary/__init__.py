# SPDX-FileCopyrightText: 2022-present Heath Brown <heathd.brown@gmail.com>
#
# SPDX-License-Identifier: MIT
"""Module contains common wireshark filters and methods to apply those filters.
  In addition to wrappers around common pyshark.FileCapture fucntions to simplify application of filters."""

# Standard Library Imports
import pathlib

# Third-party Library Imports
import pyshark

# Wireshark display_filters
BASIC_TCP = "tcp"
BASIC_UDP = "udp"
BASIC_HTTP = "http"
BASIC_DNS = "dns"
BASIC_IP = "ip"
BASIC_IPV6 = "ipv6"
BASIC_ICMP_ICMPV6 = "icmp || icmpv6"
BASIC_TLS_HANDSHAKE = "tls.record.content_type == 22"
BASIC_TLS = "tls"
TCP_SYN = "tcp.flags.syn==1 && tcp.flags.ack==0"
TCP_SYN_ACK = "tcp.flags & 0x12"
TCP_SYN_NON_ZERO_ACK = "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.ack==0"
TCP_CONN_REFUSAL = "tcp.flags.reset==1 && tcp.flags.ack==1 && tcp.seq==1 && tcp.ack==1"
TCP_DATA_IN_URGET = "tcp.urgent_pointer>0"
TCP_RESETS = "tcp.flags.reset==1"
TCP_RETRANSMISSION = "tcp.analysis.retransmission"
TCP_URGENT_BIT_SET = "tcp.flags.urg==1"
TCP_ANALYSIS_FLAGS = "tcp.analysis.flags"
TCP_WINDOW_SIZE_SCALEFACTOR = "tcp.window_size_scalefactor==-2"
TCP_BUFFER_FULL = " tcp.window_size == 0 && tcp.flags.reset != 1"
TLS_CLIENT_HELLO = "tls.handshake.type == 1"
TLS_SERVER_HELLO = "tls.handshake.type == 2"
TLS_ENCRYPTED_ALERT = "tls.record.content_type == 21"
DNS_PTR = "dns.qry.type == 12"
DNS_QUERY = "dns.flags.response == 0"
DNS_RESPONSE = "dns.flags.response == 1"
DNS_HIGH_ANSWER = "dns.count.answers>10"
DNS_RESPONSE_IPV6 = "dns.flags.response == 1 && ipv6"
DNS_IPV6 = "dns && ipv6"
DNS_IPV4 = "dns && ip"
HTTP_PUT_POST = "http.request.method in {PUT POST}"
HTTP_FILE_EXTENSION = 'http.request.uri matches "\.(exe|zip|jar)$"'
HTTP_CONTENT_TYPE = 'http.content_type contains "application"'
HTTP_REDIRECTS = "http.response.code>299 && http.response.code"
HTTP_GET_NOT_ON_80 = 'frame contains "GET" && !tcp.port==80'
FTP_LONG_USER = "ftp.request.command=='USER' && tcp.len>50"
P2P_TRAFFIC_172_16 = (
    "ip.src==172.16.0.0/16 && ip.dst==172.16.0.0/16 && !ip.dst==172.16.255.255"
)
IRC_TRAFFIC = "frame matches 'join #'"
NMAP_USER_AGENT = "http.user_agent contains 'Nmap'"
NESSUS_FRAME_OFFSET_CONTAINS = "frame[100-199] contains 'nessus'"
NESSUS_FRAME_OFFSET_MATCHES = "frame[100-199] matches 'nessus'"
MISC_UNEXPECTED = "tftp || irc || bittorrent"
MISC_SASSER_WORM = "ls_ads.opnum==0x09"
UDP_HOME_GROWN = "udp[8:3]==81:60:03"


def filter_not_ip_addr(ip_address: str) -> str:
    """Return a filter for removing a specific iP Address

    Args:
      ip_address (str): IP Address to ignore from display filter

    Returns:
      display_filter (str): Wireshark display filter that removes a specified IP Address string.

    """
    return f"!ip.addr=='{ip_address}"


def filter_ip_addr(ip_address: str) -> str:
    """Return a filter for include a specific iP Address

    Args:
      ip_address (str): IP Address to include from display filter

    Returns:
      display_filter (str): Wireshark display filter for a specified IP Address string.

    """
    return f"ip.addr=='{ip_address}'"


def filter_tls_server_name(servername: str) -> str:
    """Return a filter for including a specific server name in a TLS packet

    Args:
      server_name (str): Server Name to search for in a TLS packet extension

    Returns:
      display_filter (str): Wireshark display filter that includes a specified TLS extension server_name string.

    """
    return f"tls.handshake.extensions_server_name contains '{servername}'"


def filter_bad_dns_server(ip_address: str) -> str:
    """Return a filter for traffic that should not be destined for a DNS server:

    Args:
      ip_address (str): IP Address of a DNS Server

    Returns:
      display_filter (str): Wireshark display filter that shows non-DNS traffic for a specified IP Address string.

    """
    return f"ip.dst=='{ip_address}' && !udp.port==53 && !tcp.port==53"


def filter_tcp_window_size(win_size: int) -> str:
    """Return a filter for a specific TCP Windows Size.

    Args:
      win_size (int): TCP Windows Size to review

    Returns:
      display_filter (str): Wireshark display filter looking for specified TCP Window Size.

    """
    return f"tcp.window_size<{str(win_size)}"


def filter_tcp_stream(stream: int) -> str:
    """Return a filter for filtering a specific TCP stream id

    Args:
      stream (int): TCP Stream id to filter

    Returns:
      display_filter (str): Wireshark display filter for the specified TCP Stream Id.

    """
    return f"tcp.stream=={str(stream)}"


def filter_tcp_port(port: int) -> str:
    """Return a filter for a specific TCP Port

    Args:
      port (int): TCP Port to filter

    Returns:
      display_filter (str): Wireshark display filter that includes a specified TCP Port.

    """
    return f"tcp.port=={str(port)}"


def filter_tcp_analysis_act_rtt(roundtrip: int) -> str:
    """Return a filter for a specitific TCP Round Trip Time value.

    Args:
      roundtrip (int): TCP Round Trip Time Value to filter.

    Returns:
      display_filter (str): Wireshark display filter that looks for a specified TCP RTT value.

    """
    return f"tcp.analysis.ack_rtt>{str(roundtrip)}"


def filter_oui(oui: str) -> str:
    """Return a filter for removing a specific iP Address

    Args:
      ip_address (str): IP Address to ignore from display filter

    Returns:
      display_filter (str): Wireshark display filter that removes a specified IP Address string.

    """
    return f"eth.addr[0:3]=={oui}"


def filter_sip_to_contains(sip_to: str) -> str:
    """Return a filter for specific SIP String

    Args:
      sip_to (str): SIP To value that should be filtered

    Returns:
      display_filter (str): Wireshark display filter that includes a specified SIP_TO value.

    """
    return f"sip.To contains '{sip_to}'"


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
    filtered_dns = pyshark_filtered_capture(file, BASIC_DNS)

    if not has_packets(filtered_dns):
        print("No DNS packets found")

    if has_packets(filtered_dns):
        if summary:
            print(f"DNS Packets: {len(filtered_dns)}")

            filtered_dns_ptr = pyshark_filtered_capture(file, DNS_PTR)
            filtered_dns_ptr.load_packets()
            print(f"DNS PTR Packets: {len(filtered_dns_ptr)}")

            filtered_dns_query = pyshark_filtered_capture(file, DNS_QUERY)
            filtered_dns_query.load_packets()
            print(f"DNS Query Packets: {len(filtered_dns_query)}")

            filtered_dns_response = pyshark_filtered_capture(file, DNS_RESPONSE)
            filtered_dns_response.load_packets()
            print(f"DNS Response Packets: {len(filtered_dns_response)}")

            filtered_dns_high_answer = pyshark_filtered_capture(file, DNS_HIGH_ANSWER)
            filtered_dns_high_answer.load_packets()
            print(f"DNS High Answer Packets: {len(filtered_dns_high_answer)}")

        if not summary:
            filtered_dns.apply_on_packets(print_dns_info)
            filtered_dns_response = pyshark_filtered_capture(file, DNS_RESPONSE)
            filtered_dns_response.load_packets()
            print_dns_server(filtered_dns_response)


def http_analysis(file: str, summary: bool = True) -> None:
    """Analyze HTTP traffic and print findings

    Args:
        file (str): Path to capture file
        summary (bool, optional): Summarize or detailed results. Defaults to True.
    """
    filtered_http = pyshark_filtered_capture(file, BASIC_HTTP)

    if not has_packets(filtered_http):
        print("No HTTP packets found")

    if has_packets(filtered_http):
        if summary:
            print(f"HTTP Packets: {len(filtered_http)}")

            filtered_http_put_post = pyshark_filtered_capture(file, HTTP_PUT_POST)
            filtered_http_put_post.load_packets()
            print(f"HTTP Packets with Put or POST: {len(filtered_http_put_post)}")

            filtered_file_extension = pyshark_filtered_capture(
                file, HTTP_FILE_EXTENSION
            )
            filtered_file_extension.load_packets()
            print(
                f"HTTP Packets with exe, zip extensions: {len(filtered_file_extension)}"
            )

            filtered_content_type = pyshark_filtered_capture(file, HTTP_CONTENT_TYPE)
            filtered_content_type.load_packets()
            print(f"HTTP Packets with content type: {len(filtered_content_type)}")

            filtered_redirects = pyshark_filtered_capture(file, HTTP_REDIRECTS)
            filtered_redirects.load_packets()
            print(f"HTTP Packets with redirects: {len(filtered_redirects)}")

            filtered_http_get_not_on_80 = pyshark_filtered_capture(
                file, HTTP_GET_NOT_ON_80
            )
            filtered_http_get_not_on_80.load_packets()
            print(
                f"HTTP Packets with non standard ports: {len(filtered_http_get_not_on_80)}"
            )

            filtered_nmap_user_agent = pyshark_filtered_capture(file, NMAP_USER_AGENT)
            filtered_nmap_user_agent.load_packets()
            print(f"HTTP Packets with NMAP User Agent: {len(filtered_nmap_user_agent)}")


def tls_analysis(file: str, summary: bool = True) -> None:
    """Analyze TLS traffic and print findings

    Args:
        file (str): Path to capture file
        summary (bool, optional): Summarize or detailed results. Defaults to True.
    """
    filtered_tls = pyshark_filtered_capture(file, BASIC_TLS)

    if not has_packets(filtered_tls):
        print("No TLS packets found")

    if has_packets(filtered_tls):
        if summary:
            print(f"TLS Packets: {len(filtered_tls)}")

            filtered_tls_handshake = pyshark_filtered_capture(file, BASIC_TLS_HANDSHAKE)
            filtered_tls_handshake.load_packets()
            print(f"TLS Handshake Packets: {len(filtered_tls_handshake)}")

            filtered_tls_client_hello = pyshark_filtered_capture(file, TLS_CLIENT_HELLO)
            filtered_tls_client_hello.load_packets()
            print(f"TLS Client Hello Packets: {len(filtered_tls_client_hello)}")

            filtered_tls_server_hello = pyshark_filtered_capture(file, TLS_SERVER_HELLO)
            filtered_tls_server_hello.load_packets()
            print(f"TLS Server Hello Packets: {len(filtered_tls_server_hello)}")

            filtered_encrypted_alert = pyshark_filtered_capture(
                file, TLS_ENCRYPTED_ALERT
            )
            filtered_encrypted_alert.load_packets()
            print(f"TLS Encrypted Alert Packets: {len(filtered_encrypted_alert)}")


