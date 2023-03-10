"""pcap_summary.filters contains common display filters used in analyzing network packet captures"""


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
