# SPDX-FileCopyrightText: 2022-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
import pyshark

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
    return f"!ip.addr=='{ip_address}"


def filter_ip_addr(ip_address: str) -> str:
    return f"ip.addr=='{ip_address}'"


def filter_tls_server_name(servername: str) -> str:
    return f"tls.handshake.extensions_server_name contains '{servername}'"


def filter_bad_dns_server(ip_address: str) -> str:
    return f"ip.dst=='{ip_address}' && !udp.port==53 && !tcp.port==53"


def filter_tcp_window_size(win_size: int) -> str:
    return f"tcp.window_size<{str(win_size)}"


def filter_tcp_stream(stream: int) -> str:
    return f"tcp.stream=={str(stream)}"


def filter_tcp_port(port: int) -> str:
    return f"tcp.port=={str(port)}"


def filter_tcp_analysis_act_rtt(roundtrip: int) -> str:
    return f"tcp.analysis.ack_rtt>{str(roundtrip)}"


def filter_oui(oui: str) -> str:
    return f"eth.addr[0:3]=={oui}"


def filter_sip_to_contains(sip_to: str) -> str:
    return f"sip.To contains '{sip_to}'"


def pyshark_capture(file: str) -> pyshark.FileCapture:
    return pyshark.FileCapture(file)


def pyshark_filtered_capture(file: str, display_filter: str) -> pyshark.FileCapture:
    return pyshark.FileCapture(file, display_filter=display_filter)


def print_dns_info_v4(pkt):
    if pkt.dns.qry_name:
        print(f"DNS request from {pkt.ip.src} : {pkt.dns.qry_name}")
    elif pkt.dns.resp_name:
        print(f"DNS Response from {pkt.ip.src}: {pkt.dns.resp_name}")


def print_dns_info_v6(pkt):
    if pkt.dns.qry_name:
        print(f"DNS request from {pkt.ipv6.src}: {pkt.dns.qry_name}")
    elif pkt.dns.resp_name:
        print(f"DNS response from {pkt.ipv6.src}: {pkt.dns.resp_name}")


def ip_src(pkt) -> str:
    return pkt.ip.src


def ipv6_src(pkt) -> str:
    return pkt.ipv6.src


def dns_servers_from_capture(
    capture: pyshark.FileCapture, ip_version: int = 4
) -> set[str]:
    if ip_version == 4:
        return set([ip_src(packet) for packet in capture])
    if ip_version == 6:
        return set([ipv6_src(packet) for packet in capture])


def dns_servers_from_capture_v4(capture: pyshark.FileCapture) -> set[str]:
    return set([ip_src(packet) for packet in capture])


def dns_servers_from_capture_v6(capture: pyshark.FileCapture) -> set[str]:
    return set([ipv6_src(packet) for packet in capture])


def print_dns_servers_v4(capture: pyshark.FileCapture):
    print("DNS Servers:")
    for server in dns_servers_from_capture_v4(capture):
        print("\t - " + server)


def print_dns_servers_v6(capture: pyshark.FileCapture):
    print("DNS Servers:")
    for server in dns_servers_from_capture_v6(capture):
        print("\t - " + server)
