# SPDX-FileCopyrightText: 2022-present Heath Brown <heathd.brown@gmail.com>
#
# SPDX-License-Identifier: MIT
# CLI to analyze packet captures via pyshark and produce summaries with common filters
import click
import pyshark
import pcap_summary as ps

from ..__about__ import __version__


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(version=__version__, prog_name="pcap-summary")
@click.pass_context
@click.argument("file", required=True)
def pcap_summary(ctx: click.Context, file):
    """Print name and total number of packets for capture file"""
    # click.echo(file)
    ctx.ensure_object(dict)
    ctx.obj["file"] = file
    cap = pyshark.FileCapture(file)
    cap.load_packets()
    print(f"File Name: {cap.input_filepath}")
    print(f"Total Number of Packets: {len(cap)}")


@pcap_summary.command()
@click.pass_context
def dns(ctx):
    file = ctx.obj["file"]
    filtered_dns = ps.pyshark_filtered_capture(file, ps.BASIC_DNS)
    filtered_dns.load_packets()

    if len(filtered_dns) > 0:

        filtered_ipv6 = ps.pyshark_filtered_capture(file, ps.BASIC_IPV6)
        filtered_ipv6.load_packets()

        if len(filtered_ipv6) > 0:
            filtered_dns_ipv6 = ps.pyshark_filtered_capture(file, ps.DNS_IPV6)
            filtered_dns_ipv6.apply_on_packets(ps.print_dns_info_v6)

            filtered_dns_response_ipv6 = ps.pyshark_filtered_capture(
                file, ps.DNS_RESPONSE_IPV6
            )
            ps.print_dns_servers_v6(filtered_dns_response_ipv6)
        else:
            filtered_dns_ipv4 = ps.pyshark_filtered_capture(file, ps.DNS_IPV4)
            filtered_dns_ipv4.apply_on_packets(ps.print_dns_info_v4)

            filtered_dns_response = ps.pyshark_filtered_capture(file, ps.DNS_RESPONSE)
            ps.print_dns_servers_v4(filtered_dns_response)
    else:
        print("No DNS packets found")


@pcap_summary.command()
@click.pass_context
def summary(ctx):
    """Give a summary of protocols to view which area to review in the capture"""
    file = ctx.obj["file"]
    filtered_tcp = ps.pyshark_filtered_capture(file, ps.BASIC_TCP)
    filtered_tcp.load_packets()

    filtered_http = ps.pyshark_filtered_capture(file, ps.BASIC_HTTP)
    filtered_http.load_packets()

    if len(filtered_tcp) > 0:
        print(f"TCP Packets: {len(filtered_tcp)}")

        filtered_tcp_analysis_flag = ps.pyshark_filtered_capture(
            file, ps.TCP_ANALYSIS_FLAGS
        )
        filtered_tcp_analysis_flag.load_packets()
        print(f"TCP Packets with Analysis Flags: {len(filtered_tcp_analysis_flag)}")

        filtered_tcp_analysis_retransmissions = ps.pyshark_filtered_capture(
            file, ps.TCP_RETRANSMISSION
        )
        filtered_tcp_analysis_retransmissions.load_packets()
        print(
            f"TCP Packets with Retransmissions: {len(filtered_tcp_analysis_retransmissions)}"
        )

        filtered_syn = ps.pyshark_filtered_capture(file, ps.TCP_SYN)
        filtered_syn.load_packets()
        print(f"TCP SYN Packets: {len(filtered_syn)}")

        filtered_syn_ack = ps.pyshark_filtered_capture(file, ps.TCP_SYN_ACK)
        filtered_syn_ack.load_packets()
        print(f"TCP SYN ACK Packets: {len(filtered_syn_ack)}")

        filtered_syn_non_zero_ack = ps.pyshark_filtered_capture(
            file, ps.TCP_SYN_NON_ZERO_ACK
        )
        filtered_syn_non_zero_ack.load_packets()
        print(f"TCP SYN Non Zero ACK Packets: {len(filtered_syn_non_zero_ack)}")

        filtered_conn_refusal = ps.pyshark_filtered_capture(file, ps.TCP_CONN_REFUSAL)
        filtered_conn_refusal.load_packets()
        print(f"TCP Connection Refused Packets: {len(filtered_conn_refusal)}")

        filtered_data_in_urgent = ps.pyshark_filtered_capture(
            file, ps.TCP_DATA_IN_URGET
        )
        filtered_data_in_urgent.load_packets()
        print(f"TCP Data in Urgent Packets: {len(filtered_data_in_urgent)}")

        filtered_resets = ps.pyshark_filtered_capture(file, ps.TCP_RESETS)
        filtered_resets.load_packets()
        print(f"TCP Reset Packets: {len(filtered_resets)}")

        filtered_urgent_bit_set = ps.pyshark_filtered_capture(
            file, ps.TCP_URGENT_BIT_SET
        )
        filtered_urgent_bit_set.load_packets()
        print(f"TCP Urgent Bit Set Packets: {len(filtered_urgent_bit_set)}")

        filtered_window_size_scalefactor = ps.pyshark_filtered_capture(
            file, ps.TCP_WINDOW_SIZE_SCALEFACTOR
        )
        filtered_window_size_scalefactor.load_packets()
        print(
            f"TCP Window Size ScaleFactor Packets: {len(filtered_window_size_scalefactor)}"
        )

        filtered_buff_full = ps.pyshark_filtered_capture(file, ps.TCP_BUFFER_FULL)
        filtered_buff_full.load_packets()
        print(f"TCP Buffer Full Packets: {len(filtered_buff_full)}")

        if len(filtered_http) > 0:
            print(f"HTTP Packets: {len(filtered_http)}")

            filtered_http_put_post = ps.pyshark_filtered_capture(file, ps.HTTP_PUT_POST)
            filtered_http_put_post.load_packets()
            print(f"HTTP Packets with Put or POST: {len(filtered_http_put_post)}")

            filtered_file_extension = ps.pyshark_filtered_capture(
                file, ps.HTTP_FILE_EXTENSION
            )
            filtered_file_extension.load_packets()
            print(
                f"HTTP Packets with exe, zip extensions: {len(filtered_file_extension)}"
            )

            filtered_content_type = ps.pyshark_filtered_capture(
                file, ps.HTTP_CONTENT_TYPE
            )
            filtered_content_type.load_packets()
            print(f"HTTP Packets with content type: {len(filtered_content_type)}")

            filtered_redirects = ps.pyshark_filtered_capture(file, ps.HTTP_REDIRECTS)
            filtered_redirects.load_packets()
            print(f"HTTP Packets with redirects: {len(filtered_redirects)}")

            filtered_http_get_not_on_80 = ps.pyshark_filtered_capture(
                file, ps.HTTP_GET_NOT_ON_80
            )
            filtered_http_get_not_on_80.load_packets()
            print(
                f"HTTP Packets with non standard ports: {len(filtered_http_get_not_on_80)}"
            )

            filtered_nmap_user_agent = ps.pyshark_filtered_capture(
                file, ps.NMAP_USER_AGENT
            )
            filtered_nmap_user_agent.load_packets()
            print(f"HTTP Packets with NMAP User Agent: {len(filtered_nmap_user_agent)}")

        else:
            print("No HTTP Packets")

        filtered_tls = ps.pyshark_filtered_capture(file, ps.BASIC_TLS)
        filtered_tls.load_packets()
        if len(filtered_tls) > 0:
            print(f"TLS Packets: {len(filtered_tls)}")

            filtered_tls_handshake = ps.pyshark_filtered_capture(
                file, ps.BASIC_TLS_HANDSHAKE
            )
            filtered_tls_handshake.load_packets()
            print(f"TLS Handshake Packets: {len(filtered_tls_handshake)}")

            filtered_tls_client_hello = ps.pyshark_filtered_capture(
                file, ps.TLS_CLIENT_HELLO
            )
            filtered_tls_client_hello.load_packets()
            print(f"TLS Client Hello Packets: {len(filtered_tls_client_hello)}")

            filtered_tls_server_hello = ps.pyshark_filtered_capture(
                file, ps.TLS_SERVER_HELLO
            )
            filtered_tls_server_hello.load_packets()
            print(f"TLS Server Hello Packets: {len(filtered_tls_server_hello)}")

            filtered_encrypted_alert = ps.pyshark_filtered_capture(
                file, ps.TLS_ENCRYPTED_ALERT
            )
            filtered_encrypted_alert.load_packets()
            print(f"TLS Encrypted Alert Packets: {len(filtered_encrypted_alert)}")
        else:
            print("No TLS Packets found")
    else:
        print("No TCP Packets")

    filtered_udp = ps.pyshark_filtered_capture(file, ps.BASIC_UDP)
    filtered_udp.load_packets()
    if len(filtered_udp) > 0:
        print(f"UDP Packets: {len(filtered_udp)}")

        filtered_udp_home_grown = ps.pyshark_filtered_capture(file, ps.UDP_HOME_GROWN)
        filtered_udp_home_grown.load_packets()
        print(f"UDP Home Grown Packets: {len(filtered_udp_home_grown)}")

        filtered_dns = ps.pyshark_filtered_capture(file, ps.BASIC_DNS)
        filtered_dns.load_packets()
        if len(filtered_dns) > 0:
            filtered_dns_ptr = ps.pyshark_filtered_capture(file, ps.DNS_PTR)
            filtered_dns_ptr.load_packets()
            print(f"DNS PTR Packets: {len(filtered_dns_ptr)}")

            filtered_dns_query = ps.pyshark_filtered_capture(file, ps.DNS_QUERY)
            filtered_dns_query.load_packets()
            print(f"DNS Query Packets: {len(filtered_dns_query)}")

            filtered_dns_response = ps.pyshark_filtered_capture(file, ps.DNS_RESPONSE)
            filtered_dns_response.load_packets()
            print(f"DNS Response Packets: {len(filtered_dns_response)}")

            filtered_dns_high_answer = ps.pyshark_filtered_capture(
                file, ps.DNS_HIGH_ANSWER
            )
            filtered_dns_high_answer.load_packets()
            print(f"DNS High Answer Packets: {len(filtered_dns_high_answer)}")

    else:
        print("No UDP Packets")


if __name__ == "__main__":
    # click allows for passing a context object, we need to pass an object that is a blank dict
    pcap_summary(obj={})
