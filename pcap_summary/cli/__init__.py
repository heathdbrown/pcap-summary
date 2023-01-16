# SPDX-FileCopyrightText: 2022-present Heath Brown <heathd.brown@gmail.com>
#
# SPDX-License-Identifier: MIT
""" CLI to analyze packet captures via pyshark and produce summaries with common filters """
import logging

logger = logging.getLogger(__name__)
# stream_handler = logging.StreamHandler()
# logger.addHandler(stream_handler)

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
@click.option("-v", "--verbose", count=True)
def pcap_summary(ctx: click.Context, file, verbose):
    """Print name and total number of packets for capture file"""
    # click.echo(file)
    ctx.ensure_object(dict)
    ctx.obj["file"] = file
    cap = pyshark.FileCapture(file)
    cap.load_packets()

    if not verbose:
        log_level = "info"
    if verbose == 1:
        log_level = "info"
    if verbose >= 2:
        log_level = "debug"
    # logger.setLevel(log_level.upper())
    logging.basicConfig(
        format="%(asctime)-15s:%(levelname)s:%(name)s:%(message)s",
        level=log_level.upper(),
    )
    logger.info(f"File Name: {cap.input_filepath}")
    logger.info(f"Total Number of Packets: {len(cap)}")


@pcap_summary.command()
@click.pass_context
def dns(ctx):
    """Print DNS information from packet capture"""
    file = ctx.obj["file"]
    ps.report.dns_analysis(file, summary=False)


@pcap_summary.command()
@click.pass_context
def tcp(ctx):
    """Give a detail report on the tcp protocol"""
    file = ctx.obj["file"]
    ps.report.tcp_analysis(file, summary=False)


@pcap_summary.command()
@click.pass_context
def udp(ctx):
    """Give a detail report on the udp protocol"""
    file = ctx.obj["file"]
    ps.report.udp_analysis(file, summary=False)


if __name__ == "__main__":
    # click allows for passing a context object, we need to pass an object that is a blank dict
    pcap_summary(obj={})
