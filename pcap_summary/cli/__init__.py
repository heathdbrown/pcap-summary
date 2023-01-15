# SPDX-FileCopyrightText: 2022-present Heath Brown <heathd.brown@gmail.com>
#
# SPDX-License-Identifier: MIT
""" CLI to analyze packet captures via pyshark and produce summaries with common filters """
import logging

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
    """Print DNS information from packet capture"""
    file = ctx.obj["file"]
    ps.dns_analysis(file, summary=False)


@pcap_summary.command()
@click.pass_context
def summary(ctx):
    """Give a summary of protocols to view which area to review in the capture"""
    file = ctx.obj["file"]
    ps.tcp_analysis(file)
    ps.udp_analysis(file)


if __name__ == "__main__":
    # click allows for passing a context object, we need to pass an object that is a blank dict
    pcap_summary(obj={})
