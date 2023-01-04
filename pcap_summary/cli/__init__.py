# SPDX-FileCopyrightText: 2022-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
import click
import pyshark

from ..__about__ import __version__


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=True,
)
@click.version_option(version=__version__, prog_name="pcap-summary")
@click.pass_context
@click.argument("file", required=True)
def pcap_summary(ctx: click.Context, file):
    # click.echo(file)
    cap = pyshark.FileCapture(file)
    cap.load_packets()
    print(cap.input_filepath)
    print(len(cap))

    for packet in cap:
        print(packet.number)
        for layer in packet.layers:
            print(layer.layer_name)
            print(layer.field_names)
            try:
                print(layer.get_field("src"))
            except NotImplementedError as e:
                print(f"{e} layer does not contain field")
