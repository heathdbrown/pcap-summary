# SPDX-FileCopyrightText: 2022-present Heath Brown <heathd.brown@gmail.com>
#
# SPDX-License-Identifier: MIT
import sys

if __name__ == "__main__":
    from .cli import pcap_summary

    sys.exit(pcap_summary())
