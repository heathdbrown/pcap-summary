# pcap-summary

[![PyPI - Version](https://img.shields.io/pypi/v/pcap-summary.svg)](https://pypi.org/project/pcap-summary)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pcap-summary.svg)](https://pypi.org/project/pcap-summary)

-----

**Table of Contents**

- [Overview](#overview)
- [Usage](#usage)
- [Installation](#installation)
- [License](#license)

## Overview

Pcap-summary cli analyzes packet captures with common filters to reduce reviewing time in analysis.

## Usage

- High Level information on the packet capture by default
```console
$pcap-summary http.cap
File Name: http.cap
Total Number of Packets: 43
```

- Full summary for all protocols detected to help drop into interesting areas
```console
$pcap-summary http.cap summary
File Name: http.cap
Total Number of Packets: 43
TCP Packets: 41
TCP Packets with Analysis Flags: 2
TCP Packets with Retransmissions: 1
TCP SYN Packets: 1
TCP SYN ACK Packets: 41
TCP SYN Non Zero ACK Packets: 1
TCP Connection Refused Packets: 0
TCP Data in Urgent Packets: 0
TCP Reset Packets: 0
TCP Urgent Bit Set Packets: 0
TCP Window Size ScaleFactor Packets: 32
TCP Buffer Full Packets: 0
HTTP Packets: 4
HTTP Packets with Put or POST: 0
HTTP Packets with exe, zip extensions: 0
HTTP Packets with content type: 0
HTTP Packets with redirects: 0
HTTP Packets with non standard ports: 0
HTTP Packets with NMAP User Agent: 0
No TLS Packets found
UDP Packets: 2
UDP Home Grown Packets: 0
DNS PTR Packets: 0
DNS Query Packets: 1
DNS Response Packets: 1
DNS High Answer Packets: 0
```

- Protocol specific deeper analysis

```console
$pcap-summary http.cap dns
File Name: http.cap
Total Number of Packets: 43
DNS request from 145.254.160.237 : pagead2.googlesyndication.com
DNS request from 145.253.2.203 : pagead2.googlesyndication.com
DNS Servers:
         - 145.253.2.203
```

## Installation

```console
pip install pcap-summary
```

## Development

- Make sure `hatch` is installed

```console
# hatch install
pipx install hatch

# Development shell
hatch shell
```

## License

`pcap-summary` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
