# ipcalc

A subnet / CIDR calculator for IPv4. Pure Python, standard library only — zero dependencies.

Parse an address in CIDR notation, with a dotted netmask, or with a bare prefix, and get the network and broadcast addresses, usable host range, host counts, wildcard mask, IP class, and private/public status. It can also test membership and overlap, split a network into equal subnets, and summarize an address range into the smallest set of CIDR blocks.

IPv4 only.

## Install

Requires Python 3.8 or newer. No dependencies to install.

```bash
git clone https://github.com/ujjwalbhatiaa/ipcalc.git
cd ipcalc
```

Run it directly — no build step:

```bash
python3 ipcalc.py 192.168.1.0/24
```

## Usage

### Inspect a network

```bash
$ python3 ipcalc.py 192.168.1.0/24
Network            192.168.1.0/24
Network address    192.168.1.0
Broadcast address  192.168.1.255
Netmask            255.255.255.0 (/24)
Wildcard mask      0.0.0.255
First usable host  192.168.1.1
Last usable host   192.168.1.254
Total addresses    256
Usable hosts       254
IP class           C
Private            yes
```

Any of these forms work for the same network:

```bash
python3 ipcalc.py 192.168.1.0/24
python3 ipcalc.py 192.168.1.0/255.255.255.0
python3 ipcalc.py 192.168.1.0 24
python3 ipcalc.py 192.168.1.37/24   # host bits set: normalized to 192.168.1.0/24
```

A bare address is treated as a `/32` host:

```bash
$ python3 ipcalc.py 8.8.8.8
Network              8.8.8.8/32
Total addresses      1
Usable hosts         1
IP class             A
Private              no
```

### Machine-readable output

```bash
$ python3 ipcalc.py 10.0.0.0/8 --json
{
  "network": "10.0.0.0/8",
  "network_address": "10.0.0.0",
  "broadcast_address": "10.255.255.255",
  "netmask": "255.0.0.0",
  "wildcard_mask": "0.255.255.255",
  "prefix_length": 8,
  "first_usable_host": "10.0.0.1",
  "last_usable_host": "10.255.255.254",
  "total_addresses": 16777216,
  "usable_hosts": 16777214,
  "ip_class": "A",
  "private": true,
  "host_bits_set": false
}
```

### Split a network into equal subnets

```bash
$ python3 ipcalc.py 192.168.1.0/24 --split 4
192.168.1.0/26    192.168.1.1 - 192.168.1.62
192.168.1.64/26   192.168.1.65 - 192.168.1.126
192.168.1.128/26  192.168.1.129 - 192.168.1.190
192.168.1.192/26  192.168.1.193 - 192.168.1.254
```

The count must be a power of 2.

### Membership and overlap

```bash
$ python3 ipcalc.py 192.168.1.0/24 --contains 192.168.1.5
192.168.1.5 is in 192.168.1.0/24

$ python3 ipcalc.py 10.0.0.0/8 --overlaps 10.1.0.0/16
10.0.0.0/8 overlaps 10.1.0.0/16
```

### Summarize a range into CIDR blocks

```bash
$ python3 ipcalc.py --summarize 192.168.1.5 192.168.1.20
192.168.1.5/32
192.168.1.6/31
192.168.1.8/29
192.168.1.16/30
192.168.1.20/32
```

## Edge cases

- **`/31` networks** follow RFC 3021: both addresses are usable, there is no broadcast address to exclude, so a `/31` reports 2 usable hosts.
- **`/32`** is a single host: 1 total address, 1 usable host, first = last = the address itself.
- **`/0`** covers the whole IPv4 space: 4,294,967,296 addresses.
- **Invalid input** (bad octets, prefix outside 0–32, non-contiguous netmask, IPv6 addresses) prints a clear error to stderr and exits with code 2.
- Leading zeros in octets (e.g. `192.168.01.1`) are rejected, since they are ambiguous with octal.

## Using it as a library

```python
from ipcalc import Network, summarize_range

net = Network.parse("192.168.1.0/24")
net.broadcast          # '192.168.1.255'
net.usable_hosts       # 254
net.contains("192.168.1.42")   # True
net.overlaps("192.168.2.0/24") # False
net.split(4)           # [Network('192.168.1.0/26'), ...]

summarize_range("10.0.0.5", "10.0.0.20")  # smallest CIDR list for the range
```

## Tests

```bash
python3 -m pytest tests/ -v
```

## License

MIT — see [LICENSE](LICENSE).
