"""ipcalc - a subnet / CIDR calculator for IPv4.

Pure standard library, zero dependencies. Parses IPv4 addresses in CIDR
notation (192.168.1.0/24), with a dotted netmask (192.168.1.0/255.255.255.0)
or with a bare prefix (192.168.1.5 24), and reports network/broadcast
addresses, usable host range, host counts, IP class and private/public
status. It can also test membership and overlap, split a network into
equal subnets, and summarize an address range into the smallest set of
CIDR blocks.

IPv4 only. /31 networks follow RFC 3021 (both addresses usable, no
broadcast); /32 is a single host.
"""

import argparse
import json
import sys

__version__ = "1.0.0"

MAX_PREFIX = 32


class IpCalcError(ValueError):
    """Raised for any invalid address, prefix, or network specification."""


def ip_to_int(ip):
    """Convert a dotted-quad string to a 32-bit integer.

    Raises IpCalcError on any malformed input.
    """
    if not isinstance(ip, str):
        raise IpCalcError("IP address must be a string, got %r" % (ip,))
    ip = ip.strip()
    parts = ip.split(".")
    if len(parts) != 4:
        raise IpCalcError("invalid IPv4 address %r: expected four octets" % ip)
    value = 0
    for part in parts:
        if part == "":
            raise IpCalcError("invalid IPv4 address %r: empty octet" % ip)
        if len(part) > 1 and part.startswith("0"):
            raise IpCalcError(
                "invalid IPv4 address %r: leading zeros are not allowed" % ip
            )
        if not part.isdigit():
            raise IpCalcError(
                "invalid IPv4 address %r: octet %r is not numeric" % (ip, part)
            )
        octet = int(part)
        if octet > 255:
            raise IpCalcError(
                "invalid IPv4 address %r: octet %d out of range 0-255"
                % (ip, octet)
            )
        value = (value << 8) | octet
    return value


def int_to_ip(value):
    """Convert a 32-bit integer to a dotted-quad string."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise IpCalcError("integer %d out of IPv4 range" % value)
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def prefix_to_mask(prefix):
    """Convert a prefix length (0-32) to a 32-bit netmask integer."""
    if not isinstance(prefix, int) or isinstance(prefix, bool):
        raise IpCalcError("prefix length must be an integer, got %r" % (prefix,))
    if not 0 <= prefix <= MAX_PREFIX:
        raise IpCalcError("prefix length %d out of range 0-32" % prefix)
    if prefix == 0:
        return 0
    return (0xFFFFFFFF << (MAX_PREFIX - prefix)) & 0xFFFFFFFF


def mask_to_prefix(mask):
    """Convert a dotted netmask to a prefix length.

    Raises IpCalcError if the mask is not a run of 1s followed by 0s.
    """
    mask_int = ip_to_int(mask)
    if mask_int == 0:
        return 0
    # A valid mask is 2**32 - 2**(32 - prefix); check contiguity.
    inverted = (~mask_int) & 0xFFFFFFFF
    if inverted & (inverted + 1) != 0:
        raise IpCalcError("invalid netmask %r: bits are not contiguous" % mask)
    return bin(mask_int).count("1")


def parse_prefix(text):
    """Parse a prefix given as '/24', '24', or a dotted netmask."""
    text = text.strip()
    if text.startswith("/"):
        text = text[1:]
    if "." in text:
        return mask_to_prefix(text)
    if not text.isdigit():
        raise IpCalcError("invalid prefix %r" % text)
    prefix = int(text)
    if not 0 <= prefix <= MAX_PREFIX:
        raise IpCalcError("prefix length %d out of range 0-32" % prefix)
    return prefix


def ip_class(ip_int):
    """Return the class (A-E) of an IPv4 address integer."""
    first = (ip_int >> 24) & 0xFF
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D"
    return "E"


def is_private(ip_int):
    """Return True if the address is in a private / special-use range.

    Covers RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8),
    link-local (169.254/16) and CGNAT shared space (100.64/10).
    """
    private_ranges = [
        (ip_to_int("10.0.0.0"), 8),
        (ip_to_int("172.16.0.0"), 12),
        (ip_to_int("192.168.0.0"), 16),
        (ip_to_int("127.0.0.0"), 8),
        (ip_to_int("169.254.0.0"), 16),
        (ip_to_int("100.64.0.0"), 10),
    ]
    for base, prefix in private_ranges:
        mask = prefix_to_mask(prefix)
        if ip_int & mask == base & mask:
            return True
    return False


class Network:
    """An IPv4 network defined by an address and a prefix length."""

    def __init__(self, address, prefix):
        if isinstance(address, str):
            address = ip_to_int(address)
        if not 0 <= address <= 0xFFFFFFFF:
            raise IpCalcError("address out of IPv4 range")
        if not isinstance(prefix, int) or not 0 <= prefix <= MAX_PREFIX:
            raise IpCalcError("prefix length %r out of range 0-32" % (prefix,))
        self.prefix = prefix
        self.mask = prefix_to_mask(prefix)
        self.network_int = address & self.mask
        self.broadcast_int = self.network_int | (~self.mask & 0xFFFFFFFF)
        # True when the address given had host bits set.
        self.host_bits_set = address != self.network_int

    @classmethod
    def parse(cls, spec, prefix=None):
        """Parse a network specification.

        Accepts '192.168.1.0/24', '192.168.1.0/255.255.255.0',
        '192.168.1.0 24' (prefix as a second argument), or a bare
        address (treated as a /32 host). Host bits in the address are
        masked off; ``host_bits_set`` records that this happened.
        """
        if not isinstance(spec, str):
            raise IpCalcError("network specification must be a string")
        spec = spec.strip()
        if prefix is not None:
            if isinstance(prefix, str):
                prefix = parse_prefix(prefix)
            return cls(spec, prefix)
        if "/" in spec:
            addr_text, prefix_text = spec.split("/", 1)
            return cls(addr_text.strip(), parse_prefix(prefix_text.strip()))
        if " " in spec:
            addr_text, prefix_text = spec.rsplit(" ", 1)
            return cls(addr_text.strip(), parse_prefix(prefix_text.strip()))
        return cls(spec, MAX_PREFIX)

    @property
    def network(self):
        return int_to_ip(self.network_int)

    @property
    def broadcast(self):
        return int_to_ip(self.broadcast_int)

    @property
    def netmask(self):
        return int_to_ip(self.mask)

    @property
    def wildcard(self):
        return int_to_ip((~self.mask) & 0xFFFFFFFF)

    @property
    def total_addresses(self):
        return 1 << (MAX_PREFIX - self.prefix)

    @property
    def usable_hosts(self):
        """Usable host count. /31 has 2 (RFC 3021), /32 has 1."""
        if self.prefix >= 31:
            return self.total_addresses
        return self.total_addresses - 2

    @property
    def first_host(self):
        if self.prefix == 32:
            return self.network
        if self.prefix == 31:
            return self.network
        return int_to_ip(self.network_int + 1)

    @property
    def last_host(self):
        if self.prefix == 32:
            return self.network
        if self.prefix == 31:
            return self.broadcast
        return int_to_ip(self.broadcast_int - 1)

    @property
    def cidr(self):
        return "%s/%d" % (self.network, self.prefix)

    def contains(self, ip):
        """Return True if the given address (str or int) is in this network."""
        if isinstance(ip, str):
            ip = ip_to_int(ip)
        return self.network_int <= ip <= self.broadcast_int

    def overlaps(self, other):
        """Return True if this network shares any address with ``other``."""
        if isinstance(other, str):
            other = Network.parse(other)
        return (
            self.network_int <= other.broadcast_int
            and other.network_int <= self.broadcast_int
        )

    def split(self, count):
        """Split into ``count`` equal subnets (count must be a power of 2).

        Returns a list of Network objects in address order.
        """
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise IpCalcError("split count must be a positive integer")
        if count & (count - 1) != 0:
            raise IpCalcError(
                "split count %d is not a power of 2" % count
            )
        new_prefix = self.prefix + (count - 1).bit_length()
        if new_prefix > MAX_PREFIX:
            raise IpCalcError(
                "cannot split %s into %d subnets: prefix would exceed /32"
                % (self.cidr, count)
            )
        step = 1 << (MAX_PREFIX - new_prefix)
        return [
            Network(self.network_int + i * step, new_prefix)
            for i in range(count)
        ]

    def info(self):
        """Return a dict of every reported property for this network."""
        return {
            "network": self.cidr,
            "network_address": self.network,
            "broadcast_address": self.broadcast,
            "netmask": self.netmask,
            "wildcard_mask": self.wildcard,
            "prefix_length": self.prefix,
            "first_usable_host": self.first_host,
            "last_usable_host": self.last_host,
            "total_addresses": self.total_addresses,
            "usable_hosts": self.usable_hosts,
            "ip_class": ip_class(self.network_int),
            "private": is_private(self.network_int),
            "host_bits_set": self.host_bits_set,
        }


def summarize_range(first_ip, last_ip):
    """Summarize an inclusive address range into the smallest CIDR set.

    Returns a list of Network objects covering exactly [first_ip, last_ip].
    """
    start = ip_to_int(first_ip) if isinstance(first_ip, str) else first_ip
    end = ip_to_int(last_ip) if isinstance(last_ip, str) else last_ip
    if start > end:
        raise IpCalcError(
            "range start %s is after range end %s"
            % (int_to_ip(start), int_to_ip(end))
        )
    result = []
    current = start
    while current <= end:
        # Largest block aligned at current address.
        max_size = current & -current if current != 0 else 1 << 32
        remaining = end - current + 1
        size = min(max_size, 1 << (remaining.bit_length() - 1))
        prefix = MAX_PREFIX - (size.bit_length() - 1)
        result.append(Network(current, prefix))
        current += size
    return result


def _print_info(network, as_json):
    if as_json:
        print(json.dumps(network.info(), indent=2))
        return
    info = network.info()
    if info["host_bits_set"]:
        print(
            "note: host bits set, address normalized to %s" % info["network"]
        )
    rows = [
        ("Network", info["network"]),
        ("Network address", info["network_address"]),
        ("Broadcast address", info["broadcast_address"]),
        ("Netmask", "%s (/%d)" % (info["netmask"], info["prefix_length"])),
        ("Wildcard mask", info["wildcard_mask"]),
        ("First usable host", info["first_usable_host"]),
        ("Last usable host", info["last_usable_host"]),
        ("Total addresses", str(info["total_addresses"])),
        ("Usable hosts", str(info["usable_hosts"])),
        ("IP class", info["ip_class"]),
        ("Private", "yes" if info["private"] else "no"),
    ]
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        print("%-*s  %s" % (width, label, value))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ipcalc",
        description="Subnet / CIDR calculator for IPv4 (IPv4 only).",
    )
    parser.add_argument(
        "network",
        nargs="?",
        help="network to inspect, e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "prefix",
        nargs="?",
        help="optional prefix, e.g. 24 or 255.255.255.0",
    )
    parser.add_argument(
        "--split",
        type=int,
        metavar="N",
        help="split the network into N equal subnets (N must be a power of 2)",
    )
    parser.add_argument(
        "--contains",
        metavar="IP",
        help="check whether IP belongs to the given network",
    )
    parser.add_argument(
        "--overlaps",
        metavar="NETWORK",
        help="check whether NETWORK overlaps the given network",
    )
    parser.add_argument(
        "--summarize",
        nargs=2,
        metavar=("FIRST", "LAST"),
        help="summarize an inclusive address range into CIDR blocks",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of human-readable text",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ipcalc %s" % __version__,
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.summarize:
            networks = summarize_range(args.summarize[0], args.summarize[1])
            if args.json:
                print(json.dumps([n.cidr for n in networks], indent=2))
            else:
                for network in networks:
                    print(network.cidr)
            return 0

        if args.network is None:
            build_parser().print_usage(sys.stderr)
            print(
                "ipcalc: error: a network is required "
                "(e.g. ipcalc 192.168.1.0/24)",
                file=sys.stderr,
            )
            return 2

        network = Network.parse(args.network, args.prefix)

        if args.contains is not None:
            result = network.contains(args.contains)
            if args.json:
                print(json.dumps({
                    "ip": args.contains,
                    "network": network.cidr,
                    "contains": result,
                }, indent=2))
            else:
                print(
                    "%s %s in %s"
                    % (
                        args.contains,
                        "is" if result else "is NOT",
                        network.cidr,
                    )
                )
            return 0

        if args.overlaps is not None:
            other = Network.parse(args.overlaps)
            result = network.overlaps(other)
            if args.json:
                print(json.dumps({
                    "network": network.cidr,
                    "other": other.cidr,
                    "overlaps": result,
                }, indent=2))
            else:
                print(
                    "%s %s %s"
                    % (
                        network.cidr,
                        "overlaps" if result else "does NOT overlap",
                        other.cidr,
                    )
                )
            return 0

        if args.split is not None:
            subnets = network.split(args.split)
            if args.json:
                print(json.dumps([n.cidr for n in subnets], indent=2))
            else:
                for subnet in subnets:
                    print(
                        "%s  %s - %s"
                        % (subnet.cidr, subnet.first_host, subnet.last_host)
                    )
            return 0

        _print_info(network, args.json)
        return 0
    except IpCalcError as exc:
        print("ipcalc: error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
