"""Tests for ipcalc: parsing, network math, hosts, split, overlap,
range summarization, edge cases, error handling, and CLI smoke tests."""

import json
import subprocess
import sys

import pytest

from ipcalc import (
    IpCalcError,
    Network,
    int_to_ip,
    ip_class,
    ip_to_int,
    is_private,
    mask_to_prefix,
    parse_prefix,
    prefix_to_mask,
    summarize_range,
    main,
)


# --- ip <-> int conversion -------------------------------------------------

def test_ip_to_int_zero():
    assert ip_to_int("0.0.0.0") == 0


def test_ip_to_int_max():
    assert ip_to_int("255.255.255.255") == 0xFFFFFFFF


def test_ip_to_int_known():
    assert ip_to_int("192.168.1.1") == 3232235777


def test_int_to_ip_roundtrip():
    for ip in ["0.0.0.0", "10.0.0.1", "172.16.254.3", "255.255.255.255"]:
        assert int_to_ip(ip_to_int(ip)) == ip


def test_ip_to_int_rejects_short():
    with pytest.raises(IpCalcError):
        ip_to_int("192.168.1")


def test_ip_to_int_rejects_five_octets():
    with pytest.raises(IpCalcError):
        ip_to_int("1.2.3.4.5")


def test_ip_to_int_rejects_octet_over_255():
    with pytest.raises(IpCalcError):
        ip_to_int("192.168.1.256")


def test_ip_to_int_rejects_non_numeric():
    with pytest.raises(IpCalcError):
        ip_to_int("192.168.one.1")


def test_ip_to_int_rejects_leading_zero():
    with pytest.raises(IpCalcError):
        ip_to_int("192.168.01.1")


def test_ip_to_int_rejects_empty():
    with pytest.raises(IpCalcError):
        ip_to_int("")


# --- prefix / mask ---------------------------------------------------------

def test_prefix_to_mask_24():
    assert prefix_to_mask(24) == ip_to_int("255.255.255.0")


def test_prefix_to_mask_0_and_32():
    assert prefix_to_mask(0) == 0
    assert prefix_to_mask(32) == 0xFFFFFFFF


def test_prefix_to_mask_rejects_33():
    with pytest.raises(IpCalcError):
        prefix_to_mask(33)


def test_prefix_to_mask_rejects_negative():
    with pytest.raises(IpCalcError):
        prefix_to_mask(-1)


def test_mask_to_prefix_dotted():
    assert mask_to_prefix("255.255.255.0") == 24
    assert mask_to_prefix("255.255.0.0") == 16
    assert mask_to_prefix("255.255.255.252") == 30


def test_mask_to_prefix_rejects_non_contiguous():
    with pytest.raises(IpCalcError):
        mask_to_prefix("255.0.255.0")


def test_parse_prefix_slash_and_plain():
    assert parse_prefix("/24") == 24
    assert parse_prefix("24") == 24
    assert parse_prefix("255.255.255.128") == 25


# --- parsing ---------------------------------------------------------------

def test_parse_cidr():
    net = Network.parse("192.168.1.0/24")
    assert net.network == "192.168.1.0"
    assert net.prefix == 24


def test_parse_dotted_netmask():
    net = Network.parse("10.0.0.0/255.0.0.0")
    assert net.prefix == 8
    assert net.netmask == "255.0.0.0"


def test_parse_bare_address_is_host():
    net = Network.parse("8.8.8.8")
    assert net.prefix == 32
    assert net.network == "8.8.8.8"


def test_parse_space_separated_prefix():
    net = Network.parse("192.168.1.0", "24")
    assert net.cidr == "192.168.1.0/24"


def test_parse_normalizes_host_bits():
    net = Network.parse("192.168.1.37/24")
    assert net.network == "192.168.1.0"
    assert net.host_bits_set is True


def test_parse_rejects_bad_address():
    with pytest.raises(IpCalcError):
        Network.parse("999.1.1.0/24")


def test_parse_rejects_bad_prefix():
    with pytest.raises(IpCalcError):
        Network.parse("192.168.1.0/33")


def test_parse_rejects_ipv6():
    with pytest.raises(IpCalcError):
        Network.parse("2001:db8::/32")


# --- network math ----------------------------------------------------------

def test_class_c_network_math():
    net = Network.parse("192.168.1.0/24")
    assert net.broadcast == "192.168.1.255"
    assert net.netmask == "255.255.255.0"
    assert net.wildcard == "0.0.0.255"
    assert net.first_host == "192.168.1.1"
    assert net.last_host == "192.168.1.254"
    assert net.total_addresses == 256
    assert net.usable_hosts == 254


def test_class_a_network_math():
    net = Network.parse("10.0.0.0/8")
    assert net.broadcast == "10.255.255.255"
    assert net.total_addresses == 16777216
    assert net.usable_hosts == 16777214
    assert net.first_host == "10.0.0.1"
    assert net.last_host == "10.255.255.254"


def test_slash_zero():
    net = Network.parse("0.0.0.0/0")
    assert net.broadcast == "255.255.255.255"
    assert net.total_addresses == 2 ** 32
    assert net.netmask == "0.0.0.0"


def test_slash_31_rfc3021():
    net = Network.parse("192.168.1.0/31")
    assert net.total_addresses == 2
    assert net.usable_hosts == 2
    assert net.first_host == "192.168.1.0"
    assert net.last_host == "192.168.1.1"


def test_slash_32_single_host():
    net = Network.parse("8.8.8.8/32")
    assert net.total_addresses == 1
    assert net.usable_hosts == 1
    assert net.first_host == "8.8.8.8"
    assert net.last_host == "8.8.8.8"
    assert net.broadcast == "8.8.8.8"


# --- class and private -----------------------------------------------------

def test_ip_class_boundaries():
    assert ip_class(ip_to_int("10.0.0.1")) == "A"
    assert ip_class(ip_to_int("172.16.0.1")) == "B"
    assert ip_class(ip_to_int("192.168.0.1")) == "C"
    assert ip_class(ip_to_int("224.0.0.1")) == "D"
    assert ip_class(ip_to_int("240.0.0.1")) == "E"


def test_is_private_rfc1918():
    assert is_private(ip_to_int("10.5.6.7")) is True
    assert is_private(ip_to_int("172.16.0.1")) is True
    assert is_private(ip_to_int("172.31.255.255")) is True
    assert is_private(ip_to_int("172.32.0.1")) is False
    assert is_private(ip_to_int("192.168.1.1")) is True


def test_is_private_special_ranges():
    assert is_private(ip_to_int("127.0.0.1")) is True
    assert is_private(ip_to_int("169.254.10.20")) is True
    assert is_private(ip_to_int("100.64.0.1")) is True


def test_is_public():
    assert is_private(ip_to_int("8.8.8.8")) is False
    assert is_private(ip_to_int("1.1.1.1")) is False


# --- membership and overlap -----------------------------------------------

def test_contains_inside_and_outside():
    net = Network.parse("192.168.1.0/24")
    assert net.contains("192.168.1.1") is True
    assert net.contains("192.168.1.255") is True  # broadcast is in range
    assert net.contains("192.168.2.1") is False


def test_overlaps_nested():
    assert Network.parse("10.0.0.0/8").overlaps("10.1.0.0/16") is True


def test_overlaps_adjacent_not_overlapping():
    assert Network.parse("192.168.0.0/24").overlaps("192.168.1.0/24") is False


def test_overlaps_identical():
    assert Network.parse("192.168.1.0/24").overlaps("192.168.1.0/24") is True


# --- split -----------------------------------------------------------------

def test_split_into_four():
    subnets = Network.parse("192.168.1.0/24").split(4)
    assert [s.cidr for s in subnets] == [
        "192.168.1.0/26",
        "192.168.1.64/26",
        "192.168.1.128/26",
        "192.168.1.192/26",
    ]


def test_split_into_two():
    subnets = Network.parse("10.0.0.0/8").split(2)
    assert [s.cidr for s in subnets] == ["10.0.0.0/9", "10.128.0.0/9"]


def test_split_one_is_identity():
    assert [s.cidr for s in Network.parse("192.168.1.0/24").split(1)] == [
        "192.168.1.0/24"
    ]


def test_split_rejects_non_power_of_two():
    with pytest.raises(IpCalcError):
        Network.parse("192.168.1.0/24").split(3)


def test_split_rejects_too_many():
    with pytest.raises(IpCalcError):
        Network.parse("192.168.1.0/31").split(4)


def test_split_covers_parent_exactly():
    parent = Network.parse("172.16.0.0/16")
    subnets = parent.split(8)
    assert subnets[0].network == "172.16.0.0"
    assert subnets[-1].broadcast == "172.16.255.255"
    assert sum(s.total_addresses for s in subnets) == parent.total_addresses


# --- summarize -------------------------------------------------------------

def test_summarize_aligned_block():
    assert [n.cidr for n in summarize_range("192.168.1.0", "192.168.1.255")] == [
        "192.168.1.0/24"
    ]


def test_summarize_single_host():
    assert [n.cidr for n in summarize_range("8.8.8.8", "8.8.8.8")] == [
        "8.8.8.8/32"
    ]


def test_summarize_two_adjacent_blocks():
    result = [n.cidr for n in summarize_range("192.168.0.0", "192.168.1.255")]
    assert result == ["192.168.0.0/23"]


def test_summarize_unaligned_range_is_exact():
    result = summarize_range("192.168.1.5", "192.168.1.20")
    covered = sum(n.total_addresses for n in result)
    assert covered == 16  # exactly the 16 addresses in the range
    assert result[0].network_int == ip_to_int("192.168.1.5")
    assert result[-1].broadcast_int == ip_to_int("192.168.1.20")


def test_summarize_rejects_reversed_range():
    with pytest.raises(IpCalcError):
        summarize_range("192.168.1.20", "192.168.1.5")


# --- info dict -------------------------------------------------------------

def test_info_dict_contents():
    info = Network.parse("192.168.1.0/24").info()
    assert info["network"] == "192.168.1.0/24"
    assert info["broadcast_address"] == "192.168.1.255"
    assert info["usable_hosts"] == 254
    assert info["ip_class"] == "C"
    assert info["private"] is True


# --- CLI -------------------------------------------------------------------

def run_cli(*argv):
    proc = subprocess.run(
        [sys.executable, "-m", "ipcalc", *argv],
        capture_output=True,
        text=True,
        cwd=str(__file__).rsplit("/", 2)[0],
    )
    return proc


def test_cli_basic_output():
    proc = run_cli("192.168.1.0/24")
    assert proc.returncode == 0
    assert "192.168.1.255" in proc.stdout
    assert "254" in proc.stdout


def test_cli_json_output():
    proc = run_cli("10.0.0.0/8", "--json")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["network"] == "10.0.0.0/8"
    assert data["usable_hosts"] == 16777214


def test_cli_split():
    proc = run_cli("192.168.1.0/24", "--split", "4")
    assert proc.returncode == 0
    assert "192.168.1.64/26" in proc.stdout


def test_cli_contains_yes_and_no():
    assert run_cli("192.168.1.0/24", "--contains", "192.168.1.5").returncode == 0
    out = run_cli("192.168.1.0/24", "--contains", "10.0.0.1").stdout
    assert "is NOT" in out


def test_cli_overlaps():
    out = run_cli("10.0.0.0/8", "--overlaps", "10.1.0.0/16").stdout
    assert "overlaps" in out


def test_cli_summarize():
    proc = run_cli("--summarize", "192.168.1.0", "192.168.1.255")
    assert proc.returncode == 0
    assert "192.168.1.0/24" in proc.stdout


def test_cli_invalid_input_exit_code_2():
    proc = run_cli("not-an-ip")
    assert proc.returncode == 2
    assert "error" in proc.stderr


def test_cli_missing_argument_exit_code_2():
    proc = run_cli()
    assert proc.returncode == 2


def test_cli_main_returns_2_on_bad_network():
    assert main(["300.1.1.0/24"]) == 2
