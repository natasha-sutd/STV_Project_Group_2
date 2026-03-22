# -*- coding: utf-8 -*-
"""
Initial seed generation for IPv4 and IPv6 targets.

Seeds are organised into categories:
  - valid   : inputs the parser should accept (exercises the happy path)
  - boundary: edge cases at the limits of the grammar (0, 255, etc.)
  - invalid  : inputs the parser should reject (exercises error handling)

These are used to initialise the corpus before mutation begins.
"""

from typing import List
from corpus import Seed


# ---------------------------------------------------------------------------
# IPv4 seeds
# ---------------------------------------------------------------------------

def ipv4_seeds() -> List[Seed]:
    """
    Return ~60 IPv4 seeds covering:
      - standard valid addresses
      - boundary octets (0, 1, 127, 128, 254, 255)
      - leading-zero forms
      - loopback / private / broadcast ranges
      - known-invalid: octet > 255, wrong group count, wrong separators
    """
    valid = [
        # Standard
        "0.0.0.0", "1.2.3.4", "9.10.99.100",
        "127.0.0.1", "192.168.1.1", "192.168.0.0",
        "10.0.0.1", "172.16.0.1", "255.255.255.255",
        # Boundary octets
        "0.0.0.1", "0.0.1.0", "0.1.0.0", "1.0.0.0",
        "254.254.254.254", "255.0.0.0", "0.0.0.255",
        # Leading zeros
        "00.01.002.000", "09.10.099.100",
        "001.002.003.004", "127.000.000.001",
        "192.168.001.001", "249.250.251.252",
        # Min/max per RFC
        "0.0.0.0", "255.255.255.255",
    ]
    invalid = [
        # Octet > 255
        "256.0.0.0", "0.256.0.0", "0.0.256.0", "0.0.0.256",
        "300.1.2.3", "1.300.2.3", "1.2.300.3", "1.2.3.300",
        "999.999.999.999",
        # Wrong group count
        "1.2.3", "1.2", "1", "1.2.3.4.5",
        # Wrong separators
        "1,2,3,4", "1:2:3:4", "1/2/3/4",
        # Extra spaces
        "1.2.3.4 ", " 1.2.3.4",
        "1.2.3. 4",
        # Non-numeric
        "a.b.c.d", "1.2.3.x",
        # Empty
        "", ".",
        # Very large numbers (5+ digits)
        "12345.1.2.3", "1.2.3.12345",
        # Mixed case hex (not valid IPv4)
        "ff.ff.ff.ff",
    ]
    seeds = []
    for v in valid:
        seeds.append(Seed(data=v.encode(), energy=2.0, origin="ipv4_valid"))
    for inv in invalid:
        seeds.append(Seed(data=inv.encode(), energy=1.5, origin="ipv4_invalid"))
    return seeds


# ---------------------------------------------------------------------------
# IPv6 seeds
# ---------------------------------------------------------------------------

def ipv6_seeds() -> List[Seed]:
    """
    Return ~90 IPv6 seeds drawn from:
      - All RFC 2460 address forms
      - Known boundary patterns (all-zeros, all-ones, loopback)
      - Known-invalid patterns (too many groups, double '::' etc.)
      - Mixed IPv4-in-IPv6 forms
      - Case variants
    """
    valid = [
        # Full 8-group
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8:85a3:0:0:8a2e:370:7334",
        "2001:0000:1234:0000:0000:C1C0:ABCD:0876",
        "0000:0000:0000:0000:0000:0000:0000:0001",
        "0000:0000:0000:0000:0000:0000:0000:0000",
        "1:2:3:4:5:6:7:8",
        "FF02:0000:0000:0000:0000:0000:0000:0001",
        "3ffe:0b00:0000:0000:0001:0000:0000:000a",
        # :: compressed
        "::1", "::2:3:4:5:6:7:8",
        "2001:db8::", "2001::",
        "fe80::", "fc00::", "ff02::1",
        "2002::", "2001:10::",
        "1::", "1:2::", "1:2:3::", "1:2:3:4::",
        # :: on right
        "1:2:3:4:5:6::",
        "1:2:3:4:5::",
        # :: in middle
        "2001:0db8::1428:57ab",
        "2001:0db8:0:0::1428:57ab",
        "2001:DB8::8:800:200C:417A",
        "FF01::101",
        # IPv4-in-IPv6 suffix
        "::127.0.0.1",
        "::ffff:192.168.1.1",
        "::ffff:0:0",
        "::13.1.68.3",
        "::FFFF:129.144.52.38",
        "fe80::217:f2ff:254.7.237.98",
        "2001:db8::192.0.2.33",
        "1:2:3:4:5:6:1.2.3.4",
        "1:2:3:4::1.2.3.4",
        "::ffff:192.0.2.128",
        # Case variants
        "fe80:0000:0000:0000:0204:61ff:fe9d:f156",
        "FE80::204:61FF:FE9D:F156",
        "2001:DB8:0:0:8:800:200C:417A",
        # Special ranges
        "::ffff:0c22:384e",
        "2001:0db8:1234:ffff:ffff:ffff:ffff:ffff",
        "fc00::",
        "2001:db8:a::123",
    ]
    invalid = [
        # Plain IPv4 (should fail IPv6 parser)
        "127.0.0.1", "192.168.1.1", "1.2.3.4",
        # Wrong group count
        "3ffe:0b00:0000:0001:0000:0000:000a",           # only 7 groups
        "FF02:0000:0000:0000:0000:0000:0000:0000:0001",  # 9 groups
        "1:2:3:4:5:6:7:8:9",
        "2001:DB8:0:0:8:800:200C:417A:221FF01::101::2",
        # Double '::' 
        "3ffe:b00::1::a",
        "::1111:2222:3333:4444:5555:6666::",
        "1:2:3::4:5::7:8",
        "2001::FFD3::57ab",
        "1::2::3",
        "FF01::101::2",
        # Bare '::'
        "::",
        # Leading/trailing colon
        "1111:2222:3333:4444::5555:",
        ":1111:2222:3333:4444::5555",
        "1111:",
        ":",
        ":::",
        # Octet > 255 in IPv4 suffix
        "1::5:256.2.3.4",
        "1::5:1.256.3.4",
        "::1.2.3.256",
        "::300.2.3.4",
        "::1.300.3.4",
        # Group > 4 hex digits
        "02001:0000:1234:0000:0000:C1C0:ABCD:0876",
        "2001:0000:1234:0000:00001:C1C0:ABCD:0876",
        "12345::6:7:8",
        "2001:db8:85a3::8a2e:37023:7334",
        # Non-hex chars
        "2001:db8:85a3::8a2e:370k:7334",
        "ldkfj",
        "123",
        # Trailing/leading space
        "2001:0000:1234:0000:0000:C1C0:ABCD:0876 0",
        "2001:0000:1234: 0000:0000:C1C0:ABCD:0876",
        # IPv4 that starts the string
        "1.2.3.4:1111:2222:3333:4444::5555",
        "1.2.3.4::",
        # Incomplete IPv4 suffix
        "::ffff:2.3.4",
        "::ffff:257.1.2.3",
    ]
    seeds = []
    for v in valid:
        seeds.append(Seed(data=v.encode(), energy=2.0, origin="ipv6_valid"))
    for inv in invalid:
        seeds.append(Seed(data=inv.encode(), energy=1.5, origin="ipv6_invalid"))
    return seeds


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_seeds(target: str) -> List[Seed]:
    """Return the initial seed list for a given target."""
    if target == "ipv4":
        return ipv4_seeds()
    elif target == "ipv6":
        return ipv6_seeds()
    else:
        raise ValueError(f"Unknown target '{target}'. Choose 'ipv4' or 'ipv6'.")
