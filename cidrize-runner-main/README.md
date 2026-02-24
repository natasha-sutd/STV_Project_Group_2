# cidrize-runner 
IP address parsing for humans.

Cidrize takes IP address inputs that people tend to use in practice, validates them, and converts them to objects.

Intelligently parses IPv4/IPv6 addresses, CIDRs, ranges, and wildcard matches to attempt return a valid list of IP addresses.

The cidrize() function does all the work trying to parse IP addresses correctly. Find out more about the project [here](https://github.com/jathanism/cidrize/).

## Project structure
```markdown
cidrize-runner
├── bin
└── README.md
```
- **bin**: This directory contains the binary subject to run the fuzzer on.

## Input structure
The following materials describe the standard specifications for each supported format. Use them as a reference to understand what valid input should look like:
* `IPv4`: [RFC 6864](https://datatracker.ietf.org/doc/rfc6864/)
* `IPv6`: [RFC 2460](https://datatracker.ietf.org/doc/html/rfc2460)

Inputs in the below structure are accepted for the following formats:

* `192.0.2.18`
* `192.0.20.64/26`
* `192.0.2.80-192.0.2.85`
* `192.0.2.170-175`
* `192.0.2.8[0-5]`
* `192.0.2.[5678]`

## Output structure
<!-- The output format from the program. -->

Without bugs
```bash
$ cidrize-runner --func cidrize --ipstr 1.2.3.4
Running cidrize function with the arguments: ipstr: 1.2.3.4 strict: False raise-errors: False
Output: [IPNetwork('1.2.3.4/32')]
No bugs found. Skipping CSV creation
Final bug count: defaultdict(<class 'int'>, {})
Saved bug count report and tracebacks for the bugs encountered!
```

With bugs
```bash
$ cidrize-runner --func cidrize --ipstr '192.0.2.0 255.255.255.0' --raise-errors
Running cidrize function with the arguments: ipstr: 192.0.2.0 255.255.255.0 strict: False raise-errors: True
Syntax error caught for ipstr.
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "netaddr/ip/__init__.py", line 346, in __init__
  File "netaddr/strategy/ipv4.py", line 124, in str_to_int
netaddr.core.AddrFormatError: '192.0.2.0 255.255.255.0' is not a valid IPv4 address string!

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "netaddr/ip/__init__.py", line 1034, in __init__
  File "netaddr/ip/__init__.py", line 902, in parse_ip_network
  File "netaddr/ip/__init__.py", line 348, in __init__
netaddr.core.AddrFormatError: base address '192.0.2.0 255.255.255.0' is not IPv4

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "cidrize_runner_stv.py", line 247, in <module>
  File "buggy_cidrize/cidrize_stv.py", line 481, in cidrize
  File "netaddr/ip/__init__.py", line 1045, in __init__
netaddr.core.AddrFormatError: invalid IPNetwork 192.0.2.0 255.255.255.0
============================================================
Final bug count: defaultdict(<class 'int'>, {('syntactic', <class 'netaddr.core.AddrFormatError'>, 'invalid IPNetwork 192.0.2.0 255.255.255.0', 'netaddr/ip/__init__.py', 1045): 1})
Saved bug count report and tracebacks for the bugs encountered!
```

## Setup instructions
<!-- Make sure to have a chosen linux environment setup to run the binary scripts. You do not need to install any additional dependencies since the binary `onefile` file contains all the files required to run the code. -->
Use the respective binary script for your OS.

## Instructions to run
Run the binary file in the terminal as shown:
```bash 
$ cidrize-runner [-h] [--func FUNC] [--ipstr IPSTR] [--threshold THRESHOLD]
               [--verbose VERBOSE] [--strict] [--raise-errors]
```
Consult the documentation with the `--help` flag if you are in doubt.

## List of removed functions
* `dump`
