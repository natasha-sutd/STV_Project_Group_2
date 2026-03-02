# IPv4-IPv6-parser
Converts an IPv4/IPv6 address to a 32-bit/128-bit integer. Check out the original source code [here](https://github.com/jcollie/ipyparse/tree/master).

## Project structure
```markdown
IPv4-IPv6-parser
├── bin
└── README.md
```
- **bin**: This directory contains the binary subject to run the fuzzer on.

## Input structure
The following materials describe the standard specifications for each supported format. Use them as a reference to understand what valid input should look like:
* `IPv4`: [RFC 6864](https://datatracker.ietf.org/doc/rfc6864/)
* `IPv6`: [RFC 2460](https://datatracker.ietf.org/doc/html/rfc2460)

Inputs in the below structure are accepted for the following formats:

### IPv4 allowed inputs
* `0.0.0.0`
* `00.01.002.000`
* `1.2.3.4`
* `09.10.99.100`
* `127.0.0.1`
* `192.168.001.001`
* `249.250.251.252`
* `255.255.255.255`

### IPv6 allowed inputs:
* `2001:0db8:0000:0000:0000:ff00:0042:8329`
* `2001:db8:0:0:0:0:192.0.2.33`
* `2001:db8::`
* `2001:db8::1`
* `2001:db8::192.0.2.33`
* `2001:db8::1:2`
* `2001:db8::1:192.0.2.33`
* `2001:db8::1:2:3`
* `2001:db8::1:2:192.0.2.33`
* `2001:db8::1:2:3:4`
* `2001:db8::1:2:3:192.0.2.33`
* `2001:db8::1:2:3:4:5`
* `2001::1:2:3:4:5:6`
* `::192.0.2.33`

## Output structure
<!-- The output format from the program. -->

### IPv4-parser output

Without bugs
```bash
$ ipv4-parser --ipstr 192.166.1.1
Running the IPv4 parser with ipstr: 192.166.1.1
Output: [3232104705]
No bugs found. Skipping CSV creation
Saved bug count report and tracebacks for the bugs encountered!
Final bug count: defaultdict(<class 'int'>, {})
```

With bugs
```bash
$ ipv4-parser --ipstr 192.123249324.3242334.2343
Running the IPv4 parser with ipstr: 192.123249324.3242334.2343
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "ipv4_parser_stv.py", line 220, in <module>
  File "pyparsing/core.py", line 1340, in parse_string
pyparsing.exceptions.ParseException: Expected '.', found '249324'  (at char 7), (line:1, col:8)
============================================================
Saved bug count report and tracebacks for the bugs encountered!
Final bug count: defaultdict(<class 'int'>, {('invalidity', <class 'pyparsing.exceptions.ParseException'>, "Expected '.', found '249324'  (at char 7), (line:1, col:8)", 'pyparsing/core.py', 1340): 1})
```

### IPv6 parser output:

Without bugs
```bash
$ ipv6-parser --ipstr 2001:db8::1:2:3:192.0.2.33
Running the IPv6 parser with ipstr: 2001:db8::1:2:3:192.0.2.33
Output: [42540766411282592875351291991422927393]
No bugs found. Skipping CSV creation
Saved bug count report and tracebacks for the bugs encountered!
Final bug count: defaultdict(<class 'int'>, {})
```

With bugs
```bash
$ ipv6-parser --ipstr 2001:db8::0222:2jkf:2333
Running the IPv6 parser with ipstr: 2001:db8::0222:2jkf:2333
An unknown exception has been triggered. Expected end of text, found 'jkf'  (at char 16), (line:1, col:17)
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "ipv6_parser_stv.py", line 219, in <module>
  File "pyparsing/core.py", line 1340, in parse_string
pyparsing.exceptions.ParseException: Expected end of text, found 'jkf'  (at char 16), (line:1, col:17)
============================================================
Saved bug count report and tracebacks for the bugs encountered!
Final bug count: defaultdict(<class 'int'>, {('bonus', <class 'pyparsing.exceptions.ParseException'>, "Expected end of text, found 'jkf'  (at char 16), (line:1, col:17)", 'pyparsing/core.py', 1340): 1})
```
## Setup instructions
<!-- Make sure to have a chosen linux environment setup to run the binary scripts. -->
Use the respective binary script for your OS.

## Instructions to run
Run the binary file in the terminal as shown:
```bash
$ ipv4-parser [-h] [--ipstr IPSTR]
```
OR
```bash
$ ipv6-parser [-h] [--ipstr IPSTR]
```
Consult the documentation with the `--help` flag if you are in doubt.

## List of removed functions
No functions were removed from the original source code.
