import sys
import coverage
from io import StringIO
import re


def main():
    if len(sys.argv) < 2:
        return

    ip_to_test = sys.argv[1]

    cov = coverage.Coverage(
        data_file=".coverage_ipv4_parser",
        source=["ipyparse"],
        branch=True
    )
    cov.load() 
    cov.start()

    try:
        from ipyparse import ipv6
        result = ipv6.IPv6.parseString(ip_to_test, parseAll=True)
        decimal_ip = result[0]
        print(f"Output: [{decimal_ip}]")
    except Exception:
        print(f"Reference: Invalid IP")

    cov.stop()

    stream = StringIO()
    cov.report(file=stream, show_missing=False)
    cov.save()


if __name__ == "__main__":
    main()
