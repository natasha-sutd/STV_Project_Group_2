import sys
import coverage


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
        from ipyparse import ipv4
        result = ipv4.IPv4.parseString(ip_to_test, parseAll=True)
        decimal_ip = result[0]
        print(f"Output: [{decimal_ip}]")
    except Exception as e:
        print(f"Reference: Invalid IP")

    cov.stop()
    cov.save()


if __name__ == "__main__":
    main()
