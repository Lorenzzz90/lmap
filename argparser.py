import argparse
import ipaddress


def ip_format(ip):
        try:
            return ipaddress.IPv4Network(ip)
        except ValueError:
            raise argparse.ArgumentTypeError("Wrong ip network/address format")


def setargparse():
    parser = argparse.ArgumentParser()
    parser.add_argument("ipaddress", help="Examples: 192.168.1.1 or 192.168.1.0/24", type=ip_format)
    parser.add_argument("--fingerprint", "-f", action="store_true", help="Send an icmp packet to the given ip")
    parser.add_argument("--threads", "-t", nargs=1, type=int, help="Select the number of threads the program should use.")
    parser.add_argument("--verbose", "-v", action="store_true",  help="Choose if the filelog will also contain connections timed out or refused")
    parser.add_argument("--screenshot", "-s", action="store_true", help="Try to take a screenshot on ports 80 and 443")
    parser.add_argument("--path", nargs=1, type=str, help="Select a custom path to save report and screenshots")
    parser.add_argument("--banner", "-b", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ports", "-p", nargs='+', help="Select the ports to scan Example: 22 80 200-300")
    group.add_argument("--fileports", "-fp", nargs=1, type=str, help="Select a file to import the ports to scan")
    return parser.parse_args()
