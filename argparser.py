import argparse
import ipaddress


def ip_format(ip):
    """Check if the ip give as an argument is written in a valid format"""
    try:
        return ipaddress.IPv4Network(ip)
    except ValueError:
        raise argparse.ArgumentTypeError("Wrong ip network/address format")


def setargparse():
    """Define the arguments the program can take"""
    parser = argparse.ArgumentParser()
    parser.add_argument("ipaddress", help="Examples: 192.168.1.1 or 192.168.1.0/24", type=ip_format)
    parser.add_argument("--fingerprint", "-f", action="store_true", help="Send and save packets to detect an os")
    parser.add_argument("--threads", "-t", nargs=1, type=int,
                        help="Select the number of threads the program should use. Default is 50 ")
    parser.add_argument("--screenshot", "-s", action="store_true", help="Try to take a screenshot on ports 80 and 443")
    parser.add_argument("--excel", "-e", action="store_true", help="Write a report in an excel file")
    parser.add_argument("--graph", "-g", action="store_true",
                        help="Work in progress || Draw a graph, graph-tool is required "
                             "https://graph-tool.skewed.de/")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ports", "-p", nargs='+', help="Select the ports to scan Example: 22 80 200-300")
    group.add_argument("--fileports", "-fp", nargs=1, type=str, help="Select a file to import the ports to scan")
    return parser.parse_args()
