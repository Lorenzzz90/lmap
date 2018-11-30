from argparser import setargparse
import os
from datetime import datetime
from scanner import Scanner
from utils import import_ports, create_logger, create_report_file, write_to_file


def program_function():
    if args.fingerprint:
        fingerprint_additional_ports()
    scanner = Scanner(iplist, args)
    scanner.start()
    report_list = scanner.get_report_list()
    write_to_file(report, report_list)



def main():
    print("Scanning: {0}".format(args.ipaddress))
    program_function()
    print("Scan complete.")


def fingerprint_additional_ports():
    fpports = [22, 135, 445, 3389]
    for port in fpports:
        if port not in args.ports:
            args.ports.append(port)


def default_save_dirs():
    dirs = {}
    if not os.path.exists(os.path.join(os.getcwd(), "reports")):
        save_dir = os.path.join(os.getcwd(), "reports")
        os.mkdir(save_dir)
        dirs["save"] = save_dir
    else:
        save_dir = os.path.join(os.getcwd(), "reports")
        dirs["save"] = save_dir
    if not os.path.exists(os.path.join(os.getcwd(), "screenshots")):
        screen_dir = os.path.join(os.getcwd(), "screenshots")
        os.mkdir(screen_dir)
        dirs["screen"] = screen_dir
    else:
        screen_dir = os.path.join(os.getcwd(), "screenshots")
        dirs["screen"] = screen_dir
    if args.screenshot:
        time_screen_dir = os.path.join(screen_dir, datetime.now().strftime("%d-%m-%Y_%H^%M^%S"))
        os.mkdir(time_screen_dir)
        dirs["timescreen"] = time_screen_dir
        args.screenshot = time_screen_dir
    if args.fingerprint and not os.path.exists(os.path.join(os.getcwd(), "packets")):
        packets_dir = os.path.join(os.getcwd(), "packets")
        os.mkdir(packets_dir)
        dirs["packets"] = packets_dir
    if args.fingerprint:
        packets_dir = os.path.join(os.getcwd(), "packets")
        current_packets_dir = os.path.join(packets_dir, datetime.now().strftime("%d-%m-%Y_%H^%M^%S"))
        os.mkdir(current_packets_dir)
        dirs["current_packets_dir"] = current_packets_dir
        args.fingerprint = current_packets_dir
    return dirs


if __name__ == '__main__':
    args = setargparse()
    logger = create_logger(os.getcwd())
    dirs = default_save_dirs()
    report = create_report_file(dirs["save"])
    iplist = args.ipaddress
    ports = import_ports(args, os.path.join(os.getcwd(), "wkports.txt"))
    main()
