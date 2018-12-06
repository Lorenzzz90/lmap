# coding=utf8
from argparser import setargparse
import os
from datetime import datetime
from scanner import Scanner
from utils import import_ports, create_logger
from excelreport import ReportCreator
from histogram import Histogram


def main():
    print("Scanning: {0}".format(args.ipaddress))
    program_function()
    print("Scan complete.")


def program_function():
    if args.fingerprint:
        fingerprint_additional_ports()
    if args.screenshot:
        screenshot_additional_ports()
    scanner = Scanner(iplist, args)
    scanner.start()
    if args.excel:
        rp = ReportCreator(scanner.get_report_list(), dirs['reports'])
        rp.excel_report()
    if args.graph:
        try:
            from graphcreator import ToGraph
            graph = ToGraph(scanner.get_report_list())
            graph.write_graph()
        except ImportError as exc:
            logger.exception(exc)
            print("You need graph-tool installed to draw a graph, please visit https://graph-tool.skewed.de/")
    if args.histogram:
        ist = Histogram(scanner.get_report_list())
        ist.create_histogram()


def screenshot_additional_ports():
    """Add ports 80 and 443 to ports list"""
    ssports = [80, 443]
    for port in ssports:
        if port not in args.ports:
            args.ports.append(port)


def fingerprint_additional_ports():
    """Add ports 22, 135, 445 and 3389 to ports list"""
    fpports = [22, 135, 445, 3389]
    for port in fpports:
        if port not in args.ports:
            args.ports.append(port)


def default_save_dirs():
    """Check for save directories and if non existent it creates them"""
    dirs = {}
    if not os.path.exists(os.path.join(os.getcwd(), "reports")):
        save_dir = os.path.join(os.getcwd(), "reports")
        os.mkdir(save_dir)
        dirs["reports"] = save_dir
    else:
        save_dir = os.path.join(os.getcwd(), "reports")
        dirs["reports"] = save_dir
    if not os.path.exists(os.path.join(os.getcwd(), "screenshots")):
        screen_dir = os.path.join(os.getcwd(), "screenshots")
        os.mkdir(screen_dir)
        dirs["screen"] = screen_dir
    else:
        screen_dir = os.path.join(os.getcwd(), "screenshots")
        dirs["screen"] = screen_dir
    if args.screenshot:
        time_screen_dir = os.path.join(screen_dir, datetime.now().strftime("%d-%m-%Y_%H^%M^%S"))
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
    #if os.geteuid() != 0:
    #    exit("You need root privileges to run this program.")
    args = setargparse()
    logger = create_logger(os.getcwd())
    dirs = default_save_dirs()
    iplist = args.ipaddress
    ports = import_ports(args, os.path.join(os.getcwd(), "wkports.txt"))
    main()
