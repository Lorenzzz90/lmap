import logging
import os
from datetime import datetime

logging.getLogger(__name__)


def write_to_file(report, report_file):
    report_file.sort(key=lambda tup: tup[0])
    with open (report, "w") as f_obj:
        for id_ip in report_file:
            f_obj.write(id_ip[1])


def create_report_file(dir):
    return (os.path.join(dir, datetime.now().strftime("%d-%m-%Y_%H^%M^%S.txt")))


def import_ports(args, default):
    """Import a list of ports from an external file and return a dictionary
        where keys are the port number and values are the description of the port"""
    if args.ports:
        consecutive_ports = [x for x in args.ports if "-" in x]
        args.ports = [int(z) for z in args.ports if z not in consecutive_ports]
        for cports in consecutive_ports:
            a, b = cports.split("-")
            [args.ports.append(x) for x in range (int(a), int(b)+1) ]
            if int(a) >= int(b):
                print("Range di porte non valido, metti prima la porta piu bassa,"
                      " scansionerò solo le porte inserite correttamente")

        args.ports.sort()
        return args.ports
    elif args.fileports:
        filename = args.fileports
    else:
        filename = default
    with open(filename) as file_obj:
        lines = file_obj.readlines()
    args.ports = []
    for line in lines:
        splitted_line = line.split(" ", 1)
        args.ports.append(int(splitted_line[0]))
    args.ports.sort()
    return args.ports


def create_logger(base_dir):
    base_dir = base_dir
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(os.path.join(base_dir, "info.log"))
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(funcName)s: %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setLevel(logging.CRITICAL)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger
