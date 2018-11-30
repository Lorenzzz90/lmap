import socket
import threading



from screenshot import screenshot
from queue import Queue
import logging
from fingerprinting import Fingerprinting
from osfinder import Osfinder

logging.getLogger(__name__)


class Scanner():
    def __init__(self, iplist, args):
        self.iplist = iplist
        self.args = args
        self.report = []
        self.report_two = {}
        self.queue = Queue()
        if args.screenshot:
            self.dir = args.screenshot
        self.os = ""
        self.progress = Queue()

    class ScannerThread(threading.Thread):
        output_lock = threading.Lock()

        def __init__(self, squeue, ports, scan_ports):
            threading.Thread.__init__(self)
            self.squeue = squeue
            self.ports = ports
            self.scan_ports = scan_ports

        def run(self):
            while True:
                self.scan_ports()
                self.squeue.task_done()

    def start(self):
        threads = 30
        if self.args.threads:
            threads = self.args.threads[0]
        for i in range(threads):
            t = self.ScannerThread(self.queue, self.args.ports, self.scan_ports)
            t.setDaemon(True)
            t.start()
        idd = 0
        for ip in self.iplist:
            id_ip = (idd, ip)
            self.queue.put(id_ip)
            idd += 1
        self.queue.join()


    def get_os(self):
        return self.os

    def scan_ports(self):
        """the core of the program which scans the ports of the given ip"""
        timed_out_list = []
        active_ports = []
        conn_ref_list = []
        banners = {}
        ipt = self.queue.get()
        id, ip = ipt
        if self.args.ports is dict():
            portlist = []
            for port in self.args.ports.keys():
                portlist.append(port)
            self.args.ports = portlist
        for port in self.args.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(1)
                s.connect((str(ip), port))

                if self.args.screenshot and (port in [80, 443]):
                    screenshot(ipt, port, self.dir)
                active_ports.append(port)
                banner = s.recv(1024)
                banners[port] = banner
                if banner and self.args.banner:
                    active_ports.append(banner)

                logging.info("Answer from : {0} port: {1}".format(str(ip), str(port)))
            except socket.timeout:
                if self.args.verbose:
                    logging.info(str(ip) + " :" + str(port) + " Timed out")
                    timed_out_list.append(port)
                else:
                    pass
            except ConnectionRefusedError:
                if self.args.verbose:
                    logging.info(str(ip) + " :" + str(port) + " Connection Refused")
                    conn_ref_list.append(port)
                else:
                    pass
            except OSError as exc:
                logging.exception(exc)
            except Exception as ex:
                logging.exception(ex)
        if self.args.fingerprint and active_ports:
            fp = Fingerprinting(ip, active_ports[0], self.args)
            fp.tcp_probing()
            osf = Osfinder(fp.get_packet_list(), active_ports)
            osdetected = osf.check_os()
        if self.args.verbose:
            if self.args.fingerprint:
                self.report.append((id, "{0} :\n\tOs Detected: {1}\n\t"
                                        "Answer from: {2}\n\t"
                                        "Timed out: {3}\n\t"
                                        "Connection refused: {4}\n".format(str(ip), osdetected, str(active_ports),
                                                                           str(timed_out_list), str(conn_ref_list))))

            else:
                self.report.append((id, "{0} :\n\tAnswer from: {1}\n\t"
                                        "Timed out: {2}\n\t"
                                        "Connection refused: {3}\n".format(str(ip), str(active_ports), str(timed_out_list), str(conn_ref_list))))
        elif active_ports:
            if self.args.fingerprint:
                self.report.append((id,
                                    "Answer from: {0} ports: {1} Os Detected: {2}\n".format(str(ip), str(active_ports),
                                                                                            osdetected)))
            else:
                self.report.append((id, "Answer from: {0} ports: {1}\n".format(str(ip), str(active_ports))))







    def get_report_list(self):
        return self.report

