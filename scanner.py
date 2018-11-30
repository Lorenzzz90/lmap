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
        self.report = {}
        self.queue = Queue()
        if args.screenshot:
            self.dir = args.screenshot

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
        threads = 50
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
        ports_strings = []
        ipt = self.queue.get()
        id, ip = ipt
        if self.args.ports is dict():
            portlist = []
            for port in self.args.ports.keys():
                portlist.append(port)
            self.args.ports = portlist
        for port in self.args.ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ports_strings.append(str(port))
            try:
                s.settimeout(1)
                s.connect((str(ip), port))
                if self.args.screenshot and (port in [80, 443]):
                    screenshot(ipt, port, self.dir)
                active_ports.append(str(port))
                banner = s.recv(1024)
                banners[port] = banner
                logging.info("Answer from : {0} port: {1}".format(str(ip), str(port)))
            except socket.timeout:
                logging.info(str(ip) + " :" + str(port) + " Timed out")
                timed_out_list.append(str(port))
            except ConnectionRefusedError:
                logging.info(str(ip) + " :" + str(port) + " Connection Refused")
                conn_ref_list.append(str(port))
            except OSError as exc:
                logging.exception(exc)
            except Exception as ex:
                logging.exception(ex)
        osdetected = None
        if active_ports:
            fp = Fingerprinting(ip, int(active_ports[0]), self.args)
            fp.tcp_probing()
            osf = Osfinder(fp.get_packet_list(), active_ports)
            osdetected = osf.check_os()

        ip_dict = {}
        ip_dict["Ip"] = str(ip)
        ip_dict["Active Ports"] = active_ports
        ip_dict["Banner"] = banners
        ip_dict["Os Detected"] = osdetected
        ip_dict["Connection Refused"] = conn_ref_list
        ip_dict["Port Scanned"] = ports_strings

        self.report[id] = ip_dict



    def get_report_list(self):
        return self.report

