import logging
from scapy.all import *

logging.getLogger(__name__)


class Osfinder():

    def __init__(self, pkts, ports):
        self.pkts = pkts
        self.ports = ports
        self.windows = 0
        self.linux = 0

    def check_os(self):
        self.check_answering_ports()
        if self.pkts:
            self.check_window_scale_value()
        return self.os_detected()

    def check_answering_ports(self):
        if 22 in self.ports:
            self.linux += 3
        if 3389 in self.ports:
            self.windows += 2
        if 135 in self.ports:
            self.windows += 2
        if 445 in self.ports:
            self.windows += 2

    def check_window_scale_value(self):
        windows = 0
        linux = 0
        for pkt in self.pkts:
            tcp = pkt.getlayer(TCP)
            wsv = tcp.window
            if wsv == 28960:
                linux += 1
            elif wsv == 65535:
                windows += 1
            elif wsv == 8192:
                windows += 1
        if windows > linux:
            self.windows += 1
        elif linux > windows:
            self.linux += 1

    def os_detected(self):
        if self.windows > self.linux:
            return "Most likely: Windows"
        elif self.linux > self.windows:
            return "Most likely: Linux"
        else:
            return "Cannot detect an os"
