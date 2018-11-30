from scapy.all import *
import threading
import logging

logging.getLogger(__name__)


class Fingerprinting():
    def __init__(self, ip, port, args):
        self.ip = str(ip)
        self.pkts = []
        self.port = port
        self.dir = os.path.join(args.fingerprint, str(ip))
        os.mkdir(self.dir)
        self.pkts = ""

    def tcp_probing(self):
        t = threading.Thread(target=self.start_sniff)
        t.daemon = True
        t.start()
        time.sleep(1)
        self.send_tcp_probe_one()
        self.send_tcp_probe_two()
        self.send_tcp_probe_three()
        self.send_tcp_probe_four()
        self.send_tcp_probe_five()
        self.send_tcp_probe_six()
        t.join()

    def write_pkts(self):
        x = 1
        for pkt in self.pkts:
            wrpcap(os.path.join(self.dir, "packet{0}.pcap".format(str(x))), pkt)
            x += 1

    def icmp_probing(self):
        self.send_echo_invalid_code_packet()
        self.send_icmp_get_address_mask_packet()
        self.send_icmp_get_timestamp_packet()
        self.send_icmp_get_information_packet()
        self.send_echo_invalid_code_packet()

    def get_packet_list(self):
        return self.pkts

    def print_packets(self):
        for pkt in self.pkts:
            pkt.show()

    def start_sniff(self):
        filters = "dst port {0}" \
                  " or dst port {1}" \
                  " or dst port {2}" \
                  " or dst port {3}" \
                  " or dst port {4}" \
                  " or dst port {5}" \
                  " and host {6}".format("39429", "39430", "39431", "39432", "39433", "39434" ,str(self.ip))
        answer = sniff(count=12, timeout=10, filter=filters)
        set_answer = PacketList()
        check_port = []
        for pkt in answer:
            tcp = pkt.getlayer(TCP)
            port = str(tcp.dport)
            if port not in check_port:
                set_answer.append(pkt)
                wrpcap(os.path.join(self.dir, "packet{0}.pcap".format(str(port))), pkt)
                check_port.append(port)
        self.pkts = PacketList()
        self.pkts = set_answer

    def sniff_icmp(self):

        def stopfilter(x):
            if x[IP].src == self.ip:
                return True
            else:
                return False

        def packet_callback(pkt):
            self.pkts.append(pkt)

        filters = "host {}".format(str(self.ip))
        print('inizio cattura')
        answer = sniff(count=0, prn=packet_callback, timeout=5, filter=filters, stop_filter=stopfilter)
        print(answer)

    def create_icmp_packet(self):
        pkt = IP(dst=self.ip) / ICMP()
        return pkt

    def change_icmp_code(self, pkt, code_number):
        pkt[ICMP].code = code_number

    def change_icmp_type(self, pkt, type_number):
        pkt[ICMP].type = type_number

    def send_packet(self, pkt):
        time.sleep(0.1)
        send(pkt, verbose=False)

    def send_echo_invalid_code_packet(self):
        pkt = self.create_icmp_packet()
        self.change_icmp_type(pkt, 8)
        self.change_icmp_code(pkt, 19)
        self.send_packet(pkt)

    def send_icmp_get_address_mask_packet(self):
        pkt = self.create_icmp_packet()
        self.change_icmp_type(pkt, 17)
        self.send_packet(pkt)

    def send_icmp_get_timestamp_packet(self):
        pkt = self.create_icmp_packet()
        self.change_icmp_type(pkt, 13)
        self.send_packet(pkt)

    def send_icmp_get_information_packet(self):
        pkt = self.create_icmp_packet()
        self.change_icmp_type(pkt, 15)
        self.send_packet(pkt)

    def create_tcp_syn_packet(self):
        pkt = IP(dst=self.ip)/TCP(dport=self.port)
        return pkt

    def send_tcp_probe_one(self):
        pkt = self.create_tcp_syn_packet()
        tcp = pkt.getlayer(TCP)
        tcp.sport = 39429
        tcp.window = 1
        tcp.options = [('WScale', 10), ('NOP', ''), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]
        self.send_packet(pkt)

    def send_tcp_probe_two(self):
        pkt = self.create_tcp_syn_packet()
        tcp = pkt.getlayer(TCP)
        tcp.sport = 39430
        tcp.window = 63
        tcp.options = [('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', 1)]
        self.send_packet(pkt)

    def send_tcp_probe_three(self):
        pkt = self.create_tcp_syn_packet()
        tcp = pkt.getlayer(TCP)
        tcp.sport = 39431
        tcp.window = 4
        tcp.options = [('Timestamp', (0xFFFFFFFF, 0)), ('NOP', ''), ('NOP', ''), ('WScale', 5), ('NOP', ''), ('MSS', 640)]
        self.send_packet(pkt)

    def send_tcp_probe_four(self):
        pkt = self.create_tcp_syn_packet()
        tcp = pkt.getlayer(TCP)
        tcp.sport = 39432
        tcp.window = 4
        tcp.options = [('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', 1)]
        self.send_packet(pkt)

    def send_tcp_probe_five(self):
        pkt = self.create_tcp_syn_packet()
        tcp = pkt.getlayer(TCP)
        tcp.sport =39433
        tcp.window = 16
        tcp.options = [('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', 1)]
        self.send_packet(pkt)

    def send_tcp_probe_six(self):
        pkt = self.create_tcp_syn_packet()
        tcp = pkt.getlayer(TCP)
        tcp.sport = 39434
        tcp.window = 512
        tcp.options = [('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0))]
        self.send_packet(pkt)




