import pygal


class Histogram():
    """Create an histogram with the number of connection is enstabilished on the ports"""
    def __init__(self, report):
        self.active_ports = []
        for ip in report.values():
            for port in ip["Active Ports"]:
                self.active_ports.append(port)
        self.set_ports = set(self.active_ports)
        self.frequencies = []
        for value in self.set_ports:
            frequency = self.active_ports.count(value)
            self.frequencies.append(frequency)

    def create_histogram(self):

        hist = pygal.Bar()
        hist._title = "Results of open ports"
        hist.x_labels = self.set_ports
        hist._x_title = "Ports"
        hist._y_title = "Frequency of open connection"
        hist.add('Open ports', self.frequencies)
        hist.render_to_file('open_ports.svg')
