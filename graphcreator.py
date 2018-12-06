from graph_tool.all import *


class ToGraph():
    """Create and save the png graph / work in progress"""

    def __init__(self, report):
        self.report = report
        self.VERTEX = {}
        self.g1 = Graph()
        self.VERTEX_NAME = self.g1.new_vertex_property("string")

    def add_vertex(self, port):
        if port not in self.VERTEX:
            self.VERTEX[port] = {'vertex': None, 'connected_to': []}
            self.VERTEX[port]['vertex'] = self.g1.add_vertex()
            self.VERTEX_NAME[self.VERTEX[port]['vertex']] = port

    def write_graph(self):
        for key in self.report.keys():
            active_ports = self.report[key]['Active Ports']
            if active_ports:
                for port in active_ports:
                    self.add_vertex(port)
        graph_draw(self.g1, vertex_text=self.VERTEX_NAME, vertex_font_size=90, output_size=(3000, 3000),
                   output="graph.png")
