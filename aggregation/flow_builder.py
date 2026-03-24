"""construit les flow"""
from config import Protocole, TCPFlag, FLOW_WINDOW_SECONDS
from collections import defaultdict
from queue import Empty, Full, Queue
from datetime import datetime

# ======================== flux individuel ==============================
class Flow():
    def __init__(self):
        self.timestamp_debut = None
        self.timestamp_fin = None
        self.packets_count = 0
        self.flags = defaultdict(int)  # keys : TCPFlag | value : aparition count
        self.total_packet_length = 0

    def append_packet(self, nvx_paquet):
        if self.packets_count == 0:
            self.timestamp_debut = nvx_paquet.timestamp

        # valeur réécrite a chaque paquet
        self.timestamp_fin = nvx_paquet.timestamp

        self.packets_count += 1
        self.total_packet_length += nvx_paquet.size

        if nvx_paquet.protocole == Protocole.TCP:
            for flag in list(nvx_paquet.tcp_flags):
                self.flags[flag] += 1


# ======================= ensemble des flux sur x secound ====================
class Batch():
    def __init__(self):
        self.timestamp_start = datetime.now()
        self.flows = {} # keys : (ip_src, port_src, ip_dst, port_dst) | value : Flow
        self.protocole_used = {} # keys : src_ip | values : dict de protocole utiliser
        self.port_reached = {} # keys : src_ip | value : dict de port contacter

    def append_packet(self, nvx_paquet):
        """permet l'ajout de flow"""
        key = (nvx_paquet.src_ip,
                nvx_paquet.src_port,
                nvx_paquet.dst_ip,
                nvx_paquet.dst_port)
        
        if key not in self.flows:
            self.flows[key] = Flow()
        self.flows[key].append_packet(nvx_paquet)

        if nvx_paquet.src_ip not in self.protocole_used:
            self.protocole_used[nvx_paquet.src_ip] = defaultdict(int)
        self.protocole_used[nvx_paquet.src_ip] += 1

        if nvx_paquet.src_ip not in self.port_reached:
            self.port_reached[nvx_paquet.src_ip] = defaultdict(int)
        self.port_reached[nvx_paquet.src_ip][nvx_paquet.dst_port] += 1


# =========================== produit une pre analyse ==================
class Batch_analysis():
    def __init__(self, batch: Batch):
        self.batch = batch
        self.total_count = {
            "total_flow": len(self.batch.flows),
            "total_syn": self._get_total_flag(TCPFlag.SYN, self.batch.flows.values()),
            "total_ack": self._get_total_flag(TCPFlag.ACK, self.batch.flows.values()),
        }
        self.port_reached_by_src_ip = self.batch.port_reached
        self.protocoel_used_by_user = self.batch.protocole_used
        self.data_by_flow = self._get_data_by_flow()

    def _get_total_flag(self, flag:TCPFlag, flows: list[Flow]):
        total = 0
        for flow in flows:
            total += flow.flags[flag]
        return total

    def _get_data_by_flow(self):
        data_by_flow_dict = {}
        for key, flow in self.batch.flows.items():
            data_by_flow_dict[key] = self._analyse_flow_data(flow)
        return data_by_flow_dict

    def _analyse_flow_data(self, flow):
        return {
            "flow_syn": self._get_total_flag(TCPFlag.SYN, [flow]),
            "flow_ack": self._get_total_flag(TCPFlag.ACK, [flow]),
            "packet_count": flow.packets_count,
        }


# ========================== chef d'orchestre du module ====================
class Global_vue():
    def __init__(self):
        self.batch = Batch()
        self.analysis = Queue()
        self.dropped_analyse = 0

    def start_flow_builder(self, queue):
        while True:
            duration = datetime.now() - self.batch.timestamp_start 
            if duration.total_seconds() > FLOW_WINDOW_SECONDS:
                try:
                    self.analysis.put_nowait(Batch_analysis(self.batch))
                except Full:
                    self.dropped_analyse += 1
                self.batch = Batch()

            try:
                packet = queue.get(timeout = 0.2)
                self.batch.append_packet(packet)
            except Empty:
                continue
    
    def get_oldest_analysis(self) -> Batch_analysis:
        return self.analysis.get()