"""construit les flow"""
from collections import defaultdict
from queue import Empty, Full, Queue
from datetime import datetime
from statistics import mean #median() , variance(), stdev()
from config import Protocole, TCPFlag, FLOW_WINDOW_SECONDS, keyboardInterruption

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
        self.protocole_used[nvx_paquet.src_ip][nvx_paquet.protocole] += 1

        if nvx_paquet.src_ip not in self.port_reached:
            self.port_reached[nvx_paquet.src_ip] = defaultdict(int)
        self.port_reached[nvx_paquet.src_ip][nvx_paquet.dst_port] += 1


# =========================== produit une pre analyse ==================
class Batch_analysis():
    def __init__(self, batch: Batch):
        self.batch = batch
        self.data_by_flow = self._get_data_by_flow() # keys (src_ip, src_port, dst_ip, dst_port) | value : {"flow_syn, "flo_ack", "packet_count"}
        self.count = {
            "total_flow": len(self.batch.flows),
            "total_syn": self._get_total_flag(TCPFlag.SYN, self.batch.flows.values()),
            "total_ack": self._get_total_flag(TCPFlag.ACK, self.batch.flows.values()),
            "total_packets": self._get_total_packets()
        }
        self.port_reached_by_src_ip = self.batch.port_reached
        self.protocoel_used_by_user = self.batch.protocole_used

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
    
    def _get_total_packets(self):
        return sum([data_dict["packet_count"] for data_dict in self.data_by_flow.values()])

    def _analyse_flow_data(self, flow):
        return {
            "flow_syn": self._get_total_flag(TCPFlag.SYN, [flow]),
            "flow_ack": self._get_total_flag(TCPFlag.ACK, [flow]),
            "packet_count": flow.packets_count,
        }

    def to_vector(self):
        """produit un vecteur des donnée utilisable par l'isolation forest"""
        sum_icmp = sum([data[Protocole.ICMP] for data in self.protocoel_used_by_user.values()] or [0])
        sum_protocole = sum([sum(protocole.values()) for protocole in self.protocoel_used_by_user.values()] or [0])
        ratio_icmp = sum_icmp / sum_protocole if sum_protocole != 0 else sum_icmp

        ratio_syn_ack = self.count["total_syn"] / self.count["total_ack"] if self.count["total_ack"] != 0 else self.count["total_syn"]
        
        return (                
            self.count["total_flow"],                                   # total_flow — volume global d'activité
            ratio_syn_ack,                                              # ratio_syn_ack — détecte les scans SYN incomplets (total_syn si ack == 0)
            self.count["total_packets"],                                # total_packet — volume brut
            mean([len(port) for port in self.port_reached_by_src_ip.values()] or [0]),  # moy_ports_par_ip — diversité des ports contactés
            ratio_icmp,                                                 # ratio_icmp — proportion de trafic ICMP
            mean([data_dict["packet_count"] for data_dict in self.data_by_flow.values()] or [0])  # moy_paquets_par_flow — densité des conversati
        )


# ========================== chef d'orchestre du module ====================
class Global_vue():
    """permet l'interaction avec le module flow_builder"""
    def __init__(self):
        self.batch = Batch()
        self.analysis = Queue()
        self.dropped_analyse = 0

    def start_flow_builder(self, queue):
        """initialyse le flow_builder"""
        while not keyboardInterruption.is_set(): # verifie si il y a keyboard interuption
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
        """recupere la plus veille analyse dans la queue"""
        return self.analysis.get()
