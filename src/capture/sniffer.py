"""module qui sniff un reseaux et crée des instance de Packet pour chaque packet"""
from datetime import datetime
from queue import Queue, Full
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
from config import Protocole, TCPFlag, MAX_QUEUE_SIZE, keyboardInterruption

class Packet:
    def __init__(self, scapy_pkt):
        self.timestamp   = datetime.now()
        self.size        = len(scapy_pkt)
        self.protocole   = self._get_proto(scapy_pkt)
        self.src_ip      = scapy_pkt[IP].src  if scapy_pkt.haslayer(IP)  else None
        self.dst_ip      = scapy_pkt[IP].dst  if scapy_pkt.haslayer(IP)  else None
        self.src_port    = self._get_src_port(scapy_pkt)
        self.dst_port    = self._get_dst_port(scapy_pkt)
        self.tcp_flags   = TCPFlag.from_scapy(scapy_pkt)
        self.dns_query   = self._get_dns_query(scapy_pkt)

    def _get_proto(self, pkt) -> Protocole:
        if pkt.haslayer(TCP):
            return Protocole.TCP
        if pkt.haslayer(UDP):
            return Protocole.UDP
        if pkt.haslayer(ICMP):
            return Protocole.ICMP
        return Protocole.OTHER

    def _get_src_port(self, pkt):
        if pkt.haslayer(TCP):
            return pkt[TCP].sport
        if pkt.haslayer(UDP):
            return pkt[UDP].sport
        return None

    def _get_dst_port(self, pkt):
        if pkt.haslayer(TCP):
            return pkt[TCP].dport
        if pkt.haslayer(UDP):
            return pkt[UDP].dport
        return None

    def _get_dns_query(self, pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd:
            return pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
        return None

    def __repr__(self):
        ts   = self.timestamp.strftime("%H:%M:%S.%f")[:-3]
        src  = f"{self.src_ip}:{self.src_port}"  if self.src_port  else self.src_ip
        dst  = f"{self.dst_ip}:{self.dst_port}"  if self.dst_port  else self.dst_ip
        info = f"DNS→{self.dns_query}" if self.dns_query else f"{self.size}B"
        return f"[{ts}] {self.protocole:<5} {src} → {dst}  {info}"


# ── Collecteur ────────────────────────────────────────────────────────────────

class PacketCollector:
    def __init__(self):
        self.packets: Queue = Queue(maxsize=MAX_QUEUE_SIZE)
        self.packets_count = 0
        self.dropped_count = 0
        self.current_pkt = ""

    def handle(self, scapy_pkt):
        """Callback appelé par sniff() pour chaque paquet."""
        print("[COLLECTOR]" + str(self.packets_count))
        if not scapy_pkt.haslayer(IP):
            return                          # ignorer ARP, etc.
        self.packets_count += 1 #RECHECK packet count ou handle count ?
        pkt = Packet(scapy_pkt)
        try:
            self.packets.put_nowait(pkt)
            self.current_pkt = repr(pkt)
        except Full:
            self.dropped_count += 1

    def start(self, iface="eth0", bpf_filter="ip"):
        """initialise le sniffer"""
        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=self.handle,
            store=False,        # scapy ne stocke pas, on gère nous-mêmes
            count=0,            # infini
            stop_filter=lambda _: keyboardInterruption.is_set(),
            timeout=1,
        )
