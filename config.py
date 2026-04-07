"""configuration et variable global"""
from enum import Enum, Flag, auto
import threading

# config.py
# Tous les seuils et constantes du projet — modifier ici, pas dans le code

#constante
MAX_QUEUE_SIZE = 15000 # 15 000 passcket max dans la queue

# Réseau
INTERFACE = "eth0"          # None = interface par défaut détectée automatiquement
FLOW_WINDOW_SECONDS = 30  # Durée d'une fenêtre d'agrégation

# Seuils règles signatures
SYN_SCAN_THRESHOLD = 15       # SYN sans ACK en FLOW_WINDOW_SECONDS → scan de ports
SSH_BRUTE_THRESHOLD = 20      # Tentatives SSH en FLOW_WINDOW_SECONDS → brute force
ICMP_FLOOD_THRESHOLD = 100    # Paquets ICMP en FLOW_WINDOW_SECONDS → flood

# Seuil ML
ISOLATION_FOREST_CONTAMINATION = 0.05  # 5% de trafic considéré anormal

# Base de données
DB_PATH = "data/alerts.db"


# ================================== ENUM =================================
class Protocole(Enum):
    """enumere les protocole"""
    TCP  = 6
    UDP  = 17
    ICMP = 1
    OTHER = 0

    def est_transport(self):
        """permet de savoir si c'est un protocole de transport"""
        return self in (Protocole.TCP, Protocole.UDP)

    def __str__(self):
        return self.name
    
class TCPFlag(Flag):
    """represente les flag TCP possible"""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


    @classmethod
    def from_scapy(cls, pkt):
        """Convertit les flags d'un paquet Scapy en TCPFlag."""
        from scapy.all import TCP
        if pkt.haslayer(TCP):
            return cls(int(pkt[TCP].flags))
        return cls(0)

    def est_handshake(self):
        return TCPFlag.SYN in self and TCPFlag.ACK not in self

    def est_fermeture(self):
        return TCPFlag.FIN in self or TCPFlag.RST in self

class AlertType (Enum):
    """represente toute les type d'alert possible"""
    ICMP_flood = auto()
    SSH_bruteforce = auto()
    SYN_scan = auto()

# ========================================= Exeption ======================================

class ModelNotTrainedError(Exception):
    pass

# ======================================= Threadings events ===============================

keyboardInterruption = threading.Event()
