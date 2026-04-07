"""module qui produit les alert selon les batch_analysis"""
from config import *

class Alert():
    def __init__(self, alert_type, src_ip, severite, timestamp):
        self.alert_type = alert_type
        self.src_ip = src_ip
        self.severite = severite
        self.timestamp = timestamp


def scan_de_port(analyse) -> list[Alert]:
    """detect les attack de scan port"""
    alerts = [] # gere la possibiliter de plusieur attack dans le même batch
    for src_ip, port_dict in analyse.port_reached_by_src_ip.items():
        if len(port_dict) > SYN_SCAN_THRESHOLD:
            alerts.append(Alert(AlertType .SYN_scan,
                            src_ip,
                            calc_severity(len(port_dict), SYN_SCAN_THRESHOLD),
                            analyse.batch.timestamp_start))
    return alerts

def bruteforce_ssh(analyse) -> list[Alert]:
    """detect les attack SSH bruteforce"""
    alerts = []
    for src_ip, port_dict in analyse.port_reached_by_src_ip.items():
        if port_dict.get(22, 0) > SSH_BRUTE_THRESHOLD:
            alerts.append(Alert(AlertType .SSH_bruteforce,
                                src_ip,
                                calc_severity(port_dict[22], SSH_BRUTE_THRESHOLD),
                                analyse.batch.timestamp_start)) # imprecis a 10 second près
    return alerts

def flood_icmp(analyse) -> list[Alert]:
    """detect les attack flood IMCP"""
    alerts = []
    for src_ip, proto_dict in analyse.protocole_used_by_user.items():
        if proto_dict[Protocole.ICMP] > ICMP_FLOOD_THRESHOLD:
            alerts.append(Alert(AlertType .ICMP_flood,
                                src_ip,
                                calc_severity(proto_dict[Protocole.ICMP], ICMP_FLOOD_THRESHOLD),
                                analyse.batch.timestamp_start))
    return alerts

def set_of_rules(analyse):
    """éxécute une baterrie de test et renvoie une list d'alert"""
    alerts = []
    alerts.extend(scan_de_port(analyse))
    alerts.extend(bruteforce_ssh(analyse))
    alerts.extend(flood_icmp(analyse))
    return alerts

def calc_severity(value, threshold):
    """calcule le sévérité d'une attaque"""
    if value > 2*threshold:      # l'attaquee depasse le seuil de 200%
        return 3
    elif value > 1.5*threshold:  # l'attaquee depasse le seuil de 150%
        return 2
    elif value > threshold:      # l'attaquee depasse le seuil
        return 1
    else:
        return 0                # au cas ou l'attaque ne depasse pas le seuil