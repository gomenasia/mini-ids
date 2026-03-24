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
                            None, #FIXME pas encore de severiter implementer
                            analyse.batch.timestamp_start))
    return alerts

def bruteforce_ssh(analyse) -> list[Alert]:
    """detect les attack SSH bruteforce"""
    alerts = []
    for src_ip, port_dict in analyse.port_reached_by_src_ip.items():
        if port_dict[22] > SSH_BRUTE_THRESHOLD:
            alerts.append(Alert(AlertType .SSH_bruteforce,
                                src_ip,
                                None, #FIXME pas encore de severiter implementer
                                analyse.batch.timestamp_start)) # imprecis a 10 second près
    return alerts

def flood_icmp(analyse) -> list[Alert]:
    """detect les attack flood IMCP"""
    alerts = []
    for src_ip, proto_dict in analyse.protocoel_used_by_user.items():
        if proto_dict[Protocole.ICMP] > ICMP_FLOOD_THRESHOLD:
            alerts.append(Alert(AlertType .ICMP_flood,
                                src_ip,
                                None, #FIXME pas encore de severiter implementer
                                analyse.batch.timestamp_start))
    return alerts

def set_of_rules(analyse):
    alerts = []
    alerts.extend(scan_de_port(analyse))
    alerts.extend(bruteforce_ssh(analyse))
    alerts.extend(flood_icmp(analyse))
    return alerts