"""module qui produit les alert selon les batch_analysis"""
from config import *

class Alert():
    def __init__(self, alert_type, src_ip, severite, timestamp):
        self.alert_type = alert_type
        self.src_ip = src_ip
        self.severite = severite
        self.timestamp = timestamp


def scan_de_port(analyse) -> list[Alert]:
    alerts = [] # gere la possibiliter de plusieur attack dans le même batch
    for src_ip, port_dict in analyse.port_reached_by_src_ip.items():
        if len(port_dict) > SYN_SCAN_THRESHOLD:
            alerts.append(Alert(AlertType .SYN_scan,
                            src_ip,
                            None, #FIXME pas encore de severiter implementer
                            analyse.batch.timestamp_start))
    return alerts

def bruteforce_SSH(analyse) -> list[Alert]:
    alerts = []
    for src_ip, port_dict in analyse.port_reached_by_src_ip.items():
        if port_dict[22] > SSH_BRUTE_THRESHOLD:
            alerts.append(Alert(AlertType .SSH_bruteforce,
                                src_ip,
                                None, #FIXME pas encore de severiter implementer
                                analyse.batch.timestamp_start)) # imprecis a 10 second près
    return alerts

def flood_ICPM(analyse) -> list[Alert]:
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
    alerts.extend(bruteforce_SSH(analyse))
    alerts.extend(flood_ICPM(analyse))
    return alerts