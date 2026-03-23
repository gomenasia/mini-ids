"""Point d'entrer de l'ids"""

import threading
from capture.sniffer import PacketCollector
# ── Point d'entrée ────────────────────────────────────────────────────────────

if __name__ == "__main__":

    threads = []
    collector = PacketCollector()

        
    def appele_sniffer():
        try:
            collector.start(iface="eth0", bpf_filter="ip")
        except KeyboardInterrupt:
            print(f"\n{collector.dropped_count} paquets abandoner.")

    def appele_flow_builder():
        pass

    threads.append(threading.Thread(target=appele_sniffer))
    threads.append(threading.Thread(target=appele_flow_builder))

    for thread in threads:
        thread.start()