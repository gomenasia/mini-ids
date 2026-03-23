"""Point d'entrer de l'ids"""

import threading
from config import INTERFACE
from capture.sniffer import PacketCollector
from aggregation.flow_builder import Global_vue
# ── Point d'entrée ────────────────────────────────────────────────────────────

if __name__ == "__main__":

    threads = []
    collector = PacketCollector()

    def appele_sniffer():
        """initialyse le sniffer"""
        try:
            collector.start(iface=INTERFACE, bpf_filter="ip")
        except KeyboardInterrupt:
            print(f"\n{collector.dropped_count} paquets abandoner.")

    threads.append(threading.Thread(target=appele_sniffer))
    threads.append(threading.Thread(target=Global_vue.start_flow_builder, args=(collector,)))

    for thread in threads:
        thread.start()