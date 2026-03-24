"""Point d'entrer de l'ids"""

import threading
from queue import Empty
from config import INTERFACE, ModelNotTrainedError, keyboardInterruption
from src.capture.sniffer import PacketCollector
from src.aggregation.flow_builder import Global_vue
from src.detection.ml_detector import Ml_detector
from src.detection.rules import set_of_rules
from src.storage.database import database
# ── Point d'entrée ────────────────────────────────────────────────────────────

if __name__ == "__main__":

    collector = PacketCollector() # instance du sniffer 
    flow_builder = Global_vue()   # instance du flow_builder
    ml_detector = Ml_detector()   # instance du ml_detector

    def appele_sniffer():
        """initialyse le sniffer"""
        try:
            collector.start(iface=INTERFACE, bpf_filter="ip")
        except KeyboardInterrupt:
            keyboardInterruption.set()
            print(f"\n{collector.dropped_count} paquets abandoner.")

    def detection():
        """detecte et enregistre les alert"""
        alert_list = []
        while not keyboardInterruption.is_set():   # verifie si il y a keyboard interuption
            current_batch_analyse = flow_builder.get_oldest_analysis()

            alert_list.extend(set_of_rules(current_batch_analyse))
            try:
                alert_list.extend(ml_detector.predict(current_batch_analyse))
            except ModelNotTrainedError:
                pass

            for alert in alert_list:
                database.append_alert(alert)

    # ========================= Gestion des threads =======================
    threads = []

    threads.append(threading.Thread(target=appele_sniffer))
    threads.append(threading.Thread(target=flow_builder.start_flow_builder, args=(collector.packets ,)))
    threads.append(threading.Thread(target=detection))

    for thread in threads:
        thread.start()