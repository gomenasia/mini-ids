"""Point d'entrer de l'ids"""

import threading
from queue import Empty

from config import INTERFACE, ModelNotTrainedError, keyboardInterruption
from src.capture.sniffer import PacketCollector
from src.aggregation.flow_builder import Global_vue
from src.detection.ml_detector import Ml_detector
from src.detection.rules import set_of_rules
from src.storage.database import Database
from ui.dashboard import Dashboard
# ── Point d'entrée ────────────────────────────────────────────────────────────

if __name__ == "__main__":

    collector = PacketCollector() # instance du sniffer
    flow_builder = Global_vue()   # instance du flow_builder
    ml_detector = Ml_detector()   # instance du ml_detector
    database = Database()         # instacie la base de donnée
    dashboard = Dashboard(collector, flow_builder, database)

    def appele_sniffer():
        """initialyse le sniffer"""
        try:
            collector.start(iface=INTERFACE, bpf_filter="ip")
        except KeyboardInterrupt:
            keyboardInterruption.set()

    def detection():
        """detecte et enregistre les alert"""
        alert_list = []
        count = 1
        while not keyboardInterruption.is_set():   # verifie si il y a keyboard interuption
            print("[DETECTION]" + str(count))
            count += 1
            try:
                current_batch_analyse = flow_builder.get_oldest_analysis(timeout=1)
            except Empty:
                continue

            alert_list.extend(set_of_rules(current_batch_analyse))
            try:
                alert_list.extend(ml_detector.predict(current_batch_analyse))
            except ModelNotTrainedError:
                pass

            for alert in alert_list:
                database.append_alert(alert)

    # ========================= Gestion des threads =======================
    threads = []

    threads.append(threading.Thread(target=appele_sniffer, daemon=True))
    threads.append(threading.Thread(target=flow_builder.start_flow_builder, args=(collector.packets ,), daemon=True))
    threads.append(threading.Thread(target=detection, daemon=True))
    #threads.append(threading.Thread(target=dashboard.start, daemon=True))

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()