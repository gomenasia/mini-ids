"""Point d'entrer de l'ids"""

from datetime import time
from time import sleep
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
            print("keyboard interupt")
        except Exception as e:
            print(f"Erreur : {e}")
        finally:
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
                print("fail" + str(count-1))
                continue

            alert_list.extend(set_of_rules(current_batch_analyse))
            try:
                alert_list.extend(ml_detector.predict(current_batch_analyse))
            except ModelNotTrainedError:
                pass

            for alert in alert_list:
                database.append_alert(alert)
            alert_list = []

    # ========================= Gestion des threads =======================
    threads = []

    threads.append(threading.Thread(target=appele_sniffer, daemon=True))
    threads.append(threading.Thread(target=flow_builder.start_flow_builder, args=(collector.packets ,), daemon=True))
    threads.append(threading.Thread(target=detection, daemon=True))
    threads.append(threading.Thread(target=dashboard.start, daemon=True))

    for thread in threads:
        thread.start()

    try:
        while True:                          # boucle active sur le thread principal
            sleep(0.5)
            if not any(t.is_alive() for t in threads):
                break
    except KeyboardInterrupt:
        print("\n[IDS] Arrêt demandé...")
        keyboardInterruption.set()           # signal propre à tous les threads
    finally:
        for thread in threads:
            thread.join(timeout=3)           # timeout pour ne pas bloquer indéfiniment
        print("[IDS] Arrêté.")