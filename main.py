"""Point d'entrer de l'ids"""

from capture.sniffer import PacketCollector
# ── Point d'entrée ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    collector = PacketCollector()
    try:
        collector.start(iface="eth0", bpf_filter="ip")
    except KeyboardInterrupt:
        print(f"\n{len(collector.packets)} paquets capturés.")