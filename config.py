# config.py
# Tous les seuils et constantes du projet — modifier ici, pas dans le code

# Réseau
INTERFACE = None          # None = interface par défaut détectée automatiquement
FLOW_WINDOW_SECONDS = 10  # Durée d'une fenêtre d'agrégation

# Seuils règles signatures
SYN_SCAN_THRESHOLD = 15       # SYN sans ACK en FLOW_WINDOW_SECONDS → scan de ports
SSH_BRUTE_THRESHOLD = 20      # Tentatives SSH en FLOW_WINDOW_SECONDS → brute force
ICMP_FLOOD_THRESHOLD = 100    # Paquets ICMP en FLOW_WINDOW_SECONDS → flood

# Seuil ML
ISOLATION_FOREST_CONTAMINATION = 0.05  # 5% de trafic considéré anormal

# Base de données
DB_PATH = "data/alerts.db"