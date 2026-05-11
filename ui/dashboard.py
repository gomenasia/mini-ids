"""visuelle de l'ids"""
import time
from datetime import datetime
from rich.live import Live
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from config import keyboardInterruption, INTERFACE, FLOW_WINDOW_SECONDS

console = Console()

class Dashboard:
    def __init__(self, collector, flow_builder, db):
        self.collector = collector
        self.flow_builder = flow_builder
        self.db = db

    def make_layout(self) -> Layout:
        """Define the layout."""
        layout = Layout(name="root")

        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=4),
        )
        layout["main"].split_row(
            Layout(name="batch"),
            Layout(name="alert", ratio=2, minimum_size=60),
        )
        layout["footer"].split_row(
            Layout(name="packet"),
            Layout(name="config", ratio=1),
        )
        return layout

    def make_packet_display(self) -> Panel:
        pkt_display = Table.grid()
        dropped = self.collector.dropped_count
        handle = self.collector.packets_count - dropped
        if handle != 0:
            pkt_display.add_row(
                "handle:" + str(handle) + " | dropped:" +
                str(dropped) + " | drope rate:" + str(int((dropped * 100)/handle)) + "%"
            )
        else:
            pkt_display.add_row(
                "handle:" + str(handle) + " | dropped:" +
                str(dropped) + " | drope rate 0%"
            )
        pkt_display.add_row(
            str(self.collector.current_pkt)
        )
        return Panel(pkt_display,
                    border_style="yellow",
                    title="Packets")

    def make_alert_display(self) -> Panel:
        alert_dislpay = Table.grid()

        cursor = self.db.cursor
        cursor.execute(
            """
            SELECT *
            FROM Alert
            ORDER BY timestamp
            LIMIT 10
            """
        )
        alerts = cursor.fetchall()

        for row in alerts:
            alert = Table.grid()
            alert.add_column("src_ip", justify="left")
            alert.add_column("alert_type", justify="center")
            alert.add_column("timestamp", justify="right")

            alert.add_row(row["src_ip"], row["alert_type"], row["timestamp"])
            couleur_severiter = "green"
            match row["severite"]:
                case 1:
                    couleur_severiter = "yellow"
                case 2:
                    couleur_severiter = "rgb(255,153,51)"
                case 3:
                    couleur_severiter = "red"
                case _:
                    pass

            alert_dislpay.add_row(Panel(alert, border_style=couleur_severiter))

        return Panel(alert_dislpay, 
                    border_style="cyan",
                    title="[b blue] Alerts Display")

    def make_batch_display(self) -> Panel:
        batch_display = Table.grid()

        delta = datetime.now() - self.flow_builder.batch.timestamp_start
        pourcentage = int(int(delta.total_seconds())/FLOW_WINDOW_SECONDS)

        batch_progress = Progress(
            "{task.description}",
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        progress = batch_progress.add_task("[magenta]Progress", total=100)
        batch_progress.advance(progress, pourcentage)

        batch_display.add_row(batch_progress)
        batch_display.add_row("test")

        return Panel(batch_display,
                    title="Current Batch")

    def make_config_display(self) -> Panel:
        return Panel("panel",
                    title="Config")

    def header(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="left")
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(
            "interface:" + (str(INTERFACE) or "eth0"),
            "[b] IDS Dashboard",
            datetime.now().ctime().replace(":", "[blink]:[/]"),
        )
        return Panel(grid)

    def init_layout(self) -> Layout:
        """initialise le layout"""
        layout = self.make_layout()
        layout["header"].update(self.header())
        layout["alert"].update(self.make_alert_display())
        layout["batch"].update(self.make_batch_display())
        layout["packet"].update(self.make_packet_display())
        layout["config"].update(self.make_config_display())
        return layout

    def start(self):
        layout = self.init_layout()

        try:
            with Live(layout, refresh_per_second=10, screen=False) as live:
                while not keyboardInterruption.is_set():
                    try:
                        layout["header"].update(self.header())
                        layout["alert"].update(self.make_alert_display())
                        layout["batch"].update(self.make_batch_display())
                        layout["packet"].update(self.make_packet_display())
                        layout["config"].update(self.make_config_display())
                        time.sleep(0.1)
                    except Exception as e:
                        live.console.print(f"[DASHBOARD] ERREUR: {e}")
        except KeyboardInterrupt:
            keyboardInterruption.set()   # sécurité si le signal arrive ici
