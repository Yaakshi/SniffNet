import tkinter as tk
from tkinter import ttk, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from threading import Thread
import time

from sniffer import start_sniffing, packet_queue

from alert import alert_queue

# === GUI Setup ===

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - Real-Time Monitor")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        self.traffic_data = []
        self.alerts = []

        self.alert_active = False
        self.last_alert_time = 0
        self.alert_color_duration = 5  # seconds

        self.setup_ui()
        self.update_gui()

        # Start sniffer thread
        Thread(target=start_sniffing, daemon=True).start()

    def setup_ui(self):
        # === Graph Frame ===
        graph_frame = tk.Frame(self.root)
        graph_frame.pack(fill=tk.BOTH, expand=False)

        self.figure = Figure(figsize=(6, 2), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title("Packets per Second")
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Packets")
        self.line, = self.ax.plot([], [], color='green')

        self.canvas = FigureCanvasTkAgg(self.figure, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # === Alerts Frame ===
        alert_frame = tk.LabelFrame(self.root, text="Live Alerts", padx=10, pady=10)
        alert_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.alert_box = scrolledtext.ScrolledText(alert_frame, wrap=tk.WORD, height=20, state='disabled')
        self.alert_box.pack(fill=tk.BOTH, expand=True)

        # === Button Panel ===
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        export_btn = tk.Button(btn_frame, text="Export to CSV", command=self.export_csv)
        export_btn.pack(side=tk.LEFT, padx=10)

        clear_btn = tk.Button(btn_frame, text="Clear Alerts", command=self.clear_alerts)
        clear_btn.pack(side=tk.LEFT, padx=10)


    def export_csv(self):
        from exporter import export_to_csv
        export_to_csv()
        self.show_alert("Exported traffic to CSV.")

    def clear_alerts(self):
        self.alert_box.config(state='normal')
        self.alert_box.delete(1.0, tk.END)
        self.alert_box.config(state='disabled')

    def update_gui(self):
        # === Real-time Packet Rate ===
        now = int(time.time())
        packet_count = 0

        while not packet_queue.empty():
            pkt = packet_queue.get()
            pkt_time = int(time.mktime(time.strptime(pkt["timestamp"], "%Y-%m-%d %H:%M:%S")))
            if pkt_time == now:
                packet_count += 1

            # Display alert if anomaly was detected
            # You could expand this to pull alerts from analyzer directly
            # if "anomaly" in pkt.get("details", {}):
            #     self.show_alert(pkt["details"]["anomaly"])
            # Pull from alert queue
            while not alert_queue.empty():
                alert_msg = alert_queue.get()
                self.show_alert(alert_msg)


        self.traffic_data.append((now, packet_count))
        self.traffic_data = self.traffic_data[-30:]  # last 30 seconds

        x_vals = [t[0] - self.traffic_data[0][0] for t in self.traffic_data]
        y_vals = [t[1] for t in self.traffic_data]

        # Determine line color based on alert state
        if self.alert_active and (time.time() - self.last_alert_time) < self.alert_color_duration:
            self.line.set_color('red')
        else:
            self.line.set_color('green')
            self.alert_active = False  # Reset alert flag

        self.line.set_xdata(x_vals)
        self.line.set_ydata(y_vals)
        self.ax.set_xlim(0, max(10, len(x_vals)))
        self.ax.set_ylim(0, max(10, max(y_vals, default=1)))
        self.canvas.draw()

        self.root.after(1000, self.update_gui)

    def show_alert(self, text):
        self.alert_active = True
        self.last_alert_time = time.time()

        self.alert_box.config(state='normal')
        self.alert_box.insert(tk.END, f"{text}\n")
        self.alert_box.see(tk.END)
        self.alert_box.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
