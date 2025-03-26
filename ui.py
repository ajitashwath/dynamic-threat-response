import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
#import time
#import os
import json
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import logging
from threat_signatures import ThreatSignatures

class ThreatResponseUI:
    def __init__(self, threat_system):
        self.threat_system = threat_system
        self.root = tk.Tk()
        self.root.title("Dynamic Threat Response System")
        self.root.geometry("900x900")
        self.root.configure(bg='#F0F0F0')
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.threat_history = []
        self._create_status_frame()
        self._create_threat_log_frame()
        self._create_graph_frame()
        self._create_control_frame()
        self._create_system_info_frame()

    def _create_status_frame(self):
        status_frame = ttk.Frame(self.root, padding="10")
        status_frame.pack(fill=tk.X)
        self.system_status_label = ttk.Label(
            status_frame,
            text="System Status: SECURE - Threat Level: NORMAL",
            font=('Arial', 14, 'bold'),
            foreground='green'
        )
        self.system_status_label.pack(side=tk.LEFT)
        self.threat_count_label = ttk.Label(
            status_frame,
            text="Active Threats: 0",
            font=('Arial', 12)
        )
        self.threat_count_label.pack(side=tk.RIGHT)

    def _create_threat_log_frame(self):
        log_frame = ttk.Frame(self.root, padding="10")
        log_frame.pack(expand=True, fill=tk.BOTH)
        ttk.Label(
            log_frame,
            text="Threat Log",
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=15,
            font=('Consolas', 10)
        )
        self.log_text.pack(expand=True, fill=tk.BOTH)
        self.log_text.tag_config('info', foreground='black')
        self.log_text.tag_config('warning', foreground='orange')
        self.log_text.tag_config('error', foreground='red')
        self.log_text.tag_config('critical', foreground='red', background='yellow')

    def _create_graph_frame(self):
        graph_frame = ttk.Frame(self.root, padding="10")
        graph_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            graph_frame,
            text="Threat Score Trend",
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        self.fig, self.ax = plt.subplots(figsize=(8, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _create_control_frame(self):
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)
        self.start_btn = ttk.Button(
            control_frame,
            text="Start Monitoring",
            command=self._start_monitoring
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(
            control_frame,
            text="Stop Monitoring",
            command=self._stop_monitoring,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(
            control_frame,
            text="Reset Threat Level",
            command=self._reset_threat_level
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            control_frame,
            text="Configure Signatures",
            command=self._open_signature_config
        ).pack(side=tk.LEFT, padx=5)

    def _create_system_info_frame(self):
        info_frame = ttk.Frame(self.root, padding="10")
        info_frame.pack(fill=tk.X)
        self.system_info_label = ttk.Label(
            info_frame,
            text="CPU: 0% | Memory: 0% | Disk: 0% | Threads: 0",
            font=('Arial', 10)
        )
        self.system_info_label.pack(side=tk.LEFT)

    def _start_monitoring(self):
        if self.threat_system.start_monitoring():
            current_status = self.threat_system.system_status
            self.system_status_label.config(
                text=f"System Status: MONITORING - Threat Level: {current_status}",
                foreground='blue' if current_status == "Normal" else 'red'
            )
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self._start_ui_updates()  # Start periodic UI updates

    def _stop_monitoring(self):
        try:
            if self.threat_system.stop_monitoring():
                self.system_status_label.config(
                    text="System Status: SECURE",
                    foreground='green'
                )
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Stopping Error", str(e))

    def _start_ui_updates(self):
        def update_ui():
            if self.threat_system.is_monitoring:
                try:
                    self._update_log()
                    self._update_system_info()
                    self._update_graph()
                    current_status = self.threat_system.system_status
                    self.system_status_label.config(
                        text=f"System Status: MONITORING - Threat Level: {current_status}",
                        foreground='blue' if current_status == "Normal" else 'red'
                    )
                except Exception as e:
                    print(f"UI update error: {e}")
                self.root.after(1000, update_ui)
        self.root.after(0, update_ui)

    def _reset_threat_level(self):
        self.threat_system.threat_detector.reset_threat_score()
        self.system_status_label.config(
            text="System Status: MONITORING - Threat Level: Normal",
            foreground='blue'
        )
        self.threat_history = []

    def _update_log(self):
        try:
            recent_threats = self.threat_system.logger.get_recent_threats(limit=50)
            self.log_text.delete(1.0, tk.END)
            threat_count = 0
            for threat in recent_threats:
                severity = threat.get('severity', 'INFO').lower()
                message = f"{threat['timestamp']} - {threat['message']} (Severity: {severity.upper()})\n"
                tag = 'info'
                if severity == 'medium':
                    tag = 'warning'
                elif severity in ('high', 'critical'):
                    tag = 'critical' if severity == 'critical' else 'error'
                self.log_text.insert(tk.END, message, tag)
                threat_count += 1
            self.threat_count_label.config(text=f"Active Threats: {threat_count}")
        except Exception as e:
            self.threat_system.logger.log_event(f"Log update error: {e}", level='error')

    def _update_system_info(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=None)  # Measures since last call (~1s)
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            thread_count = threading.active_count()  # Get active thread count
            self.system_info_label.config(
                text=f"CPU: {cpu_percent}% | Memory: {memory_percent}% | Disk: {disk_percent}% | Threads: {thread_count}"
            )
        except Exception as e:
            self.threat_system.logger.log_event(f"System info update error: {e}", level='error')

    def _update_graph(self):
        try:
            score = self.threat_system.threat_detector.threat_score
            self.threat_history.append(score)
            if len(self.threat_history) > 50:
                self.threat_history.pop(0)
            self.ax.clear()
            self.ax.plot(self.threat_history, 'r-', label='Threat Score')
            self.ax.set_ylim(0, 100)
            self.ax.set_title('Threat Score Over Time')
            self.ax.set_xlabel('Time (s)')
            self.ax.set_ylabel('Score')
            self.ax.legend()
            self.canvas.draw()
        except Exception as e:
            self.threat_system.logger.log_event(f"Graph update error: {e}", level='error')

    def _open_signature_config(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("Threat Signature Configuration")
        config_window.geometry("600x400")
        sig_frame = ttk.Frame(config_window, padding="10")
        sig_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            sig_frame,
            text="Edit Threat Signatures (JSON format):",
            font=('Arial', 12, 'bold')
        ).pack(anchor='w')
        sig_text = scrolledtext.ScrolledText(sig_frame, wrap=tk.WORD, height=15)
        sig_text.pack(fill=tk.BOTH, expand=True)
        try:
            with open('signatures.json', 'r') as f:
                sig_text.insert(tk.END, json.dumps(json.load(f), indent=2))
        except FileNotFoundError:
            sig_text.insert(tk.END, json.dumps(self.threat_system.threat_detector.signatures.signatures, indent=2))
        def save_signatures():
            try:
                new_sigs = json.loads(sig_text.get(1.0, tk.END))
                with open('signatures.json', 'w') as f:
                    json.dump(new_sigs, f, indent=2)
                self.threat_system.threat_detector.signatures = ThreatSignatures()
                messagebox.showinfo("Success", "Signatures updated successfully")
            except json.JSONDecodeError as e:
                messagebox.showerror("Error", f"Invalid JSON format: {e}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save signatures: {e}")
        ttk.Button(sig_frame, text="Save Signatures", command=save_signatures).pack(pady=5)

    def run(self):
        self.root.mainloop()

def main():
    from main import DynamicThreatResponseSystem
    threat_system = DynamicThreatResponseSystem()
    ui = ThreatResponseUI(threat_system)
    ui.run()

if __name__ == "__main__":
    main()