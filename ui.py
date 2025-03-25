import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import os

class ThreatResponseUI:
    def __init__(self, threat_system):
        self.threat_system = threat_system
        self.root = tk.Tk()
        self.root.title("Dynamic Threat Response System")
        self.root.geometry("900x700")
        self.root.configure(bg = '#F0F0F0')
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self._create_status_frame()
        self._create_threat_log_frame()
        self._create_control_frame()
        self._create_system_info_frame()

    def _create_status_frame(self):
        status_frame = ttk.Frame(self.root, padding = "10")
        status_frame.pack(fill = tk.X)
        self.system_status_label = ttk.Label(
            status_frame, 
            text = "System Status: SECURE", 
            font = ('Arial', 14, 'bold'),
            foreground = 'green'
        )
        self.system_status_label.pack(side = tk.LEFT)
        self.threat_count_label = ttk.Label(
            status_frame, 
            text = "Active Threats: 0", 
            font = ('Arial', 12)
        )
        self.threat_count_label.pack(side = tk.RIGHT)

    def _create_threat_log_frame(self):
        log_frame = ttk.Frame(self.root, padding = "10")
        log_frame.pack(expand = True, fill = tk.BOTH)
        ttk.Label(
            log_frame, 
            text="Threat Log", 
            font=('Arial', 12, 'bold')
        ).pack(anchor = 'w')
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            wrap = tk.WORD, 
            height = 20, 
            font = ('Consolas', 10)
        )
        self.log_text.pack(expand = True, fill = tk.BOTH)
        self.log_text.tag_config('info', foreground = 'black')
        self.log_text.tag_config('warning', foreground = 'orange')
        self.log_text.tag_config('error', foreground = 'red')
        self.log_text.tag_config('critical', foreground = 'red', background = 'yellow')

    def _create_control_frame(self):
        control_frame = ttk.Frame(self.root, padding = "10")
        control_frame.pack(fill = tk.X)
        self.start_btn = ttk.Button(
            control_frame, 
            text = "Start Monitoring", 
            command = self._start_monitoring
        )
        self.start_btn.pack(side = tk.LEFT, padx = 5)

        self.stop_btn = ttk.Button(
            control_frame, 
            text = "Stop Monitoring", 
            command = self._stop_monitoring,
            state = tk.DISABLED
        )
        self.stop_btn.pack(side = tk.LEFT, padx = 5)
        ttk.Button(
            control_frame, 
            text = "Configure Signatures", 
            command = self._open_signature_config
        ).pack(side = tk.LEFT, padx = 5)

    def _create_system_info_frame(self):
        info_frame = ttk.Frame(self.root, padding = "10")
        info_frame.pack(fill = tk.X)
        self.system_info_label = ttk.Label(
            info_frame, 
            text = "CPU: 0% | Memory: 0% | Disk: 0%", 
            font = ('Arial', 10)
        )
        self.system_info_label.pack(side = tk.LEFT)

    def _start_monitoring(self):
        try:
            self.threat_system.start_monitoring()
            self.system_status_label.config(
                text = "System Status: MONITORING", 
                foreground = 'blue'
            )
            self.start_btn.config(state = tk.DISABLED)
            self.stop_btn.config(state = tk.NORMAL)
            self._start_ui_updates()
        except Exception as e:
            messagebox.showerror("Monitoring Error", str(e))

    def _stop_monitoring(self):
        try:
            self.threat_system.stop_monitoring()
            self.system_status_label.config(
                text = "System Status: SECURE", 
                foreground = 'green'
            )
            self.start_btn.config(state = tk.NORMAL)
            self.stop_btn.config(state = tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Stopping Error", str(e))

    def _start_ui_updates(self):
        def update_loop():
            while self.threat_system.is_monitoring:
                self._update_log()
                self._update_system_info()
                time.sleep(5)
        update_thread = threading.Thread(target = update_loop, daemon = True)
        update_thread.start()

    def _update_log(self):
        try:
            recent_threats = self.threat_system.logger.get_recent_threats()
            self.log_text.delete(1.0, tk.END)
            for threat in recent_threats:
                severity = threat.get('severity', 'INFO').lower()
                message = f"{threat['timestamp']} - {threat['message']}\n"
                tag = 'info'
                if severity == 'warning':
                    tag = 'warning'
                elif severity == 'error':
                    tag = 'error'
                elif severity == 'critical':
                    tag = 'critical'
                self.log_text.insert(tk.END, message, tag)
        except Exception:
            pass

    def _update_system_info(self):
        try:
            import psutil
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            self.system_info_label.config(
                text=f"CPU: {cpu_percent}% | Memory: {memory_percent}% | Disk: {disk_percent}%"
            )
        except Exception:
            pass

    def _open_signature_config(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("Threat Signature Configuration")
        config_window.geometry("600x400")

        ttk.Label(
            config_window, 
            text = "Signature Configuration Interface",
            font = ('Arial', 14)
        ).pack(pady = 20)
        ttk.Label(
            config_window, 
            text = "Manage threat signatures and detection rules"
        ).pack()

    def run(self):
        self.root.mainloop()

def main():
    from main import DynamicThreatResponseSystem
    threat_system = DynamicThreatResponseSystem()
    ui = ThreatResponseUI(threat_system)
    ui.run()

if __name__ == "__main__":
    main()