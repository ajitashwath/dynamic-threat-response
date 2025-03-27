import threading
import time
#import traceback
# Following files
#from threat_signatures import ThreatSignatures
from threat_detector import ThreatDetector
from network_analyzer import NetworkAnalyzer
from process_monitor import ProcessMonitor
from ui import ThreatResponseUI
from logger import ThreatLogger

class DynamicThreatResponseSystem:
    def __init__(self):
        self.logger = ThreatLogger()
        self.threat_detector = ThreatDetector(self.logger)
        self.is_monitoring = False
        self.monitoring_thread = None
        self.system_status = "SAFE"

    def update_system_status(self, new_status):
        if new_status != self.system_status:
            self.system_status = new_status
            self.logger.log_event(f"System status updated to: {new_status}")

    def start_monitoring(self):
        if not self.is_monitoring:
            try:
                self.is_monitoring = True
                self.monitoring_thread = threading.Thread(
                    target=self._monitoring_loop,
                    daemon=True
                )
                self.monitoring_thread.start()
                self.logger.log_event("Threat Monitoring Started")
                return True
            except Exception as e:
                self.logger.log_event(f"Failed to start monitoring: {e}", level='error')
                self.is_monitoring = False
                return False
        return False
    
    def reset_threat_level(self):
        self.threat_detector.reset_threat_score()
        self.update_system_status("Normal")

    def stop_monitoring(self):
        if self.is_monitoring:
            try:
                self.is_monitoring = False
                if self.monitoring_thread:
                    self.monitoring_thread.join(timeout=5)  
                    if self.monitoring_thread.is_alive():
                        self.logger.log_event("Warning: Monitoring thread still alive", level='warning')
                self.logger.log_event("Threat Monitoring Stopped")
                return True
            except Exception as e:
                self.logger.log_event(f"Error stopping monitoring: {e}", level='error')
                return False
        return False

    def _monitoring_loop(self):
        while self.is_monitoring:
            try:
                network_connections = NetworkAnalyzer.get_network_connections()
                for conn in network_connections:
                    if self.threat_detector.analyze_network_connection(conn):
                        pass  # Logging handled inside analyze_network_connection
                running_processes = ProcessMonitor.get_running_processes()
                for process in running_processes:
                    self.threat_detector.analyze_process(process)
                # Update status based on threat score after analysis
                if self.threat_detector.threat_score > 70:
                    self.update_system_status("Danger")
                else:
                    self.update_system_status("Normal")
                time.sleep(5)
            except Exception as e:
                self.logger.log_event(f"Monitoring loop critical error: {e}", level='critical')

def main():
    threat_system = DynamicThreatResponseSystem()
    ui = ThreatResponseUI(threat_system)
    ui.run()

if __name__ == "__main__":
    main()