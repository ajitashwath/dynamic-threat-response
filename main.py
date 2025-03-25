import threading
import time

# Following files
from threat_signatures import ThreatSignatures
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

    def start_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(
                target = self._monitoring_loop, 
                daemon = True
            )
            self.monitoring_thread.start()
            self.logger.log_event("Threat Monitoring Started")

    def stop_monitoring(self):
        if self.is_monitoring:
            self.is_monitoring = False
            self.monitoring_thread.join()
            self.logger.log_event("Threat Monitoring Stopped")

    def _monitoring_loop(self):
        while self.is_monitoring:
            network_connections = NetworkAnalyzer.get_network_connections()
            for conn in network_connections:
                self.threat_detector.analyze_network_connection(conn)
            running_processes = ProcessMonitor.get_running_processes()
            for process in running_processes:
                self.threat_detector.analyze_process(process)

            time.sleep(5)

def main():
    threat_system = DynamicThreatResponseSystem()
    ui = ThreatResponseUI(threat_system)
    ui.run()

if __name__ == "__main__":
    main()