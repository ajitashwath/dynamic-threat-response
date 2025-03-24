import os
import sys
import threading
import time
import logging
from dataclasses import dataclass
from typing import Optional, Callable
from bindings import monitor, detect_threat, respond_to_threat

logging.basicConfig(
    level = logging.INFO,
    format = '%(asctime)s - %(levelname)s - %(message)s',
    handlers = [
        logging.FileHandler('threat_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class MonitorConfig:
    path: str = "/tmp/test_dir"
    scan_interval: float = 1.0
    max_retries: int = 3
    timeout: float = 30.0

class ThreatMonitor:
    def __init__(self, config: MonitorConfig = MonitorConfig()):
        self.config = config
        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self._prepare_monitor_directory()

    def _prepare_monitor_directory(self):
        try:
            os.makedirs(self.config.path, exist_ok = True)
            logger.info(f"Monitoring directory prepared: {self.config.path}")
        except Exception as e:
            logger.error(f"Failed to create monitoring directory: {e}")
            raise

    def _monitor_directory(self):
        retry_count = 0
        while not self.stop_event.is_set():
            try:
                event_code = monitor(self.config.path)
                if event_code != 0:
                    self._handle_potential_threat(event_code)
                retry_count = 0
                time.sleep(self.config.scan_interval)
            
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                retry_count += 1
                if retry_count > self.config.max_retries:
                    logger.critical("Exceeded maximum retry attempts. Stopping monitoring.")
                    break
        
                # Exponential backoff
                wait_time = min(2 ** retry_count, self.config.timeout)
                logger.warning(f"Retrying in {wait_time} seconds (Attempt {retry_count})")
                time.sleep(wait_time)

    def _handle_potential_threat(self, event_code: int):
        try:
            threat_detected = detect_threat(event_code)
            if threat_detected:
                logger.warning(f"Potential threat detected! Event code: {event_code}")
                response_result = respond_to_threat()
                if response_result == 0:
                    logger.info("Threat response successful")
                else:
                    logger.error("Threat response failed")
            else:
                logger.info(f"Event processed. No immediate threat. Event code: {event_code}")
        except Exception as e:
            logger.error(f"Error handling potential threat: {e}")

    def start(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            logger.warning("Monitoring is already running")
            return
        logger.info("Starting threat monitoring system...")
        self.stop_event.clear()
        self.monitor_thread = threading.Thread(
            target = self._monitor_directory, 
            daemon = True
        )
        self.monitor_thread.start()

    def stop(self):
        logger.info("Stopping threat monitoring system...")
        self.stop_event.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout = 5)
            if self.monitor_thread.is_alive():
                logger.warning("Failed to stop monitoring thread")

def main():
    try:
        monitor_config = MonitorConfig(
            path = "/tmp/test_dir",
            scan_interval = 1.0,
            max_retries = 3
        )
        threat_monitor = ThreatMonitor(monitor_config)
        threat_monitor.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received interrupt. Shutting down...")
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}")
    finally:
        threat_monitor.stop()

if __name__ == "__main__":
    main()