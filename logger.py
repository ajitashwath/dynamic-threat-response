import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import json
from typing import Dict, Any, Optional

# Logging module to track system changes and events
# Configure logging
logging.basicConfig(
    filename="system.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_status_change(message):
    """Logs status changes in the system."""
    logging.info(message)

    
class ThreatLogger:
    def __init__(
        self,
        log_dir: str = 'logs',
        log_file: str = 'threat_response.log',
        max_log_size: int = 10 * 1024 * 1024,
        backup_count: int = 5
    ):
        os.makedirs(log_dir, exist_ok=True)
        self.log_path = os.path.join(log_dir, log_file)
        self.threat_log_path = os.path.join(log_dir, 'threat_events.json')
        if not os.path.exists(self.threat_log_path):
            with open(self.threat_log_path, 'w') as f:
                f.write('')
        
        self.logger = logging.getLogger('ThreatResponseLogger')
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        file_handler = RotatingFileHandler(
            self.log_path,
            maxBytes=max_log_size,
            backupCount=backup_count
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%H:%M:%S'
        ))

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def log_event(
        self,
        message: str,
        level: str = 'info',
        extra_data: Optional[Dict[str, Any]] = None
    ):
        log_levels = {
            'info': self.logger.info,
            'warning': self.logger.warning,
            'error': self.logger.error,
            'critical': self.logger.critical
        }
        log_func = log_levels.get(level.lower(), self.logger.info)
        log_func(message)
        if extra_data:
            self.logger.info(f"Context: {json.dumps(extra_data)}")

    def log_threat(
        self,
        message: str,
        severity: str = 'low',
        details: Optional[Dict[str, Any]] = None
    ):
        threat_entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'severity': severity.upper(),
            'details': details or {}
        }
        self.logger.warning(f"THREAT: {message}")

        try:
            threats = self.get_recent_threats(limit=None) if os.path.exists(self.threat_log_path) else []
            threats.append(threat_entry)
            with open(self.threat_log_path, 'w') as f:
                json.dump(threats, f, indent=2)
        except IOError as e:
            self.logger.error(f"Could not write to threat log: {e}")
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON error in threat log: {e}")
            # Reset file if corrupted
            with open(self.threat_log_path, 'w') as f:
                json.dump([threat_entry], f, indent=2)
        severity_colors = {
            'LOW': '\033[92m',      # Green
            'MEDIUM': '\033[93m',   # Yellow
            'HIGH': '\033[91m',     # Red
            'CRITICAL': '\033[41m'  # Red Background
        }
        severity_upper = severity.upper()
        color_code = severity_colors.get(severity_upper, '\033[0m')
        print(f"{color_code}THREAT [{severity_upper}]: {message}\033[0m")

    def get_recent_threats(self, limit: int = 10) -> list:
        try:
            with open(self.threat_log_path, 'r') as f:
                content = f.read().strip()
                if not content:
                    return []
                threats = json.loads(content)
                # If limit is None, return all threats
                return threats[-limit:] if limit else threats
        except FileNotFoundError:
            return []
        except json.JSONDecodeError:
            self.logger.error("Threat log file corrupted, resetting")
            with open(self.threat_log_path, 'w') as f:
                f.write('')
            return []

    def clear_logs(self, confirm: bool = False):
        if confirm:
            with open(self.log_path, 'w'):
                pass
            with open(self.threat_log_path, 'w'):
                pass
            self.log_event("Logs have been cleared")