import os
import json
from typing import Dict, Any

class SystemConfig:
    def __init__(self, config_path: str = 'config.json'):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        default_config = {
            "monitoring": {
                "scan_interval": 5,
                "auto_start": False
            },
            "logging": {
                "log_dir": "logs",
                "max_log_size": 10485760,
                "backup_count": 5
            },
            "threat_detection": {
                "sensitivity": "medium",
                "auto_mitigate": True
            },
            "notifications": {
                "email_alerts": False,
                "email_recipient": "",
                "sms_alerts": False,
                "phone_number": ""
            }
        }
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    self._deep_merge(default_config, user_config)
            else:
                with open(self.config_path, 'w') as f:
                    json.dump(default_config, f, indent=4)
        except (IOError, json.JSONDecodeError):
            pass
        return default_config

    def _deep_merge(self, base: Dict, update: Dict):
        for key, value in update.items():
            if isinstance(value, dict):
                base[key] = self._deep_merge(base.get(key, {}), value)
            else:
                base[key] = value
        return base

    def get(self, key: str, default=None):
        keys = key.split('.')
        config = self.config
        for k in keys:
            if isinstance(config, dict):
                config = config.get(k, default)
            else:
                return default
        return config

    def update(self, key: str, value: Any):
        keys = key.split('.')
        config = self.config
        for k in keys[: -1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value
        self._save_config()

    def _save_config(self):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent = 4)
        except IOError:
            print(f"Could not save configuration to {self.config_path}")

'''
def main():
    config = SystemConfig()
    
    # Get configuration values
    print("Scan Interval:", config.get('monitoring.scan_interval'))
    
    # Update configuration
    config.update('monitoring.scan_interval', 10)
    config.update('notifications.email_alerts', True)

if __name__ == "__main__":
    main()'
'''