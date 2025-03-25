import re
import json
from typing import Dict, List, Any

class ThreatSignatures:
    def __init__(self, config_path = 'signatures.json'):
        self.signatures = self._load_signatures(config_path)

    def _load_signatures(self, config_path: str) -> Dict[str, Any]:
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._default_signatures()

    def _default_signatures(self) -> Dict[str, Any]:
        return {
            "network_threats": {
            "suspicious_ports": [31337, 6667, 8080, 4444, 3389], # Common backdoor ports
                "blacklisted_ips": [
                    "185.153.196.74", "91.121.88.14",       # Known malicious IPs
                    "45.133.193.142", "185.234.217.0/24"
                ]
            },
            "process_threats": {
                "risky_processes": [
                    "nmap", "metasploit", "hydra",      # Common hacking tools
                    "john", "aircrack", "wireshark",
                    "sqlmap", "nikto"
                ],
                "process_patterns": [
                    r".*hack.*", 
                    r".*exploit.*", 
                    r".*shell.*", 
                    r".*reverse.*"
                ]
            },
            "file_threats": {
                "suspicious_extensions": [
                    ".exe", ".bat", ".cmd", ".vbs", 
                    ".ps1", ".dll", ".jar"
                ],
                "malware_signatures": [
                    r"MZ\x90\x00\x03\x00\x00\x00",
                    r"#!msfconsole"
                ]
            },
            "network_patterns": {
                "suspicious_domains": [
                    r".*torrent.*", 
                    r".*proxy.*", 
                    r".*anonymizer.*"
                ],
                "tor_exit_nodes": [
                    "185.220.100.0/24",
                    "85.31.186.0/24"
                ]
            }
        }

    def get_network_signatures(self) -> Dict[str, Any]:
        return self.signatures.get("network_threats", {})

    def get_process_signatures(self) -> Dict[str, Any]:
        return self.signatures.get("process_threats", {})

    def get_file_signatures(self) -> Dict[str, Any]:
        return self.signatures.get("file_threats", {})

    def match_process_name(self, process_name: str) -> bool:
        risky_processes = self.signatures['process_threats']['risky_processes']
        process_patterns = self.signatures['process_threats']['process_patterns']
        if process_name.lower() in [p.lower() for p in risky_processes]:
            return True
        for pattern in process_patterns:
            if re.search(pattern, process_name, re.IGNORECASE):
                return True
        return False
