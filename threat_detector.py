import re
import socket
import ipaddress
from typing import Dict, List, Any
# Following files
from threat_signatures import ThreatSignatures
from logger import ThreatLogger

class ThreatDetector:
    def __init__(self, logger: ThreatLogger):
        self.signatures = ThreatSignatures()
        self.logger = logger
        self.threat_score = 0
        self.max_threat_score = 100
    
    def analyze_network_connection(self, connection: Dict[str, Any]) -> bool:
        net_sigs = self.signatures.get_network_signatures()
        if connection['remote_address'] in net_sigs.get('blacklisted_ips', []):
            self.logger.log_threat(
                f"Blocked connection to blacklisted IP: {connection['remote_address']}", 
                severity='high'
            )
            self.increment_threat_score(30)
            return True

        if connection['remote_port'] in net_sigs.get('suspicious_ports', []):
            self.logger.log_threat(
                f"Suspicious port detected: {connection['remote_port']}", 
                severity='medium'
            )
            self.increment_threat_score(20)
            return True
        try:
            domain = socket.gethostbyaddr(connection['remote_address'])[0]
            for pattern in self.signatures.signatures['network_patterns']['suspicious_domains']:
                if re.search(pattern, domain, re.IGNORECASE):
                    self.logger.log_threat(
                        f"Suspicious domain detected: {domain}", 
                        severity = 'medium'
                    )
                    self.increment_threat_score(25)
                    return True
        except (socket.herror, socket.gaierror):
            pass
        return False

    def analyze_process(self, process_info: Dict[str, Any]) -> bool:
        process_name = process_info.get('name', '')
        if self.signatures.match_process_name(process_name):
            self.logger.log_threat(
                f"Potentially malicious process detected: {process_name}", 
                severity = 'high'
            )
            self.increment_threat_score(40)
            return True
        return False

    def analyze_file(self, file_path: str) -> bool:
        file_sigs = self.signatures.get_file_signatures()
        file_ext = file_path.split('.')[-1]
        if f".{file_ext}" in file_sigs.get('suspicious_extensions', []):
            self.logger.log_threat(
                f"Suspicious file extension detected: .{file_ext}", 
                severity = 'medium'
            )
            self.increment_threat_score(20)
            return True 
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
                for signature in file_sigs.get('malware_signatures', []):
                    if re.search(signature.encode(), file_content):
                        self.logger.log_threat(
                            f"Malware signature found in file: {file_path}", 
                            severity = 'high'
                        )
                        self.increment_threat_score(50)
                        return True
        except Exception:
            pass

        return False

    def increment_threat_score(self, score: int):
        self.threat_score = min(self.threat_score + score, self.max_threat_score)
        if self.threat_score > 70:
            self.logger.log_threat(
                f"CRITICAL THREAT LEVEL: Threat Score {self.threat_score}", 
                severity = 'critical'
            )

    def reset_threat_score(self):
        self.threat_score = 0