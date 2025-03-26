import re
import socket
import ipaddress
from typing import Dict, List, Any
# Following files
from threat_signatures import ThreatSignatures
from logger import ThreatLogger
from network_analyzer import NetworkAnalyzer

class ThreatDetector:
    def __init__(self, logger: ThreatLogger):
        self.signatures = ThreatSignatures()
        self.logger = logger
        self.threat_score = 0
        self.max_threat_score = 100

    def analyze_network_connection(self, connection: Dict[str, Any]) -> bool:
        if not connection or not isinstance(connection, dict):
            self.logger.log_event("Invalid network connection data received", level='warning')
            return False

        remote_address = connection.get('remote_address')
        remote_port = connection.get('remote_port')

        if not self._validate_ip_address(remote_address):
            self.logger.log_event(
                f"Invalid IP address: {remote_address}", 
                level='warning'
            )
            return False

        if not remote_port:
            self.logger.log_event(
                f"Skipping analysis: incomplete connection data - {connection}", 
                level='warning'
            )
            return False

        net_sigs = self.signatures.get_network_signatures()
        if self._is_ip_blacklisted(remote_address, net_sigs.get('blacklisted_ips', [])):
            self.logger.log_threat(
                f"Blocked connection to blacklisted IP: {remote_address}",
                severity='high',
                details=connection
            )
            self.increment_threat_score(30)
            return True

        if remote_port in net_sigs.get('suspicious_ports', []):
            self.logger.log_threat(
                f"Suspicious port detected: {remote_port}",
                severity='medium',
                details=connection
            )
            self.increment_threat_score(20)
            return True

        return False

    
    def _validate_ip_address(self, ip_address: str) -> bool:
        if not ip_address or not isinstance(ip_address, str):
            return False
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def _resolve_domain(self, ip_address: str, timeout: float = 1.0) -> str:
        if not ip_address or not isinstance(ip_address, str):
            return ip_address

        try:
            socket.setdefaulttimeout(timeout)
            domain = socket.gethostbyaddr(ip_address)[0]
            return domain
        except (socket.herror, socket.gaierror, socket.timeout):
            # Fallback: try reverse DNS lookup
            try:
                return socket.getfqdn(ip_address)
            except Exception:
                # If all methods fail, return the original IP
                return ip_address
    
    def _is_ip_blacklisted(self, ip: str, blacklist: List[str]) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for blocked_range in blacklist:
                try:
                    if '/' in blocked_range:
                        # CIDR notation check
                        network = ipaddress.ip_network(blocked_range, strict=False)
                        if ip_obj in network:
                            return True
                    elif ip == blocked_range:
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            return False

    def analyze_process(self, process_info: Dict[str, Any]) -> bool:
        if not process_info or not isinstance(process_info, dict):
            self.logger.log_event(
                "Invalid process information received", 
                level='warning'
            )
            return False

        process_name = process_info.get('name', '')
        if not process_name:
            self.logger.log_event(
                "Skipping process analysis: No process name", 
                level='warning'
            )
            return False

        if self.signatures.match_process_name(process_name):
            self.logger.log_threat(
                f"Potentially malicious process detected: {process_name}", 
                severity='high'
            )
            self.increment_threat_score(40)
            return True
        return False

    def analyze_file(self, file_path: str) -> bool:
        if not file_path or not isinstance(file_path, str):
            self.logger.log_event(
                "Invalid file path received for analysis", 
                level='warning'
            )
            return False

        file_sigs = self.signatures.get_file_signatures()
        
        try:
            # Extract file extension safely
            file_ext = file_path.split('.')[-1] if '.' in file_path else ''
            
            # Check for suspicious file extensions
            if f".{file_ext}" in file_sigs.get('suspicious_extensions', []):
                self.logger.log_threat(
                    f"Suspicious file extension detected: .{file_ext}", 
                    severity='medium'
                )
                self.increment_threat_score(20)
                return True 
            
            # Check for malware signatures in file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
                for signature in file_sigs.get('malware_signatures', []):
                    if re.search(signature.encode(), file_content):
                        self.logger.log_threat(
                            f"Malware signature found in file: {file_path}", 
                            severity='high'
                        )
                        self.increment_threat_score(50)
                        return True
        except FileNotFoundError:
            self.logger.log_event(
                f"File not found during analysis: {file_path}", 
                level='warning'
            )
        except PermissionError:
            self.logger.log_event(
                f"Permission denied accessing file: {file_path}", 
                level='warning'
            )
        except Exception as e:
            self.logger.log_event(
                f"Error analyzing file {file_path}: {str(e)}", 
                level='warning'
            )

        return False

    def increment_threat_score(self, score: int):
        with self.threat_score_lock:
            self.threat_score = min(self.threat_score + score, self.max_threat_score)
            
            # Limit threat history to last 50 entries
            self.threat_history.append(self.threat_score)
            if len(self.threat_history) > 50:
                self.threat_history.pop(0)
            
            if self.threat_score > 70:
                self.logger.log_threat(
                    f"CRITICAL THREAT LEVEL: Threat Score {self.threat_score}", 
                    severity='critical'
                )
    def get_threat_history(self):
        with self.threat_score_lock:
            return self.threat_history.copy()

    def reset_threat_score(self):
        with self.threat_score_lock:
            self.threat_score = 0
            self.threat_history.clear()

'''
def main():
    from logger import ThreatLogger
    
    # Create logger and threat detector for testing
    logger = ThreatLogger()
    threat_detector = ThreatDetector(logger)
    
    # Example network connection test
    test_connections = [
        {
            'remote_address': '8.8.8.8',  # Google DNS
            'remote_port': 53
        },
        {
            'remote_address': None,  # Invalid connection
            'remote_port': None
        }
    ]
    
    # Analyze test connections
    for connection in test_connections:
        print(f"Analyzing connection: {connection}")
        threat_detected = threat_detector.analyze_network_connection(connection)
        print(f"Threat detected: {threat_detected}\n")
    
    # Example process test
    test_processes = [
        {'name': 'normal_process'},
        {'name': 'suspicious_process'},
        {}  # Invalid process
    ]
    
    # Analyze test processes
    for process in test_processes:
        print(f"Analyzing process: {process}")
        process_threat = threat_detector.analyze_process(process)
        print(f"Process threat detected: {process_threat}\n")

if __name__ == "__main__":
    main()'
'''