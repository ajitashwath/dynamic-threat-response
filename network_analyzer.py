import psutil as ps
import socket
import ipaddress
from typing import List, Dict, Any

class NetworkAnalyzer:
    @staticmethod
    def get_network_connections() -> List[Dict[str, Any]]:
        connections = []
        for conn in ps.net_connections():
            try:
                connection_info = {
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'local_address': conn.laddr.ip,
                    'local_port': conn.laddr.port,
                    'remote_address': conn.raddr.ip if conn.raddr else None,
                    'remote_port': conn.raddr.port if conn.raddr else None,
                    'status': conn.status
                }
                connections.append(connection_info)
            except Exception:
                pass
        return connections

    @staticmethod
    def resolve_hostname(ip_address: str) -> str:
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return ip_address

    @staticmethod
    def is_private_ip(ip_address: str) -> bool:
        try:
            return ipaddress.ip_address(ip_address).is_private
        except ValueError:
            return False
