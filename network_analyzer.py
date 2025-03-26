import psutil
import socket
import ipaddress
from typing import List, Dict, Any

class NetworkAnalyzer:
    @staticmethod
    def get_network_connections() -> List[Dict[str, Any]]:
        connections = []
        try:
            for conn in psutil.net_connections(kind = 'inet'):  
                try:
                    connection_info = {
                        'fd': conn.fd if conn.fd != -1 else None,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'local_address': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_address': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    connections.append(connection_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
                    print(f"Error processing connection: {e}")
            return connections
        except Exception as e:
            print(f"Failed to retrieve network connections: {e}")
            return []

    @staticmethod
    def resolve_hostname(ip_address: str) -> str:
        if not ip_address or NetworkAnalyzer.is_private_ip(ip_address):
            return ip_address
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror, socket.timeout):
            return ip_address

    @staticmethod
    def is_private_ip(ip_address: str) -> bool:
        try:
            return ipaddress.ip_address(ip_address).is_private
        except ValueError:
            return False

    @staticmethod
    def get_connection_details(pid: int) -> Dict[str, Any]:
        try:
            process = psutil.Process(pid)
            connections = process.net_connections(kind = 'inet')
            return {
                'pid': pid,
                'name': process.name(),
                'connections': [
                    {
                        'local_address': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_address': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status
                    } for conn in connections
                ]
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}