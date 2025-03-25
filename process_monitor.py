import psutil
import os
from typing import List, Dict, Any

class ProcessMonitor:
    @staticmethod
    def get_running_processes() -> List[Dict[str, Any]]:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                process_info = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'executable_path': proc.info['exe'],
                    'command_line': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'start_time': proc.info['create_time']
                }
                processes.append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes

    @staticmethod
    def get_process_details(pid: int) -> Dict[str, Any]:
        try:
            process = psutil.Process(pid)
            return {
                'pid': process.pid,
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'status': process.status(),
                'username': process.username(),
                'memory_info': process.memory_info(),
                'cpu_percent': process.cpu_percent()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}