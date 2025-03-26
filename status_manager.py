# Manages system status updates

from config import SYSTEM_STATUS
from logger import log_status_change

def update_system_status(new_status):
    """Updates the global system status and logs the change."""
    global SYSTEM_STATUS
    SYSTEM_STATUS = new_status
    log_status_change(f"System status updated to: {new_status}")

def get_system_status():
    """Returns the current system status."""
    return SYSTEM_STATUS