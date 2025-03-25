import ctypes
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C_LIB_PATH = os.path.join(BASE_DIR, "lib", "libmonitor.dll")
RUST_LIB_PATH = os.path.join(BASE_DIR, "lib", "librustsec.dll")

c_lib = ctypes.CDLL(C_LIB_PATH)
rust_lib = ctypes.CDLL(RUST_LIB_PATH)

c_lib.monitor_directory.argtypes = [ctypes.c_char_p]
c_lib.monitor_directory.restype = ctypes.c_int

rust_lib.check_threat.argtypes = [ctypes.c_int]
rust_lib.check_threat.restype = ctypes.c_int
rust_lib.respond_to_threat.argtypes = []
rust_lib.respond_to_threat.restype = ctypes.c_int

def monitor(path):
    path_bytes = path.encode('utf-8')
    result = c_lib.monitor_directory(path_bytes)
    return result

def detect_threat(event_code):
    return rust_lib.check_threat(event_code)

def respond_to_threat():
    return rust_lib.respond_to_threat()