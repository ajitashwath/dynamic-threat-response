import ctypes
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C_LIB_PATH = os.path.join(BASE_DIR, "lib", "libmonitor.dll")
RUST_LIB_PATH = os.path.join(BASE_DIR, "lib", "librustsec.dll")

CALLBACK_TYPE = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_char_p)

c_lib = ctypes.CDLL(C_LIB_PATH)
rust_lib = ctypes.CDLL(RUST_LIB_PATH)

c_lib.monitor_directory.argtypes = [ctypes.c_char_p, CALLBACK_TYPE]
c_lib.monitor_directory.restype = ctypes.c_int

rust_lib.check_threat.argtypes = [ctypes.c_int]
rust_lib.check_threat.restype = ctypes.c_int

def monitor(path, callback=None):
    path_bytes = path.encode('utf-8')
    if callback is None:
        def default_callback(path, filename):
            pass
        callback = default_callback
    c_callback = CALLBACK_TYPE(callback)
    result = c_lib.monitor_directory(path_bytes, c_callback)
    return result

def detect_threat(event_code):
    return rust_lib.check_threat(event_code)

def respond_to_threat():
    return rust_lib.respond_to_threat()