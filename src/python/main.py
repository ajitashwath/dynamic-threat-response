import threading
import time
from bindings import monitor, detect_threat, respond_to_threat

def start_monitoring(path = "/tmp/test_dir"):
    print(f"Starting to monitor {path}...")
    event_code = monitor(path)
    return event_code

def main():
    monitor_path = "/tmp/test_dir" # Replace with actual path to monitor
    monitor_thread = threading.Thread(target = start_monitoring, args = (monitor_path,), daemon = True)
    monitor_thread.start()
    print("Dynamic Threat Response System running...")
    while True:
        event_code = 1 
        if monitor_thread.is_alive():
            threat_detected = detect_threat(event_code)
            if threat_detected == 1:
                print("Threat confirmed! Taking action...")
                respond_to_threat()
            else:
                print("No threat detected.")
        time.sleep(1) 

if __name__ == "__main__":
    main()