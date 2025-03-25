use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(windows)]
use windows_sys;

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct ThreatTracker {
    events: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    threshold: usize,
}

impl ThreatTracker {
    pub fn new(threshold: usize) -> Self {
        ThreatTracker {
            events: Arc::new(Mutex::new(HashMap::new())),
            threshold,
        }
    }

    pub fn record_event(&self, file_path: String) -> ThreatLevel {
        let mut events = self.events.lock().unwrap();
        let now = Instant::now();
        events.entry(file_path.clone()).and_modify(|v| {
            v.retain(|&event_time| now.duration_since(event_time) < Duration::from_secs(300));
        });
        events.entry(file_path.clone()).or_insert_with(Vec::new).push(now);
        let event_count = events.get(&file_path).map(|v| v.len()).unwrap_or(0);

        match event_count {
            0..=2 => ThreatLevel::Low,
            3..=5 => ThreatLevel::Medium,
            6..=10 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }
}

struct ResponseStrategy {
    threat_level: ThreatLevel,
}

impl ResponseStrategy {
    fn new(threat_level: ThreatLevel) -> Self {
        ResponseStrategy { threat_level }
    }

    fn get_response(&self) -> String {
        match self.threat_level {
            ThreatLevel::Low => "Log and monitor".to_string(),
            ThreatLevel::Medium => "Restrict file access".to_string(),
            ThreatLevel::High => "Quarantine suspicious files".to_string(),
            ThreatLevel::Critical => "Immediate system isolation".to_string(),
        }
    }
}

lazy_static::lazy_static! {
    static ref GLOBAL_THREAT_TRACKER: ThreatTracker = ThreatTracker::new(5);
}

#[no_mangle]
#[cfg(windows)]
pub extern "C" fn check_threat(event_code: i32) -> i32 {
    let file_path = format!("C:\\Temp\\event_{}", event_code);
    let threat_level = GLOBAL_THREAT_TRACKER.record_event(file_path.clone());
    println!("Threat Detection for {}: {:?}", file_path, threat_level);
    match threat_level {
        ThreatLevel::Low => 1,
        ThreatLevel::Medium => 2,
        ThreatLevel::High => 3,
        ThreatLevel::Critical => 4,
    }
}

#[no_mangle]
#[cfg(windows)]
pub extern "C" fn respond_to_threat(threat_level: i32) -> i32 {
    let level = match threat_level {
        1 => ThreatLevel::Low,
        2 => ThreatLevel::Medium,
        3 => ThreatLevel::High,
        4 => ThreatLevel::Critical,
        _ => ThreatLevel::Low,
    };
    let strategy = ResponseStrategy::new(level);
    let response = strategy.get_response();
    println!("Threat Response: {}", response);
    0
}