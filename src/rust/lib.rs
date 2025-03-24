#[no_mangle]

pub extern "C" fn check_threat(event_code: i32) -> i32 {
    println!("Rust: Received event code {}", event_code);
    if event_code == 1 {
        println!("Rust: Threat detected!");
        return 1;
    }
    println!("Rust: No threat detected.");
    0
}

#[no_mangle]
pub extern "C" fn respond_to_threat() -> i32 {
    println!("Rust: Responding to threat...");
    0 //Success
}