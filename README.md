# Dynamic Threat Response System

## Project Overview
This is a multi-language security monitoring application that:
- Uses `C` to monitor file system events
- Leverages `Rust` for threat detection
- Orchestrates the process using `Python`

## Prerequisites
- GCC (for C compilation)
- Rust (with Cargo)
- Python 3.9+
- Makefile

## Project Structure
```
project_root/
│
├── src/
│   ├── clang/
│   │   ├── Makefile
│   │   └── monitor.c
│   │
│   ├── python/
│   │   ├── main.py
│   │   └── bindings.py
│   │
│   └── rust/
│       ├── Cargo.toml
│       └── lib.rs
```

## Setup and Compilation

### 1. Compile C Library
```bash
cd src/clang
make
```
This creates `../lib/libmonitor.so`

### 2. Compile Rust Library
```bash
cd src/rust
cargo build --release
cp target/release/librustsec.so ../lib/
```

### 3. Prepare Monitoring Directory
```bash
mkdir -p /tmp/test_dir
```

### 4. Run the Application
```bash
cd src/python
python3 main.py
```

## Contributing
CSE316 Project - Dynamic Threat Response System
