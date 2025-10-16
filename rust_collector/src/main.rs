use serde::Serialize;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use sysinfo::{Pid, System, SystemExt, ProcessExt};

#[derive(Serialize, Debug)] struct ProcessEvent { event_type: String, pid: usize, name: String, exe: String, cmd: String, }
#[derive(Serialize, Debug)] struct UsbEvent { event_type: String, action: String, vendor_id: String, model_id: String, driver: String, }
#[derive(Serialize, Debug, Clone, Eq, PartialEq, Hash)] struct NetworkEvent { event_type: String, local_address: String, remote_address: String, state: String, pid: i32, }
#[derive(Serialize, Debug)] struct FileEvent { event_type: String, action: String, path: String, }
#[derive(Serialize, Debug)] #[serde(untagged)] enum TelemetryEvent { Process(ProcessEvent), Usb(UsbEvent), Network(NetworkEvent), File(FileEvent), }

fn watch_processes(tx: mpsc::Sender<TelemetryEvent>) {
    let mut system = System::new_all();
    let mut known_pids: HashSet<Pid> = system.processes().keys().cloned().collect();
    loop {
        system.refresh_processes();
        for (pid, process) in system.processes() {
            if !known_pids.contains(pid) {
                let event = ProcessEvent { event_type: "process_start".to_string(), pid: (*pid).into(), name: process.name().to_string(), exe: process.exe().to_string_lossy().to_string(), cmd: process.cmd().join(" "), };
                tx.send(TelemetryEvent::Process(event)).unwrap();
                known_pids.insert(*pid);
            }
        }
        thread::sleep(Duration::from_secs(10));
    }
}

fn watch_usb_devices(tx: mpsc::Sender<TelemetryEvent>) {
    let socket = udev::MonitorBuilder::new().unwrap().match_subsystem("usb").unwrap().listen().unwrap();
    for event in socket.iter() {
        let device = event.device();
        let vendor = device.attribute_value("idVendor").unwrap_or_default().to_string_lossy().to_string();
        let model = device.attribute_value("idProduct").unwrap_or_default().to_string_lossy().to_string();
        let driver = device.driver().unwrap_or_default().to_string_lossy().to_string();
        let usb_event = UsbEvent { event_type: "usb_event".to_string(), action: event.action().unwrap_or(OsStr::new("")).to_string_lossy().to_string(), vendor_id: vendor, model_id: model, driver: driver, };
        tx.send(TelemetryEvent::Usb(usb_event)).unwrap();
    }
}

fn watch_network_connections(tx: mpsc::Sender<TelemetryEvent>) {
    let mut known_connections = HashSet::new();
    loop {
        if let Ok(tcp) = procfs::net::tcp() {
            for entry in tcp.iter() {
                let process = procfs::process::Process::new(entry.inode as i32).ok();
                let pid = process.map_or(-1, |p| p.pid);
                let event = NetworkEvent { event_type: "network_conn".to_string(), local_address: format!("{}", entry.local_address), remote_address: format!("{}", entry.remote_address), state: format!("{:?}", entry.state), pid, };
                if !known_connections.contains(&event) {
                    tx.send(TelemetryEvent::Network(event.clone())).unwrap();
                    known_connections.insert(event);
                }
            }
        }
        thread::sleep(Duration::from_secs(20));
    }
}

fn watch_file_system(tx: mpsc::Sender<TelemetryEvent>) {
    use notify::{RecursiveMode, Watcher};
    let (notify_tx, notify_rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(notify_tx).unwrap();
    watcher.watch("/tmp".as_ref(), RecursiveMode::Recursive).unwrap();
    for res in notify_rx {
        if let Ok(event) = res {
            let event_kind_str = format!("{:?}", event.kind);
            for path in event.paths {
                tx.send(TelemetryEvent::File(FileEvent { event_type: "file_event".to_string(), action: event_kind_str.clone(), path: path.to_string_lossy().to_string(), })).unwrap();
            }
        }
    }
}

fn main() {
    let (tx, rx) = mpsc::channel();
    eprintln!("INFO: Rust collector starting...");
    thread::spawn({ let tx = tx.clone(); move || watch_processes(tx) });
    eprintln!("INFO: Process monitor thread started.");
    thread::spawn({ let tx = tx.clone(); move || watch_usb_devices(tx) });
    eprintln!("INFO: USB monitor thread started.");
    thread::spawn({ let tx = tx.clone(); move || watch_network_connections(tx) });
    eprintln!("INFO: Network monitor thread started.");
    thread::spawn({ let tx = tx.clone(); move || watch_file_system(tx) });
    eprintln!("INFO: File monitor thread started for directory: /tmp");
    eprintln!("\n--- Monitoring for system events ---");
    for received_event in rx {
        let json_output = serde_json::to_string(&received_event).unwrap();
        println!("{}", json_output);
    }
}
