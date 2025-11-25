//! Owlyshield is an open-source AI-driven behaviour based antiransomware engine designed to run
//!

// #![cfg_attr(debug_assertions, allow(dead_code, unused_imports, unused_variables))]
extern crate num;
#[macro_use]
extern crate num_derive;

#[cfg(feature = "service")]
use std::ffi::OsString; //win
#[cfg(feature = "service")]
use std::sync::mpsc;
#[cfg(feature = "service")]
use std::thread;
//win
#[cfg(feature = "service")]
use std::time::Duration;
#[cfg(feature = "service")]
use crate::mpsc::channel;

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::service_control_handler::ServiceControlHandlerResult;
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
use windows_service::{define_windows_service, service_control_handler, service_dispatcher};

use crate::connectors::register::Connectors;
#[cfg(target_os = "windows")]
use crate::driver_com::Driver;
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use std::{env, path::Path, sync::LazyLock}; // <-- MODIFIED: Removed unused Mutex

// Conditionally compile AVIntegration `use` statement
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
#[path = "windows/av_integration.rs"]
pub mod av_integration;
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use crate::av_integration::AVIntegration;

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use crate::config::Config;

#[cfg(all(target_os = "windows", feature = "hydradragon"))]
use crate::worker::predictor::PredictorMalware;


// Conditionally compile the HYDRA_DRAGON_ENABLED static variable
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub static HYDRA_DRAGON_ENABLED: LazyLock<bool> = LazyLock::new(|| {
    env::var("ProgramFiles")
        .map(|pf| Path::new(&pf).join("HydraDragonAntivirus").exists())
        .unwrap_or(false)
});

// --- ADDED: Static config to provide 'static lifetime ---
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    Config::new()
});

/* --- REMOVED: Static HYDRA_DRAGON_INTEGRATION ---
 * This static block caused error E0277 because AVIntegration (containing TFLite's NonNull pointer)
 * is not `Send`, but the static Mutex required it to be.
 * The `init_hydra_dragon` function below is the correct way to create this instance.
 *
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub static HYDRA_DRAGON_INTEGRATION: LazyLock<Option<Mutex<AVIntegration<'static>>>> = LazyLock::new(|| {
    if *HYDRA_DRAGON_ENABLED {
        // Use the static CONFIG. This provides the 'static lifetime.
        let config: &'static Config = &CONFIG;
        let predictor_malware = PredictorMalware::new(config);
        let av_integration = AVIntegration::new(config, predictor_malware);
        Some(Mutex::new(av_integration)) // Wrap in Mutex for safe access
    } else {
        None
    }
});
*/


/// Initialize AVIntegration at runtime instead of in a `static`
/// Returns `Some(AVIntegration)` when HydraDragon is present, or `None` otherwise.
///
/// IMPORTANT: Do not put `AVIntegration` into a `static Mutex` — the underlying TF-Lite
/// model uses raw pointers (NonNull) that are not `Send/Sync` and will fail `static` requirements.
/// Call this function inside the thread that will use the integration (for example inside `run::run()`).
#[cfg(all(target_os = "windows", feature = "hydradragon"))]
pub fn init_hydra_dragon() -> Option<AVIntegration<'static>> {
    if *HYDRA_DRAGON_ENABLED {
        // Construct the Config and Predictor locally, then build AVIntegration.
        // Use the static CONFIG to provide the 'static lifetime.
        let config: &'static Config = &CONFIG;
        let predictor_malware = PredictorMalware::new(config);
        Some(AVIntegration::new(config, predictor_malware))
    } else {
        None
    }
}

/*
*/

#[cfg(target_os = "windows")]
use crate::driver_com::CDriverMsgs;
#[cfg(target_os = "linux")]
use crate::driver_com::LDriverMsg;
use crate::shared_def::IOMessage;
use crate::logging::Logging;
use crate::worker::process_record_handling::{ExepathLive, ProcessRecordHandlerLive, ProcessRecordHandlerNovelty};
use crate::worker::worker_instance::{IOMsgPostProcessorMqtt, IOMsgPostProcessorRPC, IOMsgPostProcessorWriter, Worker};

mod actions_on_kill;
mod config;
mod connectors;
mod csvwriter;
#[cfg(target_os = "windows")]
#[path = "windows/driver_com.rs"]
mod driver_com;
#[cfg(target_os = "linux")]
#[path = "linux/driver_com.rs"]
mod driver_com;
mod extensions;
mod jsonrpc;
mod logging;
#[cfg(target_os = "windows")]
#[path = "windows/notifications.rs"]
mod notifications;
#[cfg(target_os = "linux")]
#[path = "linux/notifications.rs"]
mod notifications;
mod predictions;
mod process;
#[cfg(target_os = "windows")]
#[path = "windows/run.rs"]
mod run;
#[cfg(target_os = "linux")]
#[path = "linux/run.rs"]
mod run;
mod shared_def;
mod utils;
mod watchlist;
mod whitelist;
mod worker;
mod novelty;
#[cfg(feature = "realtime_learning")]
pub mod realtime_learning;  // OwlyShield realtime-learning module
#[cfg(target_os = "windows")]
#[path = "windows/threathandling.rs"]
mod threathandling;
#[cfg(target_os = "linux")]
#[path = "linux/threathandling.rs"]
mod threathandling;

#[cfg(feature = "service")]
const SERVICE_NAME: &str = "Owlyshield Service";
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
define_windows_service!(ffi_service_main, service_main);

// examples at https://github.com/mullvad/windows-service-rs/tree/master/examples
#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn service_main(arguments: Vec<OsString>) {
    Logging::init();
    std::panic::set_hook(Box::new(|pi| {
        // error!("Critical error: {}", pi);
        println!("{pi}");
        Logging::error(format!("Critical error: {pi}").as_str());
    }));
    // let log_source = "Owlyshield Ransom Rust 2";
    // winlog::register(log_source);
    // winlog::init(log_source).unwrap_or(());
    // info!("Program started.");
    Logging::start();


    if let Err(_e) = run_service(arguments) {
        // error!("Error in run_service.");
        Logging::error("Error in run_service.");
    }
}

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn run_service(_arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
    let (shutdown_tx, shutdown_rx) = channel();
    let shutdown_tx1 = shutdown_tx.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Interrogate => {
                shutdown_tx.send(()).unwrap();
                // info!("Stop event received");
                Logging::stop();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let next_status = ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    // Tell the system that the service is running now
    status_handle.set_service_status(next_status)?;

    thread::spawn(move || {
        let t = thread::spawn(move || {
            run::run();
        })
        .join();
        if t.is_err() {
            shutdown_tx1.send(()).unwrap();
        }
    });

    loop {
        // Poll shutdown event.
        match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
            // Break the loop either upon stop or channel disconnect
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,

            // Continue work if no events were received within the timeout
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        };
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

#[cfg(target_os = "windows")]
#[cfg(feature = "service")]
fn main() -> Result<(), windows_service::Error> {
    // Register generated `ffi_service_main` with the system and start the service, blocking
    // this thread until the service is stopped.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(feature = "service"))]
fn main() {
    //https://patorjk.com/software/taag/#p=display&f=Bloody&t=Owlyshield
    let banner = r#"

 ▒█████   █     █░ ██▓   ▓██   ██▓  ██████  ██░ ██  ██▓▓█████  ██▓    ▓█████▄
▒██▒  ██▒▓█░ █ ░█░▓██▒    ▒██  ██▒▒██    ▒ ▓██░ ██▒▓██▒▓█   ▀ ▓██▒    ▒██▀ ██▌
▒██░  ██▒▒█░ █ ░█ ▒██░     ▒██ ██░░ ▓██▄   ▒██▀▀██░▒██▒▒███   ▒██░    ░██   █▌
▒██   ██░░█░ █ ░█ ▒██░     ░ ▐██▓░  ▒   ██▒░▓█ ░██ ░██░▒▓█  ▄ ▒██░    ░▓█▄   ▌
░ ████▓▒░░░██▒██▓ ░██████▒ ░ ██▒▓░▒██████▒▒░▓█▒░██▓░██░░▒████▒░██████▒░▒████▓
░ ▒░▒░▒░ ░ ▓░▒ ▒  ░ ▒░▓  ░  ██▒▒▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓  ░░ ▒░ ░░ ▒░▓  ░ ▒▒▓  ▒
  ░ ▒ ▒░   ▒ ░ ░  ░ ░ ▒  ░▓██ ░▒░ ░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░ ░  ░░ ░ ▒  ░ ░ ▒  ▒
░ ░ ░ ▒    ░   ░    ░ ░   ▒ ▒ ░░  ░  ░  ░   ░  ░░ ░ ▒ ░   ░     ░ ░    ░ ░  ░
    ░ ░      ░        ░  ░░ ░           ░   ░  ░  ░ ░     ░  ░    ░  ░   ░
                          ░ ░                                          ░

                                                                By SitinCloud
    "#;
    println!("{banner}");

    run::run();
}
