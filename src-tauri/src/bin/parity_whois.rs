use std::io::{self, Read};

use app_lib::probe::run_probe_whois_internal;

fn main() {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Failed to create Tokio runtime: {error}");
            std::process::exit(5);
        }
    };

    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("Failed to read stdin: {error}");
        std::process::exit(1);
    }

    let domain = input.trim().to_string();

    let result = runtime.block_on(run_probe_whois_internal(domain));
    match serde_json::to_string(&result) {
        Ok(serialized) => {
            println!("{serialized}");
        }
        Err(error) => {
            eprintln!("Failed to serialize result: {error}");
            std::process::exit(3);
        }
    }
}
