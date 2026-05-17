use std::io::{self, Read};

use app_lib::probe::{run_probe_batch_internal, ProbeDomainInput};

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

    let domains: Vec<ProbeDomainInput> = if input.trim().is_empty() {
        Vec::new()
    } else {
        match serde_json::from_str(&input) {
            Ok(domains) => domains,
            Err(error) => {
                eprintln!("Invalid JSON input: {error}");
                std::process::exit(2);
            }
        }
    };

    match runtime.block_on(run_probe_batch_internal(domains, None, None)) {
        Ok(results) => match serde_json::to_string(&results) {
            Ok(serialized) => {
                println!("{serialized}");
            }
            Err(error) => {
                eprintln!("Failed to serialize results: {error}");
                std::process::exit(3);
            }
        },
        Err(error) => {
            eprintln!("Probe batch failed: {error}");
            std::process::exit(4);
        }
    }
}
