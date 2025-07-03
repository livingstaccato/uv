// crates/uv/src/commands/pspf.rs

use std::collections::HashMap;
use std::path::PathBuf;
use std::env;
use std::io::Write; // For writeln! on printer
use anyhow::{Context, Result};
use tracing::debug;

use uv_cli::PspfPackageArgs; // Refers to the revised args for self-unwrapping model
use crate::commands::ExitStatus;
use crate::printer::Printer;
use crate::pspf_packager::{PspPackageInputs, create_pspf_package};
use uv_pspf_format::ConfigJson; // Assuming this is the path after Step 1

/// Package a Python application into PSPF v0.1 format (self-unwrapping uv).
pub(crate) async fn pspf_package(
    args: PspfPackageArgs,
    printer: Printer, // Used for outputting success message
) -> Result<ExitStatus> {
    debug!("Packaging application into PSPF format (self-unwrapping model).");
    debug!("UV binary to use as base (if specified): {:?}", args.uv_binary_to_package);
    debug!("Project dir: {:?}", args.project_dir);
    debug!("Output path: {:?}", args.output_path);
    debug!("Private key: {:?}", args.private_key);
    debug!("Entry point: {}", args.entry_point);
    debug!("Python version: {}", args.python_version);
    debug!("Env mode: {:?}", args.env_mode);
    debug!("Env allowed: {:?}", args.env_allowed);
    debug!("Env set: {:?}", args.env_set);

    let uv_binary_to_package_path = match args.uv_binary_to_package {
        Some(path) => {
            if !path.exists() {
                return Err(anyhow::anyhow!("Specified uv binary to package does not exist: {:?}", path));
            }
            path
        },
        None => env::current_exe().context("Failed to determine current uv executable path to use as package base")?,
    };
    debug!("Using uv binary as base for PSPF: {:?}", uv_binary_to_package_path);

    let config_json = ConfigJson {
        entry_point: args.entry_point,
        python_version: args.python_version,
        env_mode: args.env_mode,
        env_allowed: args.env_allowed,
        env_set: args.env_set.map(|pairs| pairs.into_iter().collect::<HashMap<_,_>>()),
    };

    let package_inputs = PspPackageInputs {
        uv_binary_to_package_path: &uv_binary_to_package_path,
        payload_project_path: &args.project_dir,
        config_json,
        output_path: &args.output_path,
        private_key_pem_path: &args.private_key,
        // TODO: When create_payload_tgz is fully implemented, pass Cache, RegistryClientBuilder etc.
    };

    create_pspf_package(&package_inputs)
        .with_context(|| format!("Failed to create PSPF package at {:?}", args.output_path))?;

    writeln!(
        printer.stdout(),
        "Successfully created PSPF package: {}",
        args.output_path.display()
    )?;

    Ok(ExitStatus::Success)
}
