// crates/uv/src/commands/pspf.rs

use std::collections::HashMap;
use anyhow::Result;
use tracing::debug;
use uv_cli::PspfPackageArgs;
use crate::commands::ExitStatus;
use crate::printer::Printer;
use crate::pspf::{PspPackageInputs, ConfigJson};

/// Package a Python application into PSPF v0.1 format.
pub(crate) async fn pspf_package(
    args: PspfPackageArgs,
    _printer: Printer, // Keep for consistency, might use later
) -> Result<ExitStatus> {
    debug!("Packaging application into PSPF format.");
    debug!("Go launcher: {:?}", args.go_launcher);
    debug!("UV binary: {:?}", args.uv_binary);
    debug!("Project dir: {:?}", args.project_dir);
    debug!("Output path: {:?}", args.output_path);
    debug!("Private key: {:?}", args.private_key);
    debug!("Entry point: {}", args.entry_point);
    debug!("Python version: {}", args.python_version);
    debug!("Env mode: {:?}", args.env_mode);
    debug!("Env allowed: {:?}", args.env_allowed);
    debug!("Env set: {:?}", args.env_set);

    let config_json = ConfigJson {
        entry_point: args.entry_point,
        python_version: args.python_version,
        env_mode: args.env_mode,
        env_allowed: args.env_allowed,
        env_set: args.env_set.map(|pairs| pairs.into_iter().collect::<HashMap<_,_>>()),
    };

    let package_inputs = PspPackageInputs {
        go_launcher_path: &args.go_launcher,
        uv_binary_path: &args.uv_binary,
        payload_project_path: &args.project_dir,
        config_json,
        output_path: &args.output_path,
        private_key_pem_path: &args.private_key,
        // TODO: Pass cache, client, venv if needed by the real `create_payload_tgz`
    };

    crate::pspf::create_pspf_package(&package_inputs)?;

    Ok(ExitStatus::Success)
}
