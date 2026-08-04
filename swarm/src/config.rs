//! Deployment-specific settings.
//!
//! The fuzzing campaign used to assume the repository lives at
//! `/root/TA_GP_emulator` and that the emulator image is called `ta_emu`.
//! Both are now configurable so the artifact can be run from any checkout:
//!
//! ```sh
//! TAEMU_ROOT=$(pwd)/.. TAEMU_IMAGE=ta_emu_ae cargo run -- -t .. -d 15 -s
//! ```
use std::env;
use std::path::PathBuf;

pub const DEFAULT_ROOT: &str = "/root/TA_GP_emulator";
pub const DEFAULT_IMAGE: &str = "ta_emu";

/// Absolute path of the repository on the *host*. It is bind-mounted to /srv
/// inside every emulator container.
pub fn repo_root() -> PathBuf {
    match env::var("TAEMU_ROOT") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(DEFAULT_ROOT),
    }
}

/// Name of the emulator docker image.
pub fn image_name() -> String {
    match env::var("TAEMU_IMAGE") {
        Ok(i) if !i.is_empty() => i,
        _ => DEFAULT_IMAGE.to_string(),
    }
}

/// Path of a repository-relative file on the host, e.g.
/// `repo_path("emulator/fuzz.sh")`.
pub fn repo_path(rel: &str) -> PathBuf {
    repo_root().join(rel)
}
