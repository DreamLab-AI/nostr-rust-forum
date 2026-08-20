//! Validate a deployment's `forum.toml` before projecting it into bindings.

use std::path::PathBuf;

fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("forum.toml"));

    match nostr_bbs_config::load_from_path(&path) {
        Ok(_) => println!("validated {}", path.display()),
        Err(error) => {
            eprintln!("invalid {}: {error}", path.display());
            std::process::exit(1);
        }
    }
}
