//! Check a deployed `ZONE_CONFIG` JSON (ADR-2037 channel pins) before it is
//! handed to the workers: misspelt pin keys, malformed or duplicate
//! `channels` entries, and pinning zone ids that extend another zone's id.
//!
//! Usage: `validate-zone-config <file>` (`-` reads standard input). Exits 0
//! when the pins are well formed, 1 with a message when they are not, and 2
//! when the file cannot be read.

use std::io::Read;

fn main() {
    let Some(arg) = std::env::args().nth(1) else {
        eprintln!("usage: validate-zone-config <ZONE_CONFIG json file | ->");
        std::process::exit(2);
    };
    let raw = if arg == "-" {
        let mut s = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut s) {
            eprintln!("cannot read standard input: {e}");
            std::process::exit(2);
        }
        s
    } else {
        match std::fs::read_to_string(&arg) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot read {arg}: {e}");
                std::process::exit(2);
            }
        }
    };
    match nostr_bbs_config::validate::validate_zone_config_json(raw.trim()) {
        Ok(()) => println!("validated ZONE_CONFIG {arg}"),
        Err(e) => {
            eprintln!("invalid ZONE_CONFIG {arg}: {e}");
            std::process::exit(1);
        }
    }
}
