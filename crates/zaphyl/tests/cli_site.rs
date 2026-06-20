//! End-to-end CLI behaviour via the real binary.

use std::process::Command;

#[test]
fn help_lists_the_site_subcommand() {
    let out = Command::new(env!("CARGO_BIN_EXE_zaphyl"))
        .arg("--help")
        .output()
        .expect("run zaphyl --help");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("site"), "help should mention the site command:\n{text}");
}
