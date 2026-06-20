//! Verifies the documented `zaphyl.example.toml` stays valid as the schema
//! evolves.

#[test]
fn example_config_parses() {
    let toml = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../zaphyl.example.toml"
    ))
    .unwrap();
    zaphyl_config::Config::from_toml(&toml).expect("example config should parse");
}
