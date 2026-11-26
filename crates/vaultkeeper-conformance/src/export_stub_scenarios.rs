//! Exports the StubTool axis corpus (issue #313 AC4) as JSON to stdout, for
//! `packages/cli-tests/test/conformance/stub-scenarios.json` — mirrors
//! `export.rs`/`export_backend.rs`'s pattern.

fn main() {
    let cases = vaultkeeper_conformance::stub_scenario_cases();
    print!(
        "{}",
        serde_json::to_string_pretty(&cases).expect("stub scenario cases must serialize")
    );
}
