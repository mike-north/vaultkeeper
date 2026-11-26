//! Exports backend-level conformance test cases as JSON to stdout.

fn main() {
    print!(
        "{}",
        vaultkeeper_conformance::backend_cases::backend_cases_as_json()
    );
}
