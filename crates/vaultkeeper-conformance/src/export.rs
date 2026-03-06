//! Exports conformance test cases as JSON to stdout.

fn main() {
    print!("{}", vaultkeeper_conformance::cases_as_json());
}
