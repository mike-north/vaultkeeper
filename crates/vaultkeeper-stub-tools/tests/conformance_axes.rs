//! (issue #313 AC4) Drives `vaultkeeper_conformance::stub_scenario_cases()`
//! — the world-mutation / state-conditional-response / shape-assertion
//! corpus — directly against the in-process [`StubTool`] engine: each
//! `ConformanceCase.stub_scenario`'s steps run in order against one
//! [`World`] shared across the whole scenario, asserting each step's
//! `expected_exit_code`/`expected_stdout`/`expected_stderr` via the exact
//! same [`vaultkeeper_conformance::matches_output`] the CLI-argv runners use.
//!
//! See `packages/cli-tests/test/conformance/stub-tool-axes.test.ts` for the
//! JS-side counterpart that drives the identical cases through the real
//! `vk-stub-*` subprocess resolved from PATH (AC3), rather than the
//! in-process engine used here.

use vaultkeeper_conformance::{matches_output, stub_scenario_cases};
use vaultkeeper_stub_tools::{StubTool, World, tables};

#[test]
fn every_stub_scenario_case_parses_and_drives_the_stub() {
    let cases = stub_scenario_cases();
    // Sanity: the corpus actually has all three axes represented — this is
    // itself part of AC4 ("a case exercising a store->get round trip, a
    // locked-vs-unlocked conditional, and a field-structure round-trip
    // assertion all parse and drive the stub").
    assert!(
        cases.len() >= 3,
        "expected at least 3 stub-scenario cases, got {}",
        cases.len()
    );

    for case in cases {
        let scenario = case
            .stub_scenario
            .as_ref()
            .unwrap_or_else(|| panic!("case '{}' has no stub_scenario", case.name));

        let table = tables::by_tool_name(&scenario.tool).unwrap_or_else(|| {
            panic!(
                "case '{}': no built-in table for tool '{}'",
                case.name, scenario.tool
            )
        });
        let mut world = World::new();

        for (i, step) in scenario.steps.iter().enumerate() {
            let stdin = step.stdin.clone().unwrap_or_default();
            let result = StubTool::run(&table, &mut world, &step.args, stdin.as_bytes());

            assert_eq!(
                result.exit_code, step.expected_exit_code,
                "case '{}' step {i} ({:?}): exit code — argv {:?}",
                case.name, step.note, step.args
            );

            let stdout = String::from_utf8_lossy(&result.stdout);
            assert!(
                matches_output(&step.expected_stdout, &stdout),
                "case '{}' step {i} ({:?}): stdout mismatch — expected {:?}, got {:?}",
                case.name,
                step.note,
                step.expected_stdout,
                stdout
            );

            let stderr = String::from_utf8_lossy(&result.stderr);
            assert!(
                matches_output(&step.expected_stderr, &stderr),
                "case '{}' step {i} ({:?}): stderr mismatch — expected {:?}, got {:?}",
                case.name,
                step.note,
                step.expected_stderr,
                stderr
            );
        }
    }
}
