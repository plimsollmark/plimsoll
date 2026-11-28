//! The identity command: one line naming the build's inputs, as build.sh set them at compile
//! time (sandbox/internal/nativehelper's TestCommittedHelperReportsThePinnedInputs holds the
//! committed build to the pin's lines).

use std::process::Command;

const HELPER: &str = env!("CARGO_BIN_EXE_plimsoll-helper");

#[test]
fn identity_prints_the_inputs_it_was_built_with() {
    let out = Command::new(HELPER).arg("identity").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let want = format!("inputs {}\n", option_env!("PLIMSOLL_HELPER_INPUTS").unwrap_or("none"));
    assert_eq!(String::from_utf8_lossy(&out.stdout), want);
    assert_eq!(out.stderr, b"");
}

#[test]
fn identity_takes_no_argument() {
    let out = Command::new(HELPER).args(["identity", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
}
