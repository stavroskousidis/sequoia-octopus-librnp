
fn main() {
    vergen();
}

fn vergen() {
    // Generate the "cargo:" instruction cargo:rustc-env=VERGEN_GIT_SHA=<SHA>
    //
    // If the source directory is not a git repository, e.g. a tarball, this
    // produces an Error and VERGEN_GIT_SHA is not set.
    // In our case that is okay, because do not care for vergen variables other
    // than VERGEN_GIT_SHA and only use it if it is set (see
    // rnp_version_string_full in src/version.rs).
    // Upstream issue: https://github.com/rustyhorde/vergen/issues/124
    let _ = vergen::EmitBuilder::builder()
        .git_sha(/* short */ true)
        .emit();
}

