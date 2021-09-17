use vergen::{vergen, Config};

fn main() {
    let mut config = Config::default();
    // Change the SHA output to the short variant
    *config.git_mut().sha_kind_mut() = vergen::ShaKind::Short;
    // Generate the default 'cargo:' instruction output
    let _ = vergen(config);
}
