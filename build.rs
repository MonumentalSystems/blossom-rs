use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=BLOSSOM_TRUSTED_RELEASE_SIGNERS");
    compile_xdelta3();
}

fn compile_xdelta3() {
    let pointer_width = match env::var("CARGO_CFG_TARGET_POINTER_WIDTH")
        .as_deref()
        .unwrap_or("64")
    {
        "32" => "4",
        _ => "8",
    };

    let ulong_size = if cfg!(target_os = "windows") {
        "4"
    } else {
        pointer_width
    };

    let defines: Vec<(&str, &str)> = vec![
        ("SIZEOF_SIZE_T", pointer_width),
        ("SIZEOF_UNSIGNED_INT", "4"),
        ("SIZEOF_UNSIGNED_LONG", ulong_size),
        ("SIZEOF_UNSIGNED_LONG_LONG", "8"),
        ("SECONDARY_DJW", "1"),
        ("SECONDARY_FGK", "1"),
        ("EXTERNAL_COMPRESSION", "0"),
        ("XD3_USE_LARGEFILE64", "1"),
        ("SHELL_TESTS", "0"),
    ];

    // Compile the C library
    let mut cc_builder = cc::Build::new();
    cc_builder.include("vendor/xdelta3");
    for &(key, val) in &defines {
        cc_builder.define(key, Some(val));
    }
    cc_builder
        .file("vendor/xdelta3/xdelta3.c")
        .warnings(false)
        .compile("xdelta3");
}
