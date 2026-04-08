use std::env;
use std::path::PathBuf;

fn pointer_width() -> &'static str {
    match env::var("CARGO_CFG_TARGET_POINTER_WIDTH")
        .as_deref()
        .unwrap_or("64")
    {
        "32" => "4",
        _ => "8",
    }
}

fn main() {
    let ulong_size = if cfg!(target_os = "windows") {
        "4"
    } else {
        pointer_width()
    };

    let defines: Vec<(&str, &str)> = vec![
        ("SIZEOF_SIZE_T", pointer_width()),
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
    cc_builder.include("xdelta3/xdelta3");
    for &(key, val) in &defines {
        cc_builder.define(key, Some(val));
    }
    cc_builder
        .file("xdelta3/xdelta3/xdelta3.c")
        .warnings(false)
        .compile("xdelta3");

    // Generate FFI bindings
    let mut bg_builder = bindgen::Builder::default();
    for &(key, val) in &defines {
        bg_builder = bg_builder.clang_arg(format!("-D{key}={val}"));
    }
    let bindings = bg_builder
        .header("xdelta3/xdelta3/xdelta3.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("xd3_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
