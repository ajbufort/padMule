//! The bindings generator. `cargo run --bin uniffi-bindgen -- generate --library
//! <path-to-libmule_ffi> --language swift --out-dir <dir>` emits the Swift glue.
fn main() {
    uniffi::uniffi_bindgen_main()
}
