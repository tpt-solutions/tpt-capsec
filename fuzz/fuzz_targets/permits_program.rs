#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(&data);
    let allowlist: Vec<String> = ["git".to_string(), "cargo".to_string()].into();
    for token in text.split_whitespace() {
        let _ = tpt_capsec_core::permits_program(allowlist.iter(), token);
    }
});