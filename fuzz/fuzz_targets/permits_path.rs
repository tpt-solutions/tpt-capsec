#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the input into two lossy UTF-8 halves treated as scope/candidate.
    let mid = data.len() / 2;
    let scope = String::from_utf8_lossy(&data[..mid]);
    let candidate = String::from_utf8_lossy(&data[mid..]);
    let _ = tpt_capsec_core::permits_path(
        std::path::Path::new(scope.as_ref()),
        std::path::Path::new(candidate.as_ref()),
    );
});