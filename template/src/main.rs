//! Minimal starter showing the tpt-capsec workflow:
//! acquire root once -> delegate narrowly -> use only sandboxed wrappers.

use std::path::Path;

use tpt_capsec::fs;
use tpt_capsec::prelude::*;

fn main() -> Result<(), CapsecError> {
    // 1. Acquire the root capability by convention at program start.
    let root = RootCapability::acquire();

    // 2. Delegate the narrowest authority each component needs.
    let data_dir = root.delegate_fs_read("data");
    let out_dir = root.delegate_fs_write("out");

    // 3. Route all privileged operations through the wrappers.
    let config = fs::read_to_string(Path::new("data").join("config.txt"), &data_dir)?;
    fs::write(Path::new("out").join("echo.txt"), config, &out_dir)?;

    Ok(())
}