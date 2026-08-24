//! Sandboxed process spawning.
//!
//! Both functions check the program against a `ProcessSpawnToken`'s
//! exact-name allowlist before invoking `std::process::Command`. Arguments
//! are not restricted by v0.1 tokens; keep allowlists narrow accordingly.

use std::process::{Child, Command, Output};
use tpt_capsec_core::ProcessSpawnToken;

use crate::error::CapsecError;

fn authorize(token: &ProcessSpawnToken<'_>, program: &str) -> Result<(), CapsecError> {
    if token.is_revoked() {
        return Err(CapsecError::Revoked);
    }
    if !token.permits_program(program) {
        return Err(CapsecError::OutOfScope(format!(
            "spawn of '{program}' outside token allowlist"
        )));
    }
    Ok(())
}

fn build_command(program: &str, args: &[String]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd
}

/// Spawns a child process, requiring spawn authority for `program`.
///
/// # Example
///
/// ```no_run
/// use tpt_capsec::prelude::*;
/// use tpt_capsec::process;
///
/// let root = RootCapability::acquire();
/// let token = root.delegate_process_spawn(["git"]);
/// let child = process::spawn("git", ["status"], &token).unwrap();
/// ```
pub fn spawn<I, S>(
    program: &str,
    args: I,
    token: &ProcessSpawnToken<'_>,
) -> Result<Child, CapsecError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    authorize(token, program)?;
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_string()).collect();
    Ok(build_command(program, &args).spawn()?)
}

/// Spawns a child process and waits for it to finish, collecting its output,
/// requiring spawn authority for `program`.
pub fn output<I, S>(
    program: &str,
    args: I,
    token: &ProcessSpawnToken<'_>,
) -> Result<Output, CapsecError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    authorize(token, program)?;
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_string()).collect();
    Ok(build_command(program, &args).output()?)
}
