#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::process::ExitCode;

mod ui;
mod vault;

fn main() -> ExitCode {
    ui::run()
}
