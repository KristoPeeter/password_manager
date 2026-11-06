use std::process::ExitCode;

mod ui;
mod vault;

fn main() -> ExitCode {
    ui::run()
}
