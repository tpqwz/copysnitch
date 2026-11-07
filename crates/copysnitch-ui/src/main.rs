use std::env;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use copysnitch_ui::converse;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("copysnitch-ui: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: impl Iterator<Item = String>) -> io::Result<()> {
    let mut socket = None;
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --socket")
                })?);
            }
            "--help" | "-h" => {
                println!("usage: copysnitch-ui --socket PATH");
                return Ok(());
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument {other}"),
                ));
            }
        }
    }
    let Some(socket) = socket else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: copysnitch-ui --socket PATH",
        ));
    };
    let stream = UnixStream::connect(socket)?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    converse(&stream, &mut input, &mut output)?;
    output.flush()?;
    Ok(())
}
