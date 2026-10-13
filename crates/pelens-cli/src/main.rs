fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    std::process::exit(pelens_cli::run(&args, &mut out, &mut err, &pelens_cli::RealEnv));
}
