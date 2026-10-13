use pe_analysis::report::Format;
use pelens_cli::*;
use std::path::{Path, PathBuf};

struct TestEnv {
    exe: Option<PathBuf>,
}

struct NoNet;
impl pe_online::HttpClient for NoNet {
    fn get(&self, _url: &str, _h: &[(&str, &str)]) -> Result<pe_online::HttpResponse, String> {
        Ok(pe_online::HttpResponse {
            status: 200,
            body: r#"{"data":{"id":"x","attributes":{"last_analysis_stats":{"malicious":4,"undetected":5},"last_analysis_results":{}}}}"#
                .into(),
        })
    }
}

impl Env for TestEnv {
    fn exe_dir(&self) -> Option<PathBuf> {
        self.exe.clone()
    }
    fn http(&self, _k: &pe_db::Knowledge) -> Box<dyn pe_online::HttpClient> {
        Box::new(NoNet)
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn run_cli(args: &[String], env: &dyn Env) -> (i32, String, String) {
    let mut o = Vec::new();
    let mut e = Vec::new();
    let c = run(args, &mut o, &mut e, env);
    (c, String::from_utf8(o).unwrap(), String::from_utf8(e).unwrap())
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pestudiox-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn parse_arguments() {
    let a = parse_args(&s(&["-file:C:\\x\\a.exe", "/report:out.xml", "--banner", "-XML:kb", "-format:json", "-vt", "-stdout"])).unwrap();
    assert_eq!(a.file, Some(PathBuf::from("C:\\x\\a.exe")));
    assert_eq!(a.report, Some(PathBuf::from("out.xml")));
    assert!(a.hide_banner && a.vt && a.stdout && !a.help);
    assert_eq!(a.xml_dir, Some(PathBuf::from("kb")));
    assert_eq!(a.format, Some(Format::Json));
    assert_eq!(parse_args(&s(&["--format=text"])).unwrap().format, Some(Format::Text));
    assert_eq!(parse_args(&s(&["-format:txt"])).unwrap().format, Some(Format::Text));
    assert_eq!(parse_args(&s(&["-format:xml"])).unwrap().format, Some(Format::Xml));
    assert!(parse_args(&s(&["-?"])).unwrap().help);
    assert!(parse_args(&s(&["-h"])).unwrap().help);
    assert_eq!(parse_args(&s(&["-format:pdf"])), Err(ArgError::BadFormat("pdf".into())));
    assert_eq!(parse_args(&s(&["-bogus"])), Err(ArgError::Unknown("-bogus".into())));
    assert_eq!(parse_args(&s(&["-file:"])), Err(ArgError::Unknown("-file:".into())));
    assert_eq!(ArgError::Unknown("x".into()).to_string(), "unknown argument: x");
    assert_eq!(ArgError::BadFormat("x".into()).to_string(), "unknown report format: x");
}

#[test]
fn usage_and_errors() {
    let env = TestEnv { exe: None };
    let (c, o, _) = run_cli(&s(&["-help"]), &env);
    assert_eq!(c, 0);
    assert!(o.contains("pelens-cli") && o.contains("-file:"));
    let (c, o, _) = run_cli(&s(&["-help", "-banner"]), &env);
    assert_eq!(c, 0);
    assert!(!o.contains("as-is"));
    let (c, _, e) = run_cli(&s(&["-nope"]), &env);
    assert_eq!(c, 2);
    assert!(e.contains("unknown argument"));
    let (c, _, e) = run_cli(&s(&["-banner"]), &env);
    assert_eq!(c, 2);
    assert!(e.contains("missing -file:"));
    let (c, _, e) = run_cli(&s(&["-banner", "-file:Z:/no/such/file.exe", "-xml:Z:/none"]), &env);
    assert_eq!(c, 1);
    assert!(e.contains("cannot read"));
    assert!(banner().contains("Malware Initial Assessment"));
}

#[test]
fn writes_reports() {
    let dir = tmp("reports");
    let kb = pe_analysis::testkit::write_knowledge("cli");
    let st = std::fs::read_to_string(kb.join("settings.xml")).unwrap().replace("key=\"\"", "key=\"TESTKEY\"");
    std::fs::write(kb.join("settings.xml"), st).unwrap();
    let sample = dir.join("sample.exe");
    std::fs::write(&sample, pe_analysis::testkit::suspicious_sample()).unwrap();
    let env = TestEnv { exe: None };

    // default report name: input + .xml
    let (c, o, e) = run_cli(&s(&[&format!("-file:{}", sample.display()), &format!("-xml:{}", kb.display())]), &env);
    assert_eq!(c, 0, "{e}");
    assert!(o.contains("[+] report:") && o.contains("as-is"));
    let xml = std::fs::read_to_string(dir.join("sample.exe.xml")).unwrap();
    assert!(pe_db::dom::parse(&xml).is_ok());

    // explicit report, json, VirusTotal through the injected client
    let out = dir.join("r.json");
    let (c, _, _) = run_cli(
        &s(&[
            "-banner",
            &format!("-file:{}", sample.display()),
            &format!("-xml:{}", kb.display()),
            &format!("-report:{}", out.display()),
            "-format:json",
            "-vt",
        ]),
        &env,
    );
    assert_eq!(c, 0);
    let j = std::fs::read_to_string(&out).unwrap();
    assert!(j.contains("\"engine\":\"virustotal\"") || j.contains("4/9"));

    // stdout text
    let (c, o, _) = run_cli(
        &s(&["-banner", &format!("-file:{}", sample.display()), &format!("-xml:{}", kb.display()), "-format:text", "-stdout"]),
        &env,
    );
    assert_eq!(c, 0);
    assert!(o.starts_with("pelens report"));

    // unwritable report location
    let (c, _, e) = run_cli(
        &s(&[
            "-banner",
            &format!("-file:{}", sample.display()),
            &format!("-xml:{}", kb.display()),
            &format!("-report:{}", dir.join("no/such/dir/r.xml").display()),
        ]),
        &env,
    );
    assert_eq!(c, 1);
    assert!(e.contains("Cannot create Report file!"));

    // knowledge errors are reported but the analysis continues with defaults
    let empty = tmp("emptykb");
    let (c, _, e) =
        run_cli(&s(&["-banner", &format!("-file:{}", sample.display()), &format!("-xml:{}", empty.display()), "-stdout"]), &env);
    assert_eq!(c, 0);
    assert!(e.contains("[!] settings.xml"));
}

#[test]
fn locates_knowledge_directory() {
    let base = tmp("locate");
    std::fs::create_dir_all(base.join("xml")).unwrap();
    std::fs::write(base.join("xml/settings.xml"), "<xml/>").unwrap();
    assert_eq!(find_xml_dir(Some(Path::new("given")), None), Some(PathBuf::from("given")));
    assert_eq!(find_xml_dir(None, Some(&base)), Some(base.join("xml")));
    let elsewhere = tmp("locate-none");
    let r = find_xml_dir(None, Some(&elsewhere));
    assert!(r.is_none() || r.unwrap().join("settings.xml").exists());
    // builtin knowledge when nothing is found
    let sample = elsewhere.join("s.exe");
    std::fs::write(&sample, pe_parser::testutil::PeBuilder::new().build()).unwrap();
    let env = TestEnv { exe: Some(elsewhere.clone()) };
    let (c, _, _) = run_cli(&s(&["-banner", &format!("-file:{}", sample.display()), "-stdout"]), &env);
    assert_eq!(c, 0);
    let real = RealEnv;
    assert!(real.exe_dir().is_some());
    let _ = real.http(&pe_db::Knowledge::builtin());
}

#[test]
fn binary_entry_point() {
    let exe = env!("CARGO_BIN_EXE_pelens-cli");
    let out = std::process::Command::new(exe).arg("-help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("-file:"));
    let out = std::process::Command::new(exe).arg("-bad").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// Code review #8: with -stdout the report is the only thing on stdout.
#[test]
fn stdout_is_pipe_clean() {
    let dir = tmp("pipe");
    let sample = dir.join("s.exe");
    std::fs::write(&sample, pe_parser::testutil::PeBuilder::new().build()).unwrap();
    let env = TestEnv { exe: None };
    let (c, o, e) = run_cli(&s(&[&format!("-file:{}", sample.display()), "-format:json", "-stdout"]), &env);
    assert_eq!(c, 0);
    assert!(o.starts_with('{'), "stdout starts with the report: {}", &o[..40.min(o.len())]);
    assert!(e.contains("Malware Initial Assessment"), "banner went to stderr");
    let (_, o, _) = run_cli(&s(&[&format!("-file:{}", sample.display()), "-stdout"]), &env);
    assert!(o.starts_with("<?xml"));
}
