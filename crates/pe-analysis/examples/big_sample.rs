//! Write a large synthetic PE for performance measurements:
//! `cargo run --release -p pe-analysis --example big_sample -- <out.exe> <MB> [mixed|overlay|strings|resource]`
//!
//! - overlay:  random (incompressible) bytes appended after the image
//! - strings:  a data section full of short printable strings (worst case for string extraction)
//! - resource: one RCDATA resource of that size
//! - mixed:    a third of each
use pe_parser::testutil::*;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(out), Some(mb)) = (args.first(), args.get(1).and_then(|m| m.parse::<usize>().ok())) else {
        eprintln!("usage: big_sample <out.exe> <MB> [mixed|overlay|strings|resource]");
        std::process::exit(2);
    };
    let kind = args.get(2).map(String::as_str).unwrap_or("mixed");
    let size = mb << 20;
    let part = if kind == "mixed" { size / 3 } else { size };
    let mut b = PeBuilder::new();
    b.imports = vec![Import { dll: "kernel32.dll".into(), functions: vec!["CreateFileW".into(), "ReadFile".into()], delay: false }];
    if matches!(kind, "mixed" | "strings") {
        let mut s = Vec::with_capacity(part);
        let words = ["http://example.org/a", "SetWindowsHookExW", "cmd.exe /c", r"HKLM\Software\Run", "password", "kernel32.dll"];
        let mut i = 0usize;
        while s.len() < part {
            s.extend_from_slice(words[i % words.len()].as_bytes());
            s.extend_from_slice(format!("{i}").as_bytes());
            s.push(0);
            i += 1;
        }
        b.extra_sections.push(ExtraSection { name: ".strs".into(), data: s, characteristics: 0x4000_0040, virtual_size: None });
    }
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut random = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng as u8
            })
            .collect()
    };
    if matches!(kind, "mixed" | "resource") {
        b.resources = vec![Resource { type_id: ResKey::Id(10), name: ResKey::Id(1), lang: 0x409, data: random(part) }];
    }
    if matches!(kind, "mixed" | "overlay") {
        b.overlay = random(part);
    }
    let data = b.build();
    std::fs::write(out, &data).expect("write");
    println!("{out}: {} bytes ({kind})", data.len());
}
