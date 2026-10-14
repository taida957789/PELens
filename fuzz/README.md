# Fuzzing PELens

Coverage-guided fuzzing with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer +
AddressSanitizer). It needs the nightly toolchain; normal builds stay on stable.

| target | input |
|---|---|
| `parse_pe` | a whole file → `PeFile::parse` |
| `certificate` | a PKCS#7 / X.509 DER blob → Authenticode decoding |
| `dotnet` | bytes written over the metadata root of a valid .NET sample → streams, tables, heaps |
| `resources` | one resource's bytes → version, manifest, string/message tables, menus, dialogs, icons |
| `analyze` | a whole file → analysis, every view and every report format |

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
python tools/fuzz_seeds.py            # seed corpora from local PE files (not committed)
sh fuzz/run_all.sh 1800               # every target in parallel, 30 minutes each
cargo +nightly fuzz run analyze       # one target, until stopped
```

On Windows the AddressSanitizer runtime of Visual Studio must be on `PATH`, e.g.
`C:\Program Files\Microsoft Visual Studio\<version>\VC\Tools\MSVC\<msvc>\bin\Hostx64\x64`
(`clang_rt.asan_dynamic-x86_64.dll`); otherwise the targets exit with `STATUS_DLL_NOT_FOUND`.

Inputs are capped at 256 KB: instrumented analysis is about 100 times slower than a release build,
so larger inputs would only be reported as timeouts.

A crash or timeout is written to `fuzz/artifacts/<target>/`. Reproduce it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`, fix it, and keep a regression
test: inputs derived from the synthetic samples of `pe_analysis::testkit` can go to
`crates/pe-analysis/tests/corpus/`; inputs derived from third-party files must be turned into a
synthetic test instead (they cannot be committed).

`crates/pe-analysis/tests/mutation.rs` runs a deterministic, stable-Rust version of this in CI.
