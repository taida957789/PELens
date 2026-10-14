Inputs that once crashed, hung or blew up PELens, kept as permanent regression tests
(`tests/mutation.rs::corpus_inputs_stay_bounded`). All of them are mutations of the synthetic
samples in `pe_analysis::testkit`: no third-party binaries.

| file | problem | fix |
|---|---|---|
| `exports-count-bomb.bin` | NumberOfFunctions = 0x325A_0000: 1 M empty export rows, 40 MB report from 17 KB | counts bounded by the array size in the file, `Exports.truncated` |
