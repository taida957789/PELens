//! pestudio analysis engine: enriches a parsed PE with the knowledge base and evaluates indicators.

pub mod actions;
pub mod analyze;
pub mod authenticode;
pub mod disasm;
pub mod indicators;
pub mod model;
pub mod report;
pub mod sigscan;
pub mod strings;
#[doc(hidden)]
pub mod testkit;
#[cfg(unix)]
pub mod unix;
pub mod util;
pub mod verify;
pub mod view;
pub mod yara;

pub use analyze::{Options, analyze, analyze_file};
pub use model::*;

pub(crate) fn align(v: u64, a: u64) -> u64 {
    pe_parser::reader::align_up(v, a)
}
