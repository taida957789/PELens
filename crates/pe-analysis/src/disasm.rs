//! Linear x86 / x64 disassembly (iced-x86) for the "disassembly" view: from the entry point or any
//! RVA, with calls through the import address table named after the imported function.

use crate::model::Analysis;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind};
use std::collections::HashMap;

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Line {
    pub rva: u32,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    /// Imported function called through the IAT, or the target of a branch.
    pub comment: String,
    /// Branch target inside the image (lets the GUI follow it).
    pub target: Option<u32>,
    /// The instruction uses a flagged import.
    pub flag: bool,
}

/// Longest x86 instruction.
const MAX_INSTRUCTION: usize = 15;
/// Upper bound of the instruction count (setting `<disassembly count>`).
pub const MAX_COUNT: usize = 4096;

/// Disassemble `count` instructions from `rva`.
pub fn disassemble(a: &Analysis, data: &[u8], rva: u32, count: usize) -> Result<Vec<Line>, String> {
    let l = a.pe.layout.as_ref().ok_or("not a portable executable")?;
    let bitness = match l.file_header.machine {
        0x014c => 32,
        0x8664 => 64,
        m => return Err(format!("unsupported architecture ({}): x86 and x64 only", pe_parser::headers::machine_name(m))),
    };
    let off = l.rva_to_offset(rva).ok_or_else(|| format!("RVA 0x{rva:08X} is not backed by the file"))?;
    // up to the end of the section holding the RVA (code does not continue across sections)
    let end = l
        .section_of_rva(rva)
        .map(|s| (s.pointer_to_raw_data as usize).saturating_add(s.size_of_raw_data as usize))
        .unwrap_or(data.len())
        .min(data.len());
    let window = count.min(MAX_COUNT).saturating_mul(MAX_INSTRUCTION);
    let code = data.get(off..end.min(off.saturating_add(window)).max(off)).unwrap_or(&[]);
    let base = l.image_base();
    let start_ip = base.wrapping_add(rva as u64);

    // IAT slot address → "library!function"
    let mut iat: HashMap<u64, (String, bool)> = HashMap::new();
    for lib in &a.pe.imports.libraries {
        for f in &lib.functions {
            let name = match (&f.name, f.ordinal) {
                (Some(n), _) => n.clone(),
                (None, Some(o)) => format!("#{o}"),
                (None, None) => continue,
            };
            let flagged = a.imports.iter().any(|i| i.flag && i.name == name && i.library.eq_ignore_ascii_case(&lib.name));
            iat.insert(base.wrapping_add(f.iat_rva as u64), (format!("{}!{name}", lib.name), flagged));
        }
    }

    let mut decoder = Decoder::with_ip(bitness, code, start_ip, DecoderOptions::NONE);
    let mut fmt = IntelFormatter::new();
    fmt.options_mut().set_space_after_operand_separator(true);
    let mut out = Vec::new();
    let mut instr = Instruction::default();
    while decoder.can_decode() && out.len() < count.min(MAX_COUNT) {
        decoder.decode_out(&mut instr);
        let pos = instr.ip().wrapping_sub(start_ip) as usize;
        let len = instr.len();
        let mut text = String::new();
        fmt.format(&instr, &mut text);
        let mut line = Line {
            rva: rva.wrapping_add(pos as u32),
            offset: (off + pos) as u64,
            bytes: code.get(pos..pos + len).unwrap_or(&[]).to_vec(),
            text,
            ..Default::default()
        };
        if instr.is_invalid() {
            line.comment = "invalid instruction".into();
        } else {
            let memory = (0..instr.op_count()).any(|i| instr.op_kind(i) == OpKind::Memory);
            let address = if instr.is_ip_rel_memory_operand() {
                Some(instr.ip_rel_memory_address())
            } else if memory && instr.memory_base() == iced_x86::Register::None && instr.memory_index() == iced_x86::Register::None {
                Some(instr.memory_displacement64())
            } else {
                None
            };
            if let Some((name, flagged)) = address.and_then(|m| iat.get(&m)) {
                line.comment = name.clone();
                line.flag = *flagged;
            } else if matches!(instr.flow_control(), FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch)
                && (0..instr.op_count())
                    .any(|i| matches!(instr.op_kind(i), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64))
            {
                let t = instr.near_branch_target();
                match l.va_to_rva(t) {
                    Some(r) => {
                        line.comment = format!("→ 0x{r:08X} ({})", l.section_name_of_rva(r));
                        line.target = Some(r);
                    }
                    None => line.comment = "→ outside the image".into(),
                }
            }
        }
        out.push(line);
    }
    Ok(out)
}
