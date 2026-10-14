//! Resource content decoders, fed directly with a resource's bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pe_parser::resource_content as rc;

fuzz_target!(|data: &[u8]| {
    let _ = rc::VersionInfo::parse(data);
    let _ = rc::Manifest::parse(data);
    let _ = rc::parse_string_table(data, 1);
    let _ = rc::parse_message_table(data);
    let _ = rc::parse_menu(data);
    let _ = rc::parse_dialog(data);
    let _ = rc::parse_group_icon(data, false);
    let _ = rc::parse_group_icon(data, true);
    let _ = rc::decode_text(data);
});
