//! Analysis result model shared by the GUI, the CLI and the XML report.

use crate::util::Hashes;
use pe_parser::PeFile;

/// The 27 views of pestudio, in tree order. The discriminant is the value used by the
/// `type` attribute of indicators.xml (jump target of an indicator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ItemType {
    Image = 0,
    Footprints = 1,
    Groups = 2,
    Indicators = 3,
    Mitre = 4,
    Score = 5,
    DosStub = 6,
    DosHeader = 7,
    RichHeader = 8,
    FileHeader = 9,
    OptionalHeader = 10,
    Directories = 11,
    Sections = 12,
    Libraries = 13,
    Imports = 14,
    Exports = 15,
    Exceptions = 16,
    Certificate = 17,
    Relocations = 18,
    Tls = 19,
    DotNet = 20,
    Resources = 21,
    Version = 22,
    Debug = 23,
    Strings = 24,
    Manifest = 25,
    Overlay = 26,
    Yara = 27,
}

impl ItemType {
    pub const ALL: [ItemType; 28] = [
        ItemType::Image,
        ItemType::Footprints,
        ItemType::Groups,
        ItemType::Indicators,
        ItemType::Mitre,
        ItemType::Score,
        ItemType::DosStub,
        ItemType::DosHeader,
        ItemType::RichHeader,
        ItemType::FileHeader,
        ItemType::OptionalHeader,
        ItemType::Directories,
        ItemType::Sections,
        ItemType::Libraries,
        ItemType::Imports,
        ItemType::Exports,
        ItemType::Exceptions,
        ItemType::Certificate,
        ItemType::Relocations,
        ItemType::Tls,
        ItemType::DotNet,
        ItemType::Resources,
        ItemType::Version,
        ItemType::Debug,
        ItemType::Strings,
        ItemType::Manifest,
        ItemType::Overlay,
        ItemType::Yara,
    ];

    pub fn name(self) -> &'static str {
        [
            "image",
            "footprints",
            "groups",
            "indicators",
            "mitre",
            "score",
            "dos-stub",
            "dos-header",
            "rich-header",
            "file-header",
            "optional-header",
            "directories",
            "sections",
            "libraries",
            "imports",
            "exports",
            "exceptions",
            "certificate",
            "relocations",
            "thread-local-storage",
            "dotnet",
            "resources",
            "version",
            "debug",
            "strings",
            "manifest",
            "overlay",
            "yara",
        ][self as usize]
    }

    pub fn from_index(i: i64) -> Option<ItemType> {
        ItemType::ALL.get(usize::try_from(i).ok()?).copied()
    }

    /// Parse the two-digit `type` attribute of indicators.xml.
    pub fn from_code(code: &str) -> Option<ItemType> {
        code.trim().parse::<i64>().ok().and_then(ItemType::from_index)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Indicator {
    pub id: u32,
    pub severity: u8,
    pub enable: u8,
    /// Jump target view.
    pub kind: Option<ItemType>,
    pub name: String,
    pub detail: String,
    pub ti: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Footprint {
    pub item: String,
    pub location: String,
    pub hash_type: String,
    pub hash: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct GroupRow {
    pub id: u8,
    pub name: String,
    pub count: usize,
    pub rgb: (u8, u8, u8),
    pub level: u8,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MitreRow {
    pub technique: String,
    pub technique_name: String,
    pub tactic: String,
    pub tactic_name: String,
    pub flag: bool,
    pub level: u8,
    /// Items (imports, strings, namespaces, indicators) that map to the technique.
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SignatureHit {
    pub name: String,
    pub more: String,
    pub location: String,
    pub offset: u64,
    pub size: u64,
    pub file: bool,
    pub tool: bool,
    pub severity: u8,
    pub url: String,
}

#[derive(Debug, Clone, Default)]
pub struct EmbeddedFile {
    pub signature: String,
    pub location: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SectionRow {
    pub index: usize,
    pub name: String,
    pub md5: String,
    pub entropy: f64,
    pub file_ratio: f64,
    pub raw_address: u64,
    pub raw_size: u64,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
    pub flags: Vec<&'static str>,
    pub standard_name: bool,
    pub duplicate_name: bool,
    pub writable: bool,
    pub executable: bool,
    pub shareable: bool,
    pub self_modifying: bool,
    pub virtualized: bool,
    pub unreadable: bool,
    pub nameless: bool,
    pub entry_point: bool,
    pub directories: Vec<String>,
    pub embedded: Vec<String>,
    pub caves: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Default)]
pub struct LibraryRow {
    pub name: String,
    pub kind: String,
    pub imports: usize,
    pub flag: bool,
    pub group: Option<u8>,
    pub description: String,
    pub known: bool,
    pub duplicate: bool,
    pub spoofed: bool,
    pub bound: bool,
    pub stamp: u32,
    pub missing_int: bool,
    pub mismatch: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ImportRow {
    pub name: String,
    pub ordinal: Option<u16>,
    pub ordinal_mapped: bool,
    pub library: String,
    pub kind: String,
    pub hint: Option<u16>,
    pub int_value: u64,
    pub iat_value: u64,
    pub group: Option<u8>,
    pub ti: Option<String>,
    pub flag: bool,
    pub deprecated: bool,
    pub undocumented: bool,
    pub anti_debug: bool,
    pub callback: bool,
    pub map: Option<String>,
    pub mismatch: bool,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ExportRow {
    pub ordinal: u32,
    pub name: String,
    pub undecorated: String,
    pub rva: u32,
    pub function_index: u32,
    pub name_rva: u32,
    pub forwarder: Option<String>,
    pub gap: bool,
    pub anonymous: bool,
    pub duplicate: bool,
    pub flag: bool,
    pub entry_point: bool,
    pub location: String,
}

#[derive(Debug, Clone, Default)]
pub struct ResourceRow {
    pub type_name: String,
    pub name: String,
    pub language: u32,
    pub language_name: String,
    pub language_flag: bool,
    pub code_page: u32,
    pub size: u32,
    pub offset: Option<u32>,
    pub file_ratio: f64,
    pub entropy: f64,
    pub md5: String,
    pub signature: String,
    pub severity: u8,
    pub builtin: bool,
    pub first_bytes_hex: String,
    pub first_bytes_text: String,
    pub stamp: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    Ascii,
    Unicode,
    Utf8,
    DotNetStrings,
    DotNetUser,
}

impl StringKind {
    pub fn name(self) -> &'static str {
        match self {
            StringKind::Ascii => "ascii",
            StringKind::Unicode => "unicode",
            StringKind::Utf8 => "utf8",
            StringKind::DotNetStrings => "#Strings",
            StringKind::DotNetUser => "#US",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StringRow {
    pub kind: StringKind,
    pub size: usize,
    pub offset: u64,
    pub location: String,
    pub value: String,
    pub hint: Option<String>,
    pub group: Option<u8>,
    pub ti: Option<String>,
    pub flag: bool,
    pub whitelist: bool,
    pub blacklist: bool,
}

#[derive(Debug, Clone, Default)]
pub struct StampRow {
    pub kind: String,
    pub value: u32,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EngineResult {
    pub vendor: String,
    pub detected: bool,
    pub result: String,
    pub version: String,
    pub update: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScoreReport {
    /// "ok", "not found", "offline", "disabled", "error: …"
    pub status: String,
    pub resource: String,
    pub positives: u32,
    pub total: u32,
    pub scan_date: String,
    pub permalink: String,
    pub scan_id: String,
    pub engines: Vec<EngineResult>,
}

#[derive(Debug, Clone, Default)]
pub struct CertificateCheck {
    /// Result of WinVerifyTrust (None when not available on this platform).
    pub verified: Option<bool>,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct OverlayInfo {
    pub hashes: Hashes,
    pub entropy: f64,
    /// Signature of the overlay's content ("unknown" when none matches).
    pub signature: String,
}

/// Everything pestudio knows about one file.
#[derive(Debug, Clone, Default)]
pub struct Analysis {
    pub path: String,
    pub file_name: String,
    pub size: u64,
    pub pe: PeFile,
    pub hashes: Hashes,
    pub hashes_without_overlay: Option<Hashes>,
    pub entropy: f64,
    /// Hashes, entropy and signature of the overlay, computed once (views, footprints, score).
    pub overlay_info: Option<OverlayInfo>,
    /// PE checksum computed over the file (the optional header holds the claimed one).
    pub checksum_real: Option<u32>,
    /// Matching YARA rules (`Options::yara`).
    pub yara: Vec<crate::yara::YaraMatch>,
    /// Rule files the rules were compiled from (0: no rules).
    pub yara_files: usize,
    /// The scan failed (timeout, …).
    pub yara_error: Option<String>,
    pub imphash: Option<String>,
    pub cpu: String,
    pub file_type: String,
    pub subsystem: String,
    pub description: Option<String>,
    pub signatures: Vec<SignatureHit>,
    pub embedded: Vec<EmbeddedFile>,
    pub footprints: Vec<Footprint>,
    pub groups: Vec<GroupRow>,
    pub mitre: Vec<MitreRow>,
    pub indicators: Vec<Indicator>,
    pub sections: Vec<SectionRow>,
    pub libraries: Vec<LibraryRow>,
    pub imports: Vec<ImportRow>,
    pub exports: Vec<ExportRow>,
    pub resources: Vec<ResourceRow>,
    pub strings: Vec<StringRow>,
    pub strings_skipped: bool,
    pub stamps: Vec<StampRow>,
    pub score: Option<ScoreReport>,
    pub certificate_check: Option<CertificateCheck>,
    pub tooling: Vec<String>,
    pub network_drive: bool,
    pub removable_drive: bool,
}

impl Analysis {
    pub fn indicator(&self, id: u32) -> Option<&Indicator> {
        self.indicators.iter().find(|i| i.id == id)
    }

    pub fn has_indicator(&self, id: u32) -> bool {
        self.indicator(id).is_some()
    }

    /// Number of flagged items shown in a view (used for tree badges/colours).
    pub fn flagged_count(&self, t: ItemType) -> usize {
        match t {
            ItemType::Indicators => self.indicators.iter().filter(|i| i.severity == 1).count(),
            ItemType::Libraries => self.libraries.iter().filter(|l| l.flag).count(),
            ItemType::Imports => self.imports.iter().filter(|i| i.flag).count(),
            ItemType::Exports => self.exports.iter().filter(|e| e.flag).count(),
            ItemType::Strings => self.strings.iter().filter(|s| s.flag).count(),
            ItemType::Sections => self.sections.iter().filter(|s| !s.standard_name || s.self_modifying).count(),
            ItemType::Resources => self.resources.iter().filter(|r| r.severity <= 2 || r.language_flag).count(),
            ItemType::Mitre => self.mitre.iter().filter(|m| m.flag).count(),
            ItemType::Score => self.score.as_ref().map(|s| s.positives as usize).unwrap_or(0),
            ItemType::Yara => self.yara.len(),
            _ => 0,
        }
    }

    pub fn is_pe(&self) -> bool {
        self.pe.is_pe()
    }
}
