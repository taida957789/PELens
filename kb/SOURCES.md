# Sources of the open knowledge base

The open knowledge base lets PELens analyse files without pestudio's XML files, which belong to
pestudio's author and cannot be redistributed. It uses the same XML format, so PELens still reads
pestudio's files when you pass `-xml:<dir>`.

**Nothing in `kb/` is copied from pestudio's XML files.** Every entry was written for PELens from
the public sources below. The indicator **ids** are the only shared part: they keep both knowledge
bases interchangeable for the engine. The names, details, severities and techniques of the
indicators are our own.

| file | content | source |
|---|---|---|
| `src/indicators.tsv` | names, details, severities, views and techniques of the 142 indicators the engine evaluates | written from what each check in `crates/pe-analysis/src/indicators.rs` does |
| `src/libraries.tsv`, `src/functions.tsv` | Windows API libraries and functions: group, suspicious flag, ATT&CK technique, anti-debug / callback / deprecated / undocumented markers | Microsoft Learn (Win32 API reference); techniques from MITRE ATT&CK |
| `src/strings.tsv` | well-known SIDs, privilege names, user agents, file extensions, registry paths, folders, Office macro names, admin tools (LOLBins), DOS stub messages, suspicious strings and .NET obfuscator attributes | Microsoft Learn (well-known SIDs, privilege constants, registry), MITRE ATT&CK, the LOLBAS project (as a list of tool names) |
| `src/namespaces.tsv` | .NET namespaces of interest | .NET API reference (Microsoft Learn) |
| `src/signatures.tsv` | file-type magic numbers, packer / protector / installer / compiler markers | published file-format specifications and documentation of the tools; entry-point patterns only where the stub is well known |
| `src/mitre.tsv` | tactics and techniques used by the other files | MITRE ATT&CK Enterprise (© The MITRE Corporation, terms of use) |
| `src/languages.tsv` | Windows language ids (LCID) and locale names | Python's `locale.windows_locale` table (facts) |
| `src/groups.tsv` | group ids, names and colors | PELens |
| `tools/build_kb.py` | thresholds, Visual Studio toolset build ranges (Rich header), code pages, .NET metadata table names (ECMA-335), hint names, settings | public release notes, ECMA-335, PELens defaults |

Gaps compared with pestudio's knowledge base:

- Rich header **product ids** (the compiler/linker component of each entry) are not named yet;
  only the Visual Studio release is derived from the build number.
- Fewer API functions and signatures. Use `-xml:<dir>` with your own pestudio installation for its
  larger catalog.

Contributions: edit the TSV files in `src/`, run `python tools/build_kb.py`, and state the source of
new entries in the pull request.
