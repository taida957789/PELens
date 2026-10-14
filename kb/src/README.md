# Open knowledge base: sources

`tools/build_kb.py` turns these tab-separated files into the XML files of `kb/` (the format
pestudio uses, so PELens loads either). Lines starting with `#` and blank lines are ignored.
Every entry is written for PELens from public documentation (see `../SOURCES.md`); nothing is
copied from pestudio's XML files.

## Groups (`groups.tsv`)

Group ids are shared by functions, libraries, strings and namespaces. Group `10` is
`obfuscation`: the engine reports .NET obfuscators from it.

| id | name | id | name |
|---|---|---|---|
| 01 | registry | 13 | input (keyboard/mouse) |
| 02 | execution | 14 | hooking |
| 03 | network | 15 | security |
| 04 | cryptography | 16 | diagnostic (debugging, anti-debug) |
| 05 | memory | 17 | services |
| 06 | file | 18 | storage (volumes, devices) |
| 07 | reconnaissance | 19 | clipboard / data exchange |
| 08 | synchronization | 20 | shell |
| 09 | dynamic-library | 21 | com |
| 10 | obfuscation | 22 | console |
| 11 | windowing | 23 | resource |
| 12 | exception | 24 | time |

## MITRE techniques

Enterprise ATT&CK technique ids without the `T`, base techniques only (`1055`, not `1055.001`).
`mitre.tsv` lists every technique used by the other files with its name and primary tactic.

## Files

| file | columns |
|---|---|
| `groups.tsv` | id, name, level (1 = colored in the views), r, g, b |
| `libraries.tsv` | library (lower case), group or `--`, flag (0/1), description |
| `functions.tsv` | library (lower case), function, group or `--`, flag (0/1), technique or `----`, attributes (comma list or `-`: `ad` anti-debug, `cb` callback, `cd` deprecated, `un` undocumented) |
| `signatures.tsv` | name, kind (`tool` packer/protector/installer/compiler, `file` embedded file type), severity (1 high … 4 info), where (`ep` at the entry point, `start` at the start of a blob, `text` text in section names / file content), pattern (hex bytes with `xx` wildcards, or text), description, url or `-` |
| `strings.tsv` | category (`sids`, `privs`, `agents`, `exts`, `regs`, `folders`, `offices`, `utils`, `stubs`, `strings`), value, group or `--`, technique or `----`, flag (0/1), blacklist (0/1) |
| `namespaces.tsv` | kind (`system` / `custom`), namespace, group or `--`, technique or `----`, flag (0/1) |
| `indicators.tsv` | id, severity, view code, technique or `----`, name, detail (printf format, arguments in the order the engine passes them) |
| `mitre.tsv` | kind (`ta` / `ti`), id, name, tactic (for `ti`), flag, level |
