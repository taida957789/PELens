<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">Une loupe pour les Portable Executables : évaluation initiale statique des malwares pour les binaires Windows, réécrite en Rust.</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a> ·
  <a href="README.ko.md">한국어</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <b>Français</b>
</p>

---

PELens examine les fichiers `.exe`, `.dll` et `.sys` **sans les exécuter**. Il affiche leurs en-têtes, imports, ressources, certificats, métadonnées .NET et chaînes, et génère des indicateurs associés à MITRE ATT&CK. C'est une réécriture complète de **pestudio 9.61** en Rust, compatible avec sa base de connaissances XML et avec la ligne de commande `pestudiox`.

![Indicateurs (mode sombre)](../screenshots/indicators-dark.png)

## Captures d'écran

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| Imports avec groupes, techniques MITRE et marqueurs | Chaînes avec étiquettes, carte des emplacements et groupes |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| Sections en mode clair avec l'arborescence dépliée | Chaîne de certificats Authenticode et résultat de WinVerifyTrust |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | |
| En-tête .NET, flux de métadonnées, tables et espaces de noms | |

## Fonctionnalités

- **27 vues** comme dans pestudio : image, footprints, groups, indicators, MITRE, score VirusTotal, stub et en-tête DOS, en-tête Rich, en-têtes file et optional, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest et overlay.
- **150 indicateurs**, associés aux tactiques et techniques MITRE ATT&CK, avec une gravité modifiable.
- **Moteur de signatures** : signatures du point d'entrée (style PEiD, avec jokers au niveau du quartet), signatures texte et détection de fichiers intégrés dans les ressources, les sections, l'overlay et les données base64.
- **Analyseur qui ne panique jamais** : imports (INT/IAT, chargement différé, bound), exports (redirigés, anonymes, trous), ressources (version, manifest, tables de chaînes et de messages, boîtes de dialogue, menus, icônes), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 avec horodatages RFC 3161 et métadonnées .NET (les 45 tables).
- **Aide au threat hunting** : empreintes MD5/SHA-1/SHA-256, imphash (identique à celui de pefile) et liens vers VirusTotal, Google, Microsoft Learn et MITRE.
- **Modification de fichiers** : basculer entre DLL et EXE, définir le point d'entrée, basculer les characteristics, supprimer l'overlay, extraire n'importe quel élément et ouvrir un fichier intégré dans une nouvelle analyse.
- **Rapports** en XML, JSON ou texte, construits à partir des mêmes tables que celles de l'interface.
- **Interface graphique** : arborescence, thèmes sombre et clair, tableaux triables et filtrables, menus contextuels, glisser-déposer et raccourcis (Ctrl+O, S, E, R, X ; Tab parcourt l'arborescence).

## Installation / compilation

```bash
cargo build --release
# target/release/pelens.exe      (GUI)
# target/release/pelens-cli.exe  (CLI)
```

Nécessite Rust 1.85 ou plus récent (édition 2024). Développé et testé sous Windows 11 x64.

## Utilisation

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-expand] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir]
```

Par défaut, la CLI écrit `<input>.xml` à côté de l'échantillon, comme pestudio.

### Base de connaissances

PELens lit les fichiers XML de pestudio (`settings.xml`, `indicators.xml`, `functions.xml`, `signatures.xml`…) depuis votre propre installation de pestudio. Indiquez-les avec `-xml:<dir>` ou placez un dossier `xml` à côté de l'exécutable. **Ces fichiers ne sont pas distribués avec PELens** : ils appartiennent à l'auteur de pestudio. Sans eux, PELens fonctionne avec des valeurs par défaut intégrées.

### VirusTotal

Seul le **hash** est envoyé ; les échantillons ne sont jamais téléversés. Saisissez votre propre clé d'API dans la boîte de dialogue des réglages ou dans `VT_API_KEY`. L'API v3 est utilisée par défaut ; la v2 est disponible en option.

## Structure du projet

| crate | rôle |
|---|---|
| `pe-parser` | analyse PE (bornes vérifiées, jamais de panique) et modification |
| `pe-db` | base de connaissances XML de pestudio, lecture et écriture sans reformatage |
| `pe-analysis` | indicateurs, signatures, chaînes, vues, rapports, actions |
| `pe-online` | VirusTotal, liens de recherche, vérification des mises à jour |
| `pelens-cli` | ligne de commande (compatible pestudiox) |
| `pelens-gui` | interface eframe/egui |

Documents de conception : [inventaire des fonctionnalités](../FEATURE_INVENTORY.md) (212 éléments, chacun relié à son implémentation) · [plan de développement](../DEVELOPMENT_PLAN.md) · [liste des tâches](../TASKLIST.md).

## Qualité

```bash
cargo test --workspace                       # 70 tests
cargo llvm-cov --workspace --summary-only    # ≈ 97 % de couverture des lignes
python tools/crossval.py 250                 # vérification croisée avec pefile
```

## Avertissement

PELens est un projet indépendant. Il n'est ni affilié à Winitor ni à l'auteur de pestudio, ni approuvé par eux. Ne l'utilisez que sur des fichiers que vous êtes autorisé à analyser.
