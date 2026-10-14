<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">Una lente para Portable Executables: evaluación inicial estática de malware para binarios de Windows, reconstruida en Rust.</p>

<p align="center">
  [![CI](https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg)](https://github.com/taida957789/PELens/actions/workflows/ci.yml)
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a> ·
  <a href="README.ko.md">한국어</a> ·
  <b>Español</b> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a>
</p>

---

PELens examina archivos `.exe`, `.dll` y `.sys` **sin ejecutarlos**. Muestra sus cabeceras, importaciones, recursos, certificados, metadatos .NET y cadenas, y genera indicadores asociados a MITRE ATT&CK. Es una reimplementación desde cero en Rust de **pestudio 9.61**, compatible con su base de conocimiento XML y con la línea de comandos `pestudiox`.

![Indicadores (modo oscuro)](../screenshots/indicators-dark.png)

## Capturas

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| Importaciones con grupos, técnicas MITRE y marcas | Cadenas con etiquetas, mapa de ubicación y grupos |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| Secciones (modo claro) con la vista de árbol expandida | Cadena de certificados Authenticode y resultado de WinVerifyTrust |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | |
| Cabecera .NET, flujos de metadatos, tablas y espacios de nombres | |

## Idiomas de la interfaz

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

La interfaz sigue por defecto el idioma de visualización de Windows. Cámbielo en «ver > idioma» o en la configuración, o inicie con `-lang:<código>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Los resultados del análisis (contenido de las tablas, indicadores, informes) se mantienen en inglés para coincidir con los informes y las búsquedas. Las traducciones están en `crates/pelens-gui/i18n/`.

## Funciones

- **27 vistas** como en pestudio: image, footprints, groups, indicators, MITRE, puntuación de VirusTotal, DOS stub y header, Rich header, file y optional headers, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest y overlay.
- **150 indicadores**, asociados a tácticas y técnicas de MITRE ATT&CK, con severidad editable.
- **Motor de firmas**: firmas del punto de entrada (estilo PEiD, con comodines de nibble), firmas de texto y detección de archivos incrustados en recursos, secciones, el overlay y datos base64.
- **Analizador que nunca entra en pánico**: imports (INT/IAT, carga diferida, bound), exports (reenviados, anónimos, huecos), recursos (version, manifest, tablas de cadenas y mensajes, diálogos, menús, iconos), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 con sellos de tiempo RFC 3161 y metadatos .NET (las 45 tablas).
- **Ayudas para threat hunting**: huellas MD5/SHA-1/SHA-256, imphash (idéntico al de pefile) y enlaces a VirusTotal, Google, Microsoft Learn y MITRE.
- **Modificación de archivos**: cambiar entre DLL y EXE, fijar el punto de entrada, alternar characteristics, borrar el overlay, volcar cualquier elemento y abrir un archivo incrustado en un nuevo análisis.
- **Informes** en XML, JSON o texto, generados a partir de las mismas tablas que muestra la GUI.
- **GUI**: vista de árbol, temas oscuro y claro, tablas ordenables y filtrables, menús contextuales, arrastrar y soltar, y atajos (Ctrl+O, S, E, R, X; Tab recorre el árbol).
- **Interfaz en 8 idiomas**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch y Français; por defecto sigue el idioma de Windows.

## Instalación / compilación

**Descarga**: obtenga `PELens-<versión>-windows-x64.zip` en [Releases](https://github.com/taida957789/PELens/releases/latest), descomprímalo y ejecute `pelens.exe` (sin instalación). Incluye un `.sha256` para verificarlo. Para compilar desde el código fuente:

```bash
cargo build --release
# target/release/pelens.exe      (GUI)
# target/release/pelens-cli.exe  (CLI)
```

Requiere Rust 1.85 o posterior (edition 2024). Desarrollado y probado en Windows 11 x64.

## Uso

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir]
```

Por defecto la CLI escribe `<input>.xml` junto a la muestra, igual que pestudio.

### Base de conocimiento

PELens lee los archivos XML de pestudio (`settings.xml`, `indicators.xml`, `functions.xml`, `signatures.xml`, …) de tu propia instalación de pestudio. Indícalos con `-xml:<dir>` o coloca una carpeta `xml` junto al ejecutable. **Estos archivos no se distribuyen con PELens**: pertenecen al autor de pestudio. Sin ellos, PELens funciona con valores predeterminados integrados.

### VirusTotal

Solo se envía el **hash**; las muestras nunca se suben. Configura tu propia clave de API en el diálogo de ajustes o en `VT_API_KEY`. Se usa la API v3 por defecto; la v2 está disponible como opción.

## Estructura del proyecto

| crate | función |
|---|---|
| `pe-parser` | análisis PE (con comprobación de límites, sin pánicos) y parcheo |
| `pe-db` | base de conocimiento XML de pestudio, lectura y escritura sin reformatear |
| `pe-analysis` | indicadores, firmas, cadenas, vistas, informes, acciones |
| `pe-online` | VirusTotal, enlaces de búsqueda, comprobación de actualizaciones |
| `pelens-cli` | línea de comandos (compatible con pestudiox) |
| `pelens-gui` | GUI eframe/egui |

Documentación de diseño: [inventario de funciones](../FEATURE_INVENTORY.md) (212 elementos, cada uno enlazado a su implementación) · [plan de desarrollo](../DEVELOPMENT_PLAN.md) · [lista de tareas](../TASKLIST.md).

## Calidad

```bash
cargo test --workspace                       # 87 pruebas
cargo llvm-cov --workspace --summary-only    # ≈ 97 % de cobertura de líneas
python tools/crossval.py 250                 # verificación cruzada con pefile
```

## Aviso

PELens es un proyecto independiente. No está afiliado a Winitor ni al autor de pestudio, ni cuenta con su respaldo. Úsalo solo con archivos que tengas autorización para analizar.
