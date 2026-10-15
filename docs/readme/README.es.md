<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">Una lente para Portable Executables: evaluación inicial estática de malware para binarios de Windows, reconstruida en Rust.</p>

<p align="center">
  <a href="https://github.com/taida957789/PELens/actions/workflows/ci.yml"><img src="https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  · <a href="https://taida957789.github.io/PELens/">Website</a>
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

PELens examina archivos `.exe`, `.dll` y `.sys` **sin ejecutarlos**. Muestra sus cabeceras, importaciones, recursos, certificados, metadatos .NET y cadenas, y genera indicadores asociados a MITRE ATT&CK. Está escrito desde cero en Rust y funciona con una base de conocimiento XML que puede ampliar o sustituir.

![Indicadores (modo oscuro)](../screenshots/indicators-dark.png)

## Capturas

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| Importaciones con grupos, técnicas MITRE y marcas | Cadenas con etiquetas, mapa de ubicación y grupos |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| Secciones (modo claro) con la vista de árbol expandida | Cadena de certificados Authenticode y resultado de WinVerifyTrust |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | ![disassembly](../screenshots/disassembly-hex-dark.png) |
| Cabecera .NET, flujos de metadatos, tablas y espacios de nombres | Desensamblado (llamadas por la IAT con su nombre) y vista hexadecimal |

## Idiomas de la interfaz

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

La interfaz sigue por defecto el idioma del sistema (idioma de Windows, idioma preferido de macOS, `LANG` en Linux). Cámbielo en «ver > idioma» o en la configuración, o inicie con `-lang:<código>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Los resultados del análisis (contenido de las tablas, indicadores, informes) se mantienen en inglés para coincidir con los informes y las búsquedas. Las traducciones están en `crates/pelens-gui/i18n/`.

## Funciones

- **27 vistas**: image, footprints, groups, indicators, MITRE, puntuación de VirusTotal, DOS stub y header, Rich header, file y optional headers, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest y overlay.
- **150 indicadores**, asociados a tácticas y técnicas de MITRE ATT&CK, con severidad editable.
- **Motor de firmas**: firmas del punto de entrada (estilo PEiD, con comodines de nibble), firmas de texto y detección de archivos incrustados en recursos, secciones, el overlay y datos base64.
- **Analizador que nunca entra en pánico**: imports (INT/IAT, carga diferida, bound), exports (reenviados, anónimos, huecos), recursos (version, manifest, tablas de cadenas y mensajes, diálogos, menús, iconos), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 con sellos de tiempo RFC 3161 y metadatos .NET (las 45 tablas).
- **Ayudas para threat hunting**: huellas MD5/SHA-1/SHA-256, imphash (idéntico al de pefile) y enlaces a VirusTotal, Google, Microsoft Learn y MITRE.
- **Modificación de archivos**: cambiar entre DLL y EXE, fijar el punto de entrada, alternar characteristics, borrar el overlay, volcar cualquier elemento y abrir un archivo incrustado en un nuevo análisis.
- **Informes** en XML, JSON o texto, generados a partir de las mismas tablas que muestra la GUI.
- **GUI**: vista de árbol, temas oscuro y claro, tablas ordenables y filtrables, menús contextuales, arrastrar y soltar, y atajos (Ctrl+O, S, E, R, X; Tab recorre el árbol).
- **Interfaz en 8 idiomas**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch y Français; por defecto sigue el idioma del sistema.
- **Vista hexadecimal** (Ctrl+H): solo dibuja las filas visibles, también fluida con archivos grandes; los elementos con posición se abren con «mostrar en hexadecimal» del menú contextual, con salto a un desplazamiento o RVA y copia como hexadecimal o texto.
- **Análisis YARA** (YARA-X): indique la carpeta de reglas en configuración > YARA o con `-yara:<dir>`; cada regla que coincide genera un indicador (gravedad según el metadato `severity` de la regla), las coincidencias se abren en la vista hexadecimal y aparecen en los informes.
- **Desensamblado** (x86/x64, iced-x86): desde el punto de entrada, una función exportada o un callback TLS; las llamadas a través de la IAT muestran el nombre de la función, se pueden seguir los saltos y abrir en la vista hexadecimal.
- **Multiplataforma**: las mismas funciones en Windows, Linux y macOS: fuera de Windows, Authenticode se verifica con un verificador propio en Rust puro (raíces de Microsoft + raíces del sistema); la clave de VirusTotal se guarda en el almacén de credenciales del sistema (Administrador de credenciales, Llavero de macOS, Secret Service de Linux); comprobación de unidades de red/extraíbles y ACL; fuentes CJK del sistema; atajos con ⌘ en macOS.

## Instalación / compilación

**Descarga**: obtenga el archivo de su plataforma (`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`) en [Releases](https://github.com/taida957789/PELens/releases/latest); cada uno incluye un `.sha256` para verificarlo. Windows: descomprima y ejecute `pelens.exe`. Linux: descomprima y ejecute `./pelens`, o `./install.sh` para instalarlo en `~/.local` (con entrada de escritorio e icono). macOS (Apple silicon e Intel): descomprima y mueva `PELens.app` a Aplicaciones; la primera vez use clic derecho > Abrir (sin notarización de Apple). Para compilar desde el código fuente:

```bash
cargo build --release
# target/release/pelens      (GUI; pelens.exe on Windows)
# target/release/pelens-cli  (CLI; pelens-cli.exe on Windows)
```

Requiere Rust 1.88 o posterior (edition 2024). La CI compila y ejecuta todas las pruebas en Windows, Linux y macOS.

## Uso

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir] [-yara:dir]
```

Por defecto la CLI escribe `<input>.xml` junto a la muestra.

### Base de conocimiento

PELens incluye su propia **base de conocimiento abierta** (`kb/`, CC0): 142 definiciones de indicadores, unas 2.500 funciones de la API de Windows, unas 900 cadenas sospechosas, unas 100 firmas y la correspondencia con MITRE ATT&CK. Se genera desde `kb/src` con `tools/build_kb.py` y cada entrada se escribió a partir de fuentes públicas (ver [kb/SOURCES.md](../../kb/SOURCES.md)); no copia ninguna base de conocimiento de terceros. También puede usar otros archivos de conocimiento XML con el mismo formato mediante `-xml:<dir>`; los archivos de terceros no se distribuyen con PELens.

### VirusTotal

Solo se envía el **hash**; las muestras nunca se suben. Configura tu propia clave de API en el diálogo de ajustes o en `VT_API_KEY`. Se usa la API v3 por defecto; la v2 está disponible como opción.

## Estructura del proyecto

| crate | función |
|---|---|
| `pe-parser` | análisis PE (con comprobación de límites, sin pánicos) y parcheo |
| `pe-db` | base de conocimiento XML, lectura y escritura sin reformatear |
| `pe-analysis` | indicadores, firmas, cadenas, vistas, informes, acciones |
| `pe-online` | VirusTotal, enlaces de búsqueda, comprobación de actualizaciones |
| `pelens-cli` | línea de comandos |
| `pelens-gui` | GUI eframe/egui |

Documentación de diseño: [inventario de funciones](../FEATURE_INVENTORY.md) (212 elementos, cada uno enlazado a su implementación) · [plan de desarrollo](../DEVELOPMENT_PLAN.md) · [lista de tareas](../TASKLIST.md).

## Calidad

```bash
cargo test --workspace                       # 107 pruebas
cargo llvm-cov --workspace --summary-only    # ≈ 97 % de cobertura de líneas
python tools/crossval.py 250                 # verificación cruzada con pefile
```

## Aviso

PELens es un proyecto independiente. Úsalo solo con archivos que tengas autorización para analizar.
