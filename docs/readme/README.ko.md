<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">Portable Executable을 들여다보는 렌즈 — Rust로 다시 만든 Windows 바이너리 정적 악성코드 초기 분석 도구.</p>

<p align="center">
  <a href="https://github.com/taida957789/PELens/actions/workflows/ci.yml"><img src="https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  · <a href="https://taida957789.github.io/PELens/">Website</a>
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a> ·
  <b>한국어</b> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a>
</p>

---

PELens는 `.exe`, `.dll`, `.sys` 파일을 **실행하지 않고** 검사합니다. 헤더, 임포트, 리소스, 인증서, .NET 메타데이터, 문자열을 보여 주고 MITRE ATT&CK에 매핑된 지표를 생성합니다. **pestudio 9.61**을 Rust로 처음부터 다시 구현했으며, pestudio의 XML 지식 베이스와 `pestudiox` 명령줄과 호환됩니다.

![지표(다크 모드)](../screenshots/indicators-dark.png)

## 스크린샷

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| 임포트: 그룹, MITRE 기법, 플래그 | 문자열: 레이블, 위치 맵, 그룹 |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| 섹션(라이트 모드)과 펼친 트리 뷰 | Authenticode 인증서 체인과 WinVerifyTrust 결과 |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | ![disassembly](../screenshots/disassembly-hex-dark.png) |
| .NET 헤더, 메타데이터 스트림, 테이블, 네임스페이스 | 디스어셈블리(IAT 호출에 함수 이름 표시)와 16진수 보기 |

## 인터페이스 언어

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

인터페이스는 기본적으로 Windows 표시 언어를 따릅니다. "보기 > 언어" 또는 설정 대화 상자에서 바꾸거나 `-lang:<코드>`(`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`)로 시작하세요. 분석 결과(테이블 내용, 지표, 보고서)는 보고서 및 검색과 일치하도록 영어로 유지됩니다. 번역 파일은 `crates/pelens-gui/i18n/`에 있습니다.

## 기능

- pestudio와 같은 **27개 뷰**: image, footprints, groups, indicators, MITRE, VirusTotal 점수, DOS stub/header, Rich header, file/optional header, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest, overlay.
- MITRE ATT&CK 전술·기법에 매핑된 **150개 지표**, 심각도 수정 가능.
- **시그니처 엔진**: 엔트리 포인트 시그니처(PEiD 방식, 니블 와일드카드 지원), 텍스트 시그니처, resources·sections·overlay·base64 안의 내장 파일 탐지.
- **패닉하지 않는 파서**: imports(INT/IAT, 지연 로드, bound), exports(forwarded, anonymous, gaps), resources(version, manifest, 문자열·메시지 테이블, 대화 상자, 메뉴, 아이콘), debug(RSDS, POGO, REPRO, CET), RFC 3161 타임스탬프를 포함한 Authenticode PKCS#7, .NET 메타데이터(45개 테이블 전부).
- **헌팅 도우미**: MD5/SHA-1/SHA-256 지문, imphash(pefile과 동일), VirusTotal·Google·Microsoft Learn·MITRE 링크.
- **파일 수정**: DLL ⇄ EXE 전환, 엔트리 포인트 설정, characteristics 전환, overlay 삭제, 항목 덤프, 내장 파일을 새 분석으로 열기.
- **보고서**: XML, JSON, 텍스트. GUI와 같은 테이블로 만듭니다.
- **GUI**: 트리 뷰, 다크·라이트 테마, 정렬·필터 가능한 테이블, 컨텍스트 메뉴, 드래그 앤 드롭, 단축키(Ctrl+O, S, E, R, X, Tab으로 트리 이동).
- **8개 인터페이스 언어**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch, Français. 기본값은 Windows 표시 언어를 따릅니다.
- **16진수 보기**(Ctrl+H): 보이는 행만 그려 큰 파일도 부드럽습니다. 위치 정보가 있는 항목은 오른쪽 클릭의 "16진수 보기에서 표시"로 열 수 있고, 오프셋이나 RVA로 이동하거나 16진수·텍스트로 복사할 수 있습니다.
- **YARA 검사**(YARA-X): 설정 > YARA 또는 `-yara:<dir>`로 규칙 폴더를 지정합니다. 일치한 규칙마다 지표를 만들고(심각도는 규칙의 `severity` 메타데이터), 일치 위치는 16진수 보기에서 바로 보며 보고서에도 기록됩니다.
- **디스어셈블리**(x86/x64, iced-x86): 진입점, 익스포트 함수, TLS 콜백에서 시작합니다. IAT를 통한 호출은 함수 이름을 보여 주고, 분기 대상을 따라가며, 16진수 보기에서도 볼 수 있습니다.

## 설치／빌드

**다운로드**: [Releases](https://github.com/taida957789/PELens/releases/latest)에서 `PELens-<버전>-windows-x64.zip`을 받아 압축을 풀고 `pelens.exe`를 실행하세요(설치 불필요). 검증용 `.sha256` 파일이 함께 제공됩니다. 소스에서 빌드하려면:

```bash
cargo build --release
# target/release/pelens.exe      (GUI)
# target/release/pelens-cli.exe  (CLI)
```

Rust 1.88 이상(edition 2024)이 필요합니다. Windows 11 x64에서 개발·테스트했습니다.

## 사용법

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir] [-yara:dir]
```

CLI는 기본적으로 pestudio처럼 샘플 옆에 `<input>.xml`을 씁니다.

### 지식 베이스

PELens에는 자체 **오픈 지식 베이스**(`kb/`, CC0)가 내장되어 있습니다. 지표 정의 142개, Windows API 함수 약 2,500개, 의심 문자열 약 900개, 시그니처 약 100개와 MITRE ATT&CK 매핑을 담고 있습니다. `tools/build_kb.py`로 `kb/src`에서 생성하며, 모든 항목은 공개 자료를 바탕으로 작성했습니다([kb/SOURCES.md](../../kb/SOURCES.md) 참고). pestudio의 XML은 복사하지 않았습니다. `-xml:<dir>`로 직접 설치한 pestudio의 XML 파일을 사용할 수도 있습니다. 이 파일은 pestudio 작성자의 것이므로 PELens와 함께 배포되지 않습니다.

### VirusTotal

**해시만** 전송하며 샘플은 절대 업로드하지 않습니다. 설정 대화 상자나 `VT_API_KEY`에 본인의 API 키를 넣으세요. 기본은 API v3이며 v2도 선택할 수 있습니다.

## 프로젝트 구조

| crate | 역할 |
|---|---|
| `pe-parser` | PE 파싱(경계 검사, 패닉 없음)과 패치 |
| `pe-db` | pestudio XML 지식 베이스(서식을 유지한 채 읽기·쓰기) |
| `pe-analysis` | 지표, 시그니처, 문자열, 뷰, 보고서, 동작 |
| `pe-online` | VirusTotal, 검색 링크, 업데이트 확인 |
| `pelens-cli` | 명령줄(pestudiox 호환) |
| `pelens-gui` | eframe/egui GUI |

설계 문서: [기능 목록](../FEATURE_INVENTORY.md)(212개 항목, 각 항목에 구현 위치 연결) · [개발 계획](../DEVELOPMENT_PLAN.md) · [작업 목록](../TASKLIST.md).

## 품질

```bash
cargo test --workspace                       # 테스트 107개
cargo llvm-cov --workspace --summary-only    # 라인 커버리지 약 97%
python tools/crossval.py 250                 # pefile과 교차 검증
```

## 면책 조항

PELens는 독립 프로젝트이며 Winitor 및 pestudio 작성자와 관련이 없고 보증을 받지 않았습니다. 분석 권한이 있는 파일에만 사용하세요.
