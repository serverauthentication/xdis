# xdis

High-speed, zero-external-native-dependency reverse engineering workbench written in C11 + MASM x64 AVX2, paired with an Electron desktop UI, a zero-dependency Python 3 SDK, and a 35-tool MCP server.

## Overview

- **Core engine (`src/`):** ~60.7k lines of C11 + MASM x64 AVX2, building cleanly at MSVC `/W4` (0 warnings) into a single ~1.5 MB `xdis.exe` with no third-party native libraries.
- **Desktop UI (`app/`):** Electron interface with `IDA Dark` and `IDA Classic` themes, synchronized disassembly (`IDA View-A`) + decompiler (`Pseudocode-A`) split view, CFG graph view, hex/patch view, debugger, protection/deobfuscation lab, security audit/Hilbert map, Live Collab, and `Ctrl+K` command palette.
- **Automation & AI (`sdk/`, `mcp/`):** Zero-dependency Python 3 SDK (`sdk/xdis.py`) and 35-tool JSON-RPC 2.0 MCP server (`mcp/server.py`).

## Key Capabilities

### Disassemblers & Assembler (`src/arch/`)
- **x86-64 & x86-32 (`x86.c`):** Full EVEX / AVX-512 (`zmm0..31`, `{k}{z}`, `{1toN}`, `{rn-sae}`, compressed `disp8*N`), VEX / AVX / AVX2 / FMA3, BMI1/BMI2, AMD XOP (`0x8F`), MMX (`mm0..7`), x87 FPU (`0xD8..0xDF`), segment-prefixed moffs (`fs:`/`gs:`), legacy 32-bit x86 + `0x67` 16-bit ModRM, and invalid-encoding rejection.
- **Multi-architecture (`arm64.c`, `multi.c`):** ARM64 (128-bit SIMD `q` load/store, NEON, FP, atomics, bitfield, PAC), ARM32 + Thumb-1 (16-bit) / Thumb-2 (32-bit) with odd-VA interworking, MIPS32, RISC-V, WebAssembly (`0xFC`/`0xFD`/`0xFE`), Dalvik (DEX), and .NET CIL.
- **x86/x64 Assembler (`asm.c`):** Register, immediate, and full memory operands (`[base+idx*scale+disp]`, `[rip+disp]`, `fs:`/`gs:`, sized `ptr`), `lea`, 1/2/3-operand `imul`, shifts/rotates, 8/16/32/64-bit registers, and hex branch targets.

### Binary Formats & Debug Symbols (`src/bin/`)
- **Formats:** PE32 / PE32+ (chained `.pdata` `UNW_FLAG_CHAININFO` merging, ARM32 PE routing, delay-imports, forwarded exports, .NET CLR metadata, TLS/relocs/resources), ELF32 / ELF64, Mach-O (incl. fat binaries), WebAssembly, DEX, Minidump (`.dmp`), and raw binaries.
- **Debug Info & Demangling:** MSF/PDB TPI/DBI parser (with cycle/step budgets), DWARF parser (abbrev hash/cache), and MSVC / Itanium / Rust symbol demangling.
- **Hardened Loaders:** Overflow-safe bounds checks and global symbol/string-pool budgets (`BIN_MAX_SYMS`, `BIN_MAX_POOL`), plus UTF-8 to UTF-16 `CreateFileW` / `_wfopen` / `CommandLineToArgvW` support for Unicode paths on Windows.

### Decompiler v2 & Static Analysis (`src/ana/`)
- **Decompiler v2 (`hlir.c`, `type_inf.c`, `struct_cfg.c`, `dec.c`):** Function-wide pruned SSA -> HLIR expression tree -> 684-API + interprocedural + `typ_store` type inference -> IPDOM structural AST & C pretty-printer.
  - Supports `float`/`double` returns, SSE `movsd`, Win64 `va_start` + stack varargs, `const char *` byte-pointer array vs. struct distinction, valid C 128-bit high-multiply emission, unsigned operator printing, MSVC x64 jump-table (`switch`) recovery, and large-function CFG limits (up to 2,048 blocks / 65,536 instructions with explicit truncation reporting).
- **Deobfuscation & Analysis:** Control-flow flattening (CFF) recovery, verified MBA simplifier, VM handler lifting, API hash & string decryption, PE unpacker, taint & symbolic micro-emulator, C header parser (`.xtypes`), and auto-signature matching (`.xsig`).
- **Forensics & Audit (`forensics.c`, `vuln.c`):** Built-in YARA rule engine, embedded file carver, IOC extractor, vulnerability & security patch-diff triage, and 512x512 Hilbert entropy map.

### Debugger v2 (`src/dbg/`)
- Native Windows debugger, remote GDB RSP client, and Windows Minidump (`.dmp`) loader.
- Conditional software breakpoints (`dbg_read_mem` `0xCC` masking + `dbg_write_mem` `orig` sync), multi-thread hardware breakpoints (`DR0..DR3` propagated across all threads and `CREATE_THREAD_DEBUG_EVENT`), `PAGE_GUARD` memory breakpoints, `pause`, `set_reg`, hardened `step_out`, Delta Time-Travel Debugging (`Who Wrote?`), live PE dumping, and leak-free debuggee teardown.

### Security Model
- **Electron Bridge (`app/main.js`):** 256-bit per-session `XDIS_RPC_TOKEN` (`crypto.timingSafeEqual`, 3-strike lockout), `worker_threads` isolated JS script sandbox with hard timeout, `will-navigate` & `setWindowOpenHandler` blocking, dialog-confirmed `writeText` path allowlisting, and bounded Live Collab buffers with optional room secret & unique nick ownership.
- **Plugins (`src/ext/ext.c`):** Resolved strictly relative to `xdis.exe` (never CWD), `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`, and explicit `[security] plugins_allow` allowlist in `xdis.ini`.
- **MCP (`mcp/server.py`):** Strict `va`/parameter validation and `debug_control launch` guard restricting launches to the currently loaded binary (or explicit `XDIS_MCP_LAUNCH_ALLOWLIST` / `XDIS_MCP_ALLOW_LAUNCH` opt-in).

## Building (Windows x64)

### Requirements
- Visual Studio 2022 or 18 (MSVC `cl` + `ml64`, x64 Native Tools)
- Node.js + npm (for the Electron desktop UI in `app/`)
- Python 3.10+ (optional, for `sdk/xdis.py` and `mcp/server.py`)

### Build Core Engine & Plugin
```bat
build.bat
xdis.exe --test
```

### Install & Launch Desktop UI
```bat
cd app
npm install
cd ..
run.bat [optional-binary-path]
```

## CLI Usage

```bat
xdis.exe <binary> --info
xdis.exe <binary> --funcs
xdis.exe <binary> --strings
xdis.exe <binary> --dis [va] [count]
xdis.exe <binary> --cfg [va]
xdis.exe <binary> --dec [va]
xdis.exe <binary> --xrefs <va>
xdis.exe <binary> --find "48 83 EC ?? E8"
xdis.exe --rpc
xdis.exe --test
xdis.exe --bench [MB]
```

## Python SDK & MCP Server

```python
import sys
sys.path.insert(0, "sdk")
import xdis

with xdis.open("xdis.exe") as b:
    print(b.info())
    print(b.decompile(b.entry))
```

Start the 35-tool MCP stdio server:
```bat
python mcp\server.py
```

## Project Layout

```text
src/
  core/   File mapping (Win32 UTF-16 COW) & open-addressing hash tables
  scan/   AVX2 + x64 SIMD byte/pattern/string scanners (MASM)
  bin/    PE, ELF, Mach-O, WASM/DEX/CLR, PDB/MSF, DWARF, demangler
  arch/   x86/x64, ARM64, ARM32/Thumb, MIPS, RISC-V, WASM/CIL, x86/x64 asm
  ana/    CFG, SSA IR, HLIR, type inference, Decompiler v2, CFF/MBA/VM/taint/YARA/vuln
  dbg/    Win32 native debugger + Delta TTD, GDB RSP, Minidump
  cli/    CLI runner, JSONL RPC engine, self-test suite
  ext/    Allowlisted native plugin loader
  opt/    INI configuration loader
  ui/     Lightweight Win32 native UI
plugins/  Sample entropy plugin (entropy.c)
app/      Electron desktop UI
sdk/      Zero-dependency Python 3 SDK
mcp/      35-tool MCP stdio server
```
