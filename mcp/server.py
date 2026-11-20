from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
SDK_DIR = str(ROOT / "sdk")
if SDK_DIR not in sys.path:
    sys.path.insert(0, SDK_DIR)

import xdis

PROTOCOL_VERSION = "2024-11-05"
SERVER_VERSION = "3.0.0"
SERVER_INFO = {"name": "xdis", "version": SERVER_VERSION}


def _schema(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        out["required"] = required
    return out


TOOLS: list[dict[str, Any]] = [
    {
        "name": "open_binary",
        "description": "Open and analyze a binary file (PE, ELF, Mach-O, or raw) in xdis.",
        "inputSchema": _schema({"path": {"type": "string", "description": "Path to target binary"}}, ["path"]),
    },
    {
        "name": "get_triage",
        "description": "Get packing/obfuscation verdict, scores, section entropies, API capabilities, and hotspots.",
        "inputSchema": _schema({}),
    },
    {
        "name": "list_functions",
        "description": "List analyzed functions with optional substring filter and pagination.",
        "inputSchema": _schema({
            "query": {"type": "string", "description": "Case-insensitive name substring filter"},
            "limit": {"type": "integer", "description": "Max functions to return (default 50)"},
            "offset": {"type": "integer", "description": "Pagination offset (default 0)"},
        }),
    },
    {
        "name": "disassemble",
        "description": "Disassemble instructions starting at a virtual address or symbol name.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address (e.g. 0x140001000) or symbol name"},
            "count": {"type": "integer", "description": "Instruction count (default 32)"},
        }, ["va"]),
    },
    {
        "name": "decompile",
        "description": "Decompile the function containing a virtual address or symbol into C-like pseudocode.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
        }, ["va"]),
    },
    {
        "name": "get_microcode",
        "description": "Lift a function into simplified IR microcode ops and recovered struct layouts.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
        }, ["va"]),
    },
    {
        "name": "get_xrefs",
        "description": "List incoming call, jump, and data cross-references to an address or symbol.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
        }, ["va"]),
    },
    {
        "name": "find_pattern",
        "description": "Search binary bytes for a hex pattern (supports ?? wildcards) or text string.",
        "inputSchema": _schema({
            "query": {"type": "string", "description": "Hex byte pattern (e.g. 48 8b ?? 24) or ASCII string"},
        }, ["query"]),
    },
    {
        "name": "find_crypto",
        "description": "Scan the open binary for known cryptographic constants (AES, SHA, RC4, etc.).",
        "inputSchema": _schema({}),
    },
    {
        "name": "pathfind",
        "description": "Find a call graph path from a source function/VA to a target function/VA.",
        "inputSchema": _schema({
            "src": {"type": "string", "description": "Source hex VA or symbol name"},
            "dst": {"type": "string", "description": "Destination hex VA or symbol name"},
        }, ["src", "dst"]),
    },
    {
        "name": "semantic_diff",
        "description": "Diff functions of the currently open binary against a second binary.",
        "inputSchema": _schema({
            "other_path": {"type": "string", "description": "Path to second binary to compare against"},
        }, ["other_path"]),
    },
    {
        "name": "deobfuscate",
        "description": "Analyze and simplify junk code, opaque predicates, folded constants, and stack strings.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
        }, ["va"]),
    },
    {
        "name": "emulate",
        "description": "Symbolically/concretely emulate instructions from an address and return register/step trace.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Start hex virtual address or symbol name"},
            "steps": {"type": "integer", "description": "Max instruction steps (default 48)"},
        }, ["va"]),
    },
    {
        "name": "annotate",
        "description": "Rename a symbol and/or attach an analyst comment at a virtual address.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Target hex virtual address or symbol name"},
            "name": {"type": "string", "description": "New symbol name to assign"},
            "comment": {"type": "string", "description": "Comment text to attach"},
        }, ["va"]),
    },
    {
        "name": "get_ssa",
        "description": "Lift a function into 3-tier SSA IR (MLIR or LLIR) with dominators, phi nodes, SCCP/GVN/DCE metrics, prototype, and typed SSA variables.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
            "tier": {"type": "string", "enum": ["mlir", "llir"], "description": "SSA tier: 'mlir' (default) or 'llir'"},
        }, ["va"]),
    },
    {
        "name": "get_lang_info",
        "description": "Detect binary runtime language (C++, Go, Rust, ObjC, C/Native), C++ RTTI class hierarchy, Go .gopclntab functions, and Rust source paths.",
        "inputSchema": _schema({}),
    },
    {
        "name": "manage_snapshots",
        "description": "Manage project .xdb v3 snapshots and undo/redo history (list, save, load, undo, redo).",
        "inputSchema": _schema({
            "action": {
                "type": "string",
                "enum": ["list", "save", "load", "undo", "redo"],
                "description": "Snapshot/history action: list, save, load, undo, or redo",
            },
            "name": {"type": "string", "description": "Snapshot name (required for save and load)"},
        }, ["action"]),
    },
    {
        "name": "unflatten_cff",
        "description": "Detect Control Flow Flattening (CFF) dispatcher/state variable and recover real-block edges.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
        }, ["va"]),
    },
    {
        "name": "simplify_mba",
        "description": "Simplify a Mixed Boolean-Arithmetic (MBA) expression directly (expr) or scan a function for MBA hits (va).",
        "inputSchema": _schema({
            "expr": {"type": "string", "description": "MBA expression to evaluate (e.g. (x ^ y) + 2 * (x & y))"},
            "va": {"type": "string", "description": "Hex virtual address or symbol name to scan when expr is omitted"},
        }),
    },
    {
        "name": "analyze_vm",
        "description": "Detect VM dispatcher/handler table, classify virtual opcode handlers, and lift folded virtual trace.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
        }, ["va"]),
    },
    {
        "name": "resolve_hashes_and_strings",
        "description": "Resolve FNV1a/DJB2/ROR13/CRC32/SDBM API hashes across the binary and decrypt XOR/ADD/ROL strings.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Optional hex virtual address or symbol name for string decryption focus"},
            "apply": {"type": "boolean", "description": "Annotate resolved hashes and decrypted strings in the analysis database"},
        }),
    },
    {
        "name": "taint_analysis",
        "description": "Run static forward taint tracking and Win32/libc API shims from an address to detect tainted sinks, branches, stores, and indirect jumps.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Start hex virtual address or symbol name"},
            "reg": {"type": "string", "description": "Source tainted register (default 'rcx')"},
            "buf_len": {"type": "integer", "description": "Optional tainted input buffer byte length pointed to by reg (default 0)"},
            "steps": {"type": "integer", "description": "Max instruction steps (default 128)"},
        }, ["va"]),
    },
    {
        "name": "solve_path_constraints",
        "description": "Solve CFG path reachability between two addresses, collect symbolic branch constraints, and synthesize concrete witness inputs.",
        "inputSchema": _schema({
            "src": {"type": "string", "description": "Start hex virtual address or symbol name"},
            "dst": {"type": "string", "description": "Target hex virtual address or symbol name"},
        }, ["src", "dst"]),
    },
    {
        "name": "inspect_minidump",
        "description": "Parse a Windows crash dump (.dmp) and return OS version, CPU count, faulting exception code/address, thread register contexts, and loaded modules.",
        "inputSchema": _schema({
            "path": {"type": "string", "description": "Path to Windows .dmp minidump file"},
        }, ["path"]),
    },
    {
        "name": "debug_control",
        "description": "Control the Win32 local debugger and delta time-travel recorder (launch, step, step_over, step_out, cont, pause, set_reg, bp, write_mem, mmap, bt, ttd_rec, ttd_back, ttd_who, kill, detach).",
        "inputSchema": _schema({
            "action": {
                "type": "string",
                "enum": [
                    "launch", "step", "step_over", "step_out", "cont", "pause", "set_reg",
                    "bp", "write_mem", "mmap", "bt", "ttd_rec", "ttd_back", "ttd_who",
                    "kill", "detach",
                ],
                "description": "Debugger action to execute",
            },
            "va": {"type": "string", "description": "Target hex virtual address or symbol name (for bp, write_mem, or ttd_who)"},
            "path": {"type": "string", "description": "Optional executable path (for launch; restricted to the currently open binary unless allowlisted)"},
            "args": {"type": "string", "description": "Optional command-line arguments (for launch)"},
            "cond": {"type": "string", "description": "Optional condition expression for conditional breakpoint (for bp)"},
            "reg": {"type": "string", "description": "Register name (for set_reg or ttd_who, e.g. rax, rip, rflags)"},
            "val": {"type": "string", "description": "New register value as hex or integer string (required for set_reg, e.g. 0x1234)"},
            "hex": {"type": "string", "description": "Hex bytes to write to debuggee memory (required for write_mem, e.g. '90 90' or '9090')"},
            "steps": {"type": "integer", "description": "Max TTD delta steps to record (for ttd_rec, default 64)"},
        }, ["action"]),
    },
    {
        "name": "generate_unique_sig",
        "description": "Generate a unique relocation-masked byte signature (IDA pattern and C bytes/mask) for an address or function.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Hex virtual address or symbol name"},
        }, ["va"]),
    },
    {
        "name": "import_c_header",
        "description": "Import C/C++ type definitions from raw header text, a .h/.hpp file path, or a built-in .xtil stdlib pack ('win32' or 'posix').",
        "inputSchema": _schema({
            "text": {"type": "string", "description": "Inline C/C++ header declarations to parse"},
            "path": {"type": "string", "description": "Path to a .h/.hpp header file"},
            "stdlib": {"type": "string", "enum": ["win32", "posix"], "description": "Built-in .xtil type library pack ('win32' or 'posix')"},
        }),
    },
    {
        "name": "inspect_metadata",
        "description": "Inspect .NET CLR metadata ('dotnet'), embedded DWARF ('dwarf'), native MSF PDB ('pdb_msf'), or live/static struct overlay ('struct_apply').",
        "inputSchema": _schema({
            "kind": {
                "type": "string",
                "enum": ["dotnet", "dwarf", "pdb_msf", "struct_apply"],
                "description": "Metadata action: 'dotnet' (default), 'dwarf', 'pdb_msf', or 'struct_apply'",
            },
            "struct_name": {"type": "string", "description": "Loaded struct type name (required for struct_apply)"},
            "va": {"type": "string", "description": "Hex virtual address or symbol name (for struct_apply; defaults to entry)"},
            "pdb_path": {"type": "string", "description": "Path to .pdb file (required for pdb_msf)"},
        }),
    },
    {
        "name": "yara_scan",
        "description": "Scan the open binary with custom YARA rules (or built-in default rules when rules is omitted) and return rule hits with VAs and file offsets.",
        "inputSchema": _schema({
            "rules": {"type": "string", "description": "Optional YARA rules text; omit or leave empty to run built-in default rules"},
        }),
    },
    {
        "name": "carve_embedded_files",
        "description": "Carve embedded payloads (PE, ELF, ZIP, PNG, PDF, certificates, etc.) from the open binary with offsets, VAs, sizes, and entropies.",
        "inputSchema": _schema({}),
    },
    {
        "name": "extract_iocs",
        "description": "Extract Indicators of Compromise (URLs, IPv4 addresses, domains, registry keys, file paths, etc.) and their virtual addresses from the open binary.",
        "inputSchema": _schema({}),
    },
    {
        "name": "scan_vulnerabilities",
        "description": "Run backward source-to-sink vulnerability slicing across analyzed functions and return severity-ranked findings.",
        "inputSchema": _schema({}),
    },
    {
        "name": "triage_security_patch",
        "description": "Rank modified functions between the open binary and a second binary by security patch likelihood (bounds checks, comparisons, branches).",
        "inputSchema": _schema({
            "other_path": {"type": "string", "description": "Optional path to second binary; omit to triage against the already-loaded diff binary"},
        }),
    },
    {
        "name": "get_hilbert_map",
        "description": "Compute a Hilbert space-filling byte-class and Shannon entropy map summary (class counts, percentages, and top high-entropy regions).",
        "inputSchema": _schema({
            "order": {"type": "integer", "minimum": 4, "maximum": 6, "description": "Hilbert curve order: 4 (16x16), 5 (32x32), or 6 (64x64, default)"},
        }),
    },
    {
        "name": "propose_annotation",
        "description": "Queue a human-in-the-loop rename, comment, or C type proposal into the AI Suggestion Queue without mutating the analysis database until approved by the analyst.",
        "inputSchema": _schema({
            "va": {"type": "string", "description": "Target hex virtual address or symbol name"},
            "kind": {"type": "string", "enum": ["rename", "cmt", "type"], "description": "Proposal kind: rename, cmt, or type"},
            "val": {"type": "string", "description": "Proposed symbol name, comment text, or C type declaration"},
            "reason": {"type": "string", "description": "Optional brief justification for the analyst"},
            "conf": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Confidence score 0..100 (default 85)"},
        }, ["va", "kind", "val"]),
    },
]


_BLOCKED_LAUNCH_SHELLS = frozenset({
    "cmd.exe", "cmd", "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "bash.exe", "sh.exe", "wsl.exe",
})


def _canon_path(p: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(p)))


class McpServer:
    def __init__(
        self,
        initial_binary: str | None = None,
        allow_launch: bool | None = None,
        launch_allowlist: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self._db: xdis.Binary | None = None
        self._allow_launch = (
            bool(allow_launch)
            if allow_launch is not None
            else os.environ.get("XDIS_MCP_ALLOW_LAUNCH", "").strip().lower() in ("1", "true", "yes")
        )
        raw_list = (
            launch_allowlist
            if launch_allowlist is not None
            else [p for p in os.environ.get("XDIS_MCP_LAUNCH_ALLOWLIST", "").split(os.pathsep) if p.strip()]
        )
        self._launch_allowlist: set[str] = {_canon_path(p) for p in raw_list if str(p).strip()}
        self._tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "open_binary": self._t_open,
            "get_triage": self._t_triage,
            "list_functions": self._t_list_functions,
            "disassemble": self._t_disassemble,
            "decompile": self._t_decompile,
            "get_microcode": self._t_microcode,
            "get_xrefs": self._t_xrefs,
            "find_pattern": self._t_find_pattern,
            "find_crypto": self._t_find_crypto,
            "pathfind": self._t_pathfind,
            "semantic_diff": self._t_semantic_diff,
            "deobfuscate": self._t_deobfuscate,
            "emulate": self._t_emulate,
            "annotate": self._t_annotate,
            "get_ssa": self._t_ssa,
            "get_lang_info": self._t_lang_info,
            "manage_snapshots": self._t_manage_snapshots,
            "unflatten_cff": self._t_unflatten_cff,
            "simplify_mba": self._t_simplify_mba,
            "analyze_vm": self._t_analyze_vm,
            "resolve_hashes_and_strings": self._t_resolve_hashes_and_strings,
            "taint_analysis": self._t_taint_analysis,
            "solve_path_constraints": self._t_solve_path_constraints,
            "inspect_minidump": self._t_inspect_minidump,
            "debug_control": self._t_debug_control,
            "generate_unique_sig": self._t_generate_unique_sig,
            "import_c_header": self._t_import_c_header,
            "inspect_metadata": self._t_inspect_metadata,
            "yara_scan": self._t_yara_scan,
            "carve_embedded_files": self._t_carve_embedded_files,
            "extract_iocs": self._t_extract_iocs,
            "scan_vulnerabilities": self._t_scan_vulnerabilities,
            "triage_security_patch": self._t_triage_security_patch,
            "get_hilbert_map": self._t_get_hilbert_map,
            "propose_annotation": self._t_propose_annotation,
        }
        if initial_binary:
            self._open_path(initial_binary)

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def _require_db(self) -> xdis.Binary:
        if self._db is None and os.environ.get("XDIS_RPC_PORT", "").strip():
            self._db = xdis.connect()
        if self._db is None:
            raise xdis.XdisError("no binary open; call open_binary first")
        return self._db

    def _open_path(self, path: str) -> dict[str, Any]:
        p = Path(path)
        target = str(p.resolve()) if p.exists() else path
        if self._db is not None and self._db.engine.is_tcp:
            res = self._db.engine.call("open", path=target)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err", f"open failed: {target}")))
            self._db.refresh_info()
            return self._db.info
        new_db = xdis.open(target)
        old_db = self._db
        self._db = new_db
        if old_db is not None:
            try:
                old_db.close()
            except Exception:
                pass
        return self._db.info

    def _t_open(self, args: dict[str, Any]) -> dict[str, Any]:
        path = str(args.get("path", "")).strip()
        if not path:
            raise ValueError("path is required")
        return self._open_path(path)

    def _t_triage(self, _: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        tri = db.triage()
        ent = db.entropy_map()
        ent_by_va = {s.get("va"): s.get("ent", 0.0) for s in ent.get("secs", [])}
        secs = [{**s, "ent": ent_by_va.get(s.get("va"), 0.0)} for s in db.sections()]
        return {
            "binary": {"path": db.path, "fmt": db.fmt, "arch": db.arch, "bits": db.bits, "entry": hex(db.entry)},
            "triage": tri,
            "sections": secs,
        }

    def _t_list_functions(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        q = str(args.get("query", ""))
        limit = int(args.get("limit", 50))
        offset = int(args.get("offset", 0))
        fns = db.functions(q=q, limit=limit, offset=offset)
        return {"count": len(fns), "functions": [{"va": hex(f.va), "size": f.size, "name": f.name} for f in fns]}

    def _t_disassemble(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        va = args["va"]
        count = int(args.get("count", 32))
        addr = db._va(va)
        return {"va": addr, "rows": db.disasm(addr, n=count)}

    def _t_decompile(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.decompile_raw(args["va"])
        if not res.get("ok"):
            raise xdis.XdisError(str(res.get("err", "cannot decompile")))
        code = "\n".join(str(ln.get("text", "")) for ln in res.get("lines", []))
        return {"func_va": res.get("func_va"), "name": res.get("name", ""), "vars": res.get("vars", []), "code": code}

    def _t_microcode(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.microcode(args["va"])
        if not res.get("ok"):
            raise xdis.XdisError("cannot lift microcode")
        return res

    def _t_xrefs(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        addr = db._va(args["va"])
        items = db.xrefs(addr)
        return {"va": addr, "count": len(items), "items": items}

    def _t_find_pattern(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        q = str(args["query"])
        hits = db.find(q)
        return {"query": q, "count": len(hits), "hits": hits}

    def _t_find_crypto(self, _: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        items = db.crypto()
        return {"count": len(items), "items": items}

    def _t_pathfind(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        steps = db.pathfind(args["src"], args["dst"])
        return {"found": bool(steps), "steps": steps}

    def _t_semantic_diff(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.diff(str(args["other_path"]))
        if not res.get("ok"):
            raise xdis.XdisError(str(res.get("err", "diff failed")))
        return res

    def _t_deobfuscate(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.deobf(args["va"])
        if not res.get("ok"):
            raise xdis.XdisError("deobfuscate failed")
        return res

    def _t_emulate(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        steps = int(args.get("steps", 48))
        res = db.emulate(args["va"], steps=steps)
        if not res.get("ok"):
            raise xdis.XdisError("emulate failed")
        return res

    def _t_annotate(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        name = args.get("name")
        comment = args.get("comment")
        if name is None and comment is None:
            raise ValueError("provide name and/or comment")
        addr = db._va(args["va"])
        if name is not None:
            db.rename(addr, str(name))
        if comment is not None:
            db.comment(addr, str(comment))
        return {"ok": True, "va": addr, "renamed": name, "commented": comment}

    def _t_ssa(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        tier = str(args.get("tier", "mlir"))
        res = db.ssa(args["va"], tier=tier)
        if not res.get("ok"):
            raise xdis.XdisError(f"cannot lift {tier} ssa")
        return res

    def _t_lang_info(self, _: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.lang_info()
        if not res.get("ok"):
            raise xdis.XdisError("lang analysis failed")
        return res

    def _t_manage_snapshots(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        action = str(args.get("action", "")).lower().strip()
        if action == "list":
            items = db.snap_list()
            return {"ok": True, "count": len(items), "items": items}
        if action == "save":
            name = str(args.get("name", "")).strip()
            if not name:
                raise ValueError("name is required for save")
            if not db.snap_save(name):
                raise xdis.XdisError(f"failed to save snapshot: {name}")
            return {"ok": True, "action": "save", "name": name}
        if action == "load":
            name = str(args.get("name", "")).strip()
            if not name:
                raise ValueError("name is required for load")
            if not db.snap_load(name):
                raise xdis.XdisError(f"failed to load snapshot: {name}")
            return {"ok": True, "action": "load", "name": name}
        if action == "undo":
            return db.undo()
        if action == "redo":
            return db.redo()
        raise ValueError(f"unsupported action: {action}")

    def _t_unflatten_cff(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.cff(args["va"])
        if not res.get("ok"):
            raise xdis.XdisError("cff analysis failed")
        return res

    def _t_simplify_mba(self, args: dict[str, Any]) -> dict[str, Any]:
        expr = args.get("expr")
        if expr is not None:
            if not isinstance(expr, str):
                raise ValueError("expr must be a string")
            if expr.strip():
                text = expr.strip()
                if self._db is None and os.environ.get("XDIS_RPC_PORT", "").strip():
                    self._db = xdis.connect()
                if self._db is not None:
                    return self._db.mba_eval(text)
                with xdis.Engine() as eng:
                    return eng.call("mba_eval", expr=text)
        va = args.get("va")
        if va is None or (isinstance(va, str) and not va.strip()):
            raise ValueError("provide expr or va")
        db = self._require_db()
        res = db.mba_scan(va)
        if not res.get("ok"):
            raise xdis.XdisError("mba scan failed")
        return res

    def _t_analyze_vm(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.vm_analyze(args["va"])
        if not res.get("ok"):
            raise xdis.XdisError("vm analysis failed")
        return res

    def _t_resolve_hashes_and_strings(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        va = args.get("va")
        apply = bool(args.get("apply", False))
        hashes = db.resolve_hashes(apply=apply)
        strings = db.decrypt_strings(va=0 if va is None else va, apply=apply)
        return {
            "ok": True,
            "applied": apply,
            "hash_count": len(hashes),
            "hashes": hashes,
            "string_count": len(strings),
            "strings": strings,
        }

    def _t_taint_analysis(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        reg = str(args.get("reg", "rcx"))
        buf_len = int(args.get("buf_len", 0))
        steps = int(args.get("steps", 128))
        res = db.taint_run(args["va"], reg=reg, buf_len=buf_len, steps=steps)
        if not res.get("ok"):
            raise xdis.XdisError("taint analysis failed")
        return res

    def _t_solve_path_constraints(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.sym_solve(args["src"], args["dst"])
        if not res.get("ok"):
            raise xdis.XdisError("symbolic path solve failed")
        return res

    def _t_inspect_minidump(self, args: dict[str, Any]) -> dict[str, Any]:
        path = str(args.get("path", "")).strip()
        if not path:
            raise ValueError("path is required")
        if self._db is None and os.environ.get("XDIS_RPC_PORT", "").strip():
            self._db = xdis.connect()
        if self._db is not None:
            res = self._db.dmp_open(path)
        else:
            p = Path(path)
            target = str(p.resolve()) if p.exists() else path
            with xdis.Engine() as eng:
                res = eng.call("dmp_open", path=target)
        if not res.get("ok"):
            raise xdis.XdisError(str(res.get("err", f"failed to inspect minidump: {path}")))
        return res

    def _t_debug_control(self, args: dict[str, Any]) -> dict[str, Any]:
        action = str(args.get("action", "")).lower().strip()
        va = args.get("va")
        raw_cond = args.get("cond")
        if raw_cond is not None and not isinstance(raw_cond, str):
            raise ValueError("cond must be a string")
        cond = raw_cond or ""
        raw_reg = args.get("reg")
        if raw_reg is not None and not isinstance(raw_reg, str):
            raise ValueError("reg must be a string")
        reg = raw_reg or ""

        if action == "launch":
            raw_path = args.get("path")
            if raw_path is not None and not isinstance(raw_path, str):
                raise ValueError("path must be a string")
            raw_args = args.get("args")
            if raw_args is not None and not isinstance(raw_args, str):
                raise ValueError("args must be a string")
            launch_args = raw_args or ""
            if any(c in launch_args for c in ("\x00", "\r", "\n")) or len(launch_args) >= 256:
                raise ValueError("invalid launch args")
            req_path = (raw_path or "").strip()

            if self._db is None:
                if not req_path:
                    raise xdis.XdisError("no binary open; call open_binary first")
                canon_req = _canon_path(req_path)
                if not self._allow_launch and canon_req not in self._launch_allowlist:
                    raise xdis.XdisError(
                        "launch denied: no binary open and path is not allowlisted"
                    )
                if not os.environ.get("XDIS_RPC_PORT", "").strip():
                    self._db = xdis.Binary(xdis.Engine(), info={})
            db = self._require_db()

            target = req_path or db.path
            if not target:
                raise xdis.XdisError("no binary open; call open_binary first")
            canon_target = _canon_path(target)
            if not self._allow_launch and canon_target not in self._launch_allowlist:
                if not db.path or canon_target != _canon_path(db.path):
                    raise xdis.XdisError(
                        "launch denied: target must match currently open binary or launch allowlist"
                    )
                if Path(canon_target).name.lower() in _BLOCKED_LAUNCH_SHELLS:
                    raise xdis.XdisError(
                        f"launch denied: blocked shell/interpreter {Path(canon_target).name}"
                    )

            res = db.dbg_launch(path=target, args=launch_args)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err", "dbg_launch failed")))
            return res

        db = self._require_db()
        if action == "step":
            return db.dbg_step()
        if action == "step_over":
            return db.dbg_step_over()
        if action == "step_out":
            return db.dbg_step_out()
        if action == "cont":
            return db.dbg_cont()
        if action == "pause":
            return db.dbg_pause()
        if action == "set_reg":
            val = args.get("val")
            if not reg.strip():
                raise ValueError("reg is required for set_reg")
            if val is None or isinstance(val, bool) or (isinstance(val, str) and not val.strip()):
                raise ValueError("val is required for set_reg")
            res = db.dbg_set_reg(reg.strip(), val)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err", "dbg_set_reg failed")))
            return res
        if action == "bp":
            if va is None or isinstance(va, bool) or (isinstance(va, str) and not va.strip()):
                raise ValueError("va is required for bp")
            return db.dbg_bp_cond(va, cond) if cond.strip() else db.dbg_bp(va)
        if action in ("write_mem", "dbg_write_mem"):
            if va is None or isinstance(va, bool) or (isinstance(va, str) and not va.strip()):
                raise ValueError("va is required for write_mem")
            hex_data = args.get("hex")
            if hex_data is None:
                hex_data = args.get("data")
            if not isinstance(hex_data, str) or not hex_data.strip():
                raise ValueError("hex is required for write_mem")
            res = db.dbg_write_mem(va, hex_data)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err", "dbg_write_mem failed")))
            return res
        if action == "mmap":
            items = db.dbg_mmap()
            return {"ok": True, "count": len(items), "items": items}
        if action == "bt":
            items = db.dbg_backtrace()
            return {"ok": True, "count": len(items), "items": items}
        if action == "ttd_rec":
            raw_steps = args.get("steps")
            steps = 64 if raw_steps is None else int(raw_steps)
            return db.dbg_ttd_record(n=steps)
        if action == "ttd_back":
            return db.dbg_ttd_back()
        if action == "ttd_who":
            target = 0 if (va is None or (isinstance(va, str) and not va.strip())) else va
            return db.dbg_ttd_who_wrote(va=target, reg=reg)
        if action == "kill":
            return db.dbg_kill()
        if action == "detach":
            return db.dbg_detach()
        raise ValueError(f"unsupported debug action: {action}")

    def _t_generate_unique_sig(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.make_sig(args["va"])
        if not res.get("ok"):
            raise xdis.XdisError(f"failed to generate signature at {args['va']}")
        return res

    def _t_import_c_header(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        text = args.get("text")
        path = args.get("path")
        stdlib = args.get("stdlib")
        has_text = text is not None and bool(str(text).strip())
        has_path = path is not None and bool(str(path).strip())
        has_std = stdlib is not None and bool(str(stdlib).strip())
        if not (has_text or has_path or has_std):
            raise ValueError("provide text, path, or stdlib ('win32'/'posix')")

        out: dict[str, Any] = {"ok": True}
        total_added = 0
        if has_std:
            pack = str(stdlib).strip().lower()
            added = db.load_stdlib_types(pack=pack)
            out["stdlib"] = {"pack": pack, "added": added}
            total_added += added
        if has_path:
            p = Path(str(path).strip())
            res = db.parse_header(p, is_file=True)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err") or f"failed to parse header: {path}"))
            out["file"] = res
            total_added += int(res.get("added", 0))
        if has_text:
            res = db.parse_header(str(text), is_file=False)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err") or "failed to parse header text"))
            out["text"] = res
            total_added += int(res.get("added", 0))
        out["added"] = total_added
        out["total_types"] = len(db.types())
        return out

    def _t_inspect_metadata(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        kind = str(args.get("kind", "dotnet")).lower().strip()
        if kind == "dotnet":
            res = db.dotnet_info()
            if not res.get("ok"):
                raise xdis.XdisError("no .NET CLR metadata found in binary")
            return res
        if kind == "dwarf":
            res = db.load_dwarf()
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err") or "no DWARF metadata found"))
            return res
        if kind == "pdb_msf":
            pdb_path = str(args.get("pdb_path") or "").strip()
            if not pdb_path:
                raise ValueError("pdb_path is required for pdb_msf")
            res = db.load_pdb_msf(pdb_path)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err") or f"failed to load MSF PDB: {pdb_path}"))
            return res
        if kind == "struct_apply":
            sname = str(args.get("struct_name") or "").strip()
            if not sname:
                raise ValueError("struct_name is required for struct_apply")
            va = args.get("va")
            target = hex(db.entry) if (va is None or (isinstance(va, str) and not va.strip())) else va
            res = db.apply_struct(sname, target)
            if not res.get("ok"):
                raise xdis.XdisError(str(res.get("err") or f"failed to apply struct {sname}"))
            return res
        raise ValueError(f"unsupported metadata kind: {kind}")

    def _t_yara_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        rules = str(args.get("rules") or "")
        res = db.yara_scan(rules=rules)
        if not res.get("ok"):
            raise xdis.XdisError(str(res.get("err") or "yara scan failed"))
        return res

    def _t_carve_embedded_files(self, _: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        items = db.carve()
        return {"ok": True, "count": len(items), "items": items}

    def _t_extract_iocs(self, _: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        items = db.extract_iocs()
        return {"ok": True, "count": len(items), "items": items}

    def _t_scan_vulnerabilities(self, _: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        res = db.vuln_scan()
        if not res.get("ok"):
            raise xdis.XdisError("vulnerability scan failed")
        return res

    def _t_triage_security_patch(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        other = str(args.get("other_path") or "").strip()
        target = ""
        if other:
            p = Path(other)
            target = str(p.resolve()) if p.exists() else other
        res = db.engine.call("pdiff", path=target)
        if not res.get("ok"):
            raise xdis.XdisError(str(res.get("err") or "security patch triage failed"))
        items = list(res.get("items", []))
        return {"ok": True, "count": len(items), "items": items}

    def _t_get_hilbert_map(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        raw_order = args.get("order")
        order = max(4, min(6, 6 if raw_order is None else int(raw_order)))
        res = db.hilbert_map(order=order)
        if not res.get("ok"):
            raise xdis.XdisError("hilbert map generation failed")
        return _summarize_hilbert(res, order)

    def _t_propose_annotation(self, args: dict[str, Any]) -> dict[str, Any]:
        db = self._require_db()
        addr = db._va(args["va"])
        kind = str(args["kind"]).strip().lower()
        val = str(args["val"]).strip()
        if not val:
            raise ValueError("val must be non-empty")
        reason = str(args.get("reason") or "")
        raw_conf = args.get("conf")
        conf = max(0, min(100, 85 if raw_conf is None else int(raw_conf)))
        res = db.propose(addr, kind=kind, val=val, reason=reason, conf=conf)
        if not res.get("ok"):
            raise xdis.XdisError(str(res.get("err") or "failed to queue annotation proposal"))
        return res

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        has_id = "id" in msg
        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        if not isinstance(method, str):
            return _rpc_err(req_id, -32600, "invalid request") if has_id else None

        if not has_id:
            # notifications never emit responses
            return None

        if method == "initialize":
            return _rpc_ok(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        if method == "ping":
            return _rpc_ok(req_id, {})
        if method == "tools/list":
            return _rpc_ok(req_id, {"tools": TOOLS})
        if method == "tools/call":
            return self._handle_tool_call(req_id, params)
        return _rpc_err(req_id, -32601, f"method not found: {method}")

    def _handle_tool_call(self, req_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return _rpc_err(req_id, -32602, "invalid tools/call params")
        name = params["name"]
        raw_args = params.get("arguments")
        args = {} if raw_args is None else raw_args
        if not isinstance(args, dict):
            return _rpc_err(req_id, -32602, "arguments must be an object")
        fn = self._tools.get(name)
        if fn is None:
            return _rpc_err(req_id, -32602, f"unknown tool: {name}")
        try:
            data = fn(args)
            text = json.dumps(data, indent=2)
            return _rpc_ok(req_id, {"content": [{"type": "text", "text": text}], "isError": False})
        except (xdis.XdisError, KeyError, ValueError, TypeError, AttributeError, OSError) as exc:
            return _rpc_ok(req_id, {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True})


_HILBERT_CLASS_NAMES = ("zero_pad", "code", "data", "strings", "high_entropy")


def _norm_hilbert_ent(raw: int | float) -> float:
    return min(8.0, max(0.0, float(raw) / 10.0))


def _summarize_hilbert(res: dict[str, Any], order: int) -> dict[str, Any]:
    side = int(res.get("side", 0))
    cls_arr = list(res.get("cls", []))
    ent_arr = list(res.get("ent", []))
    offs_arr = list(res.get("offs", []))
    vas_arr = list(res.get("vas", []))
    ncell = min(int(res.get("ncell", len(cls_arr))), len(cls_arr))

    counts = {name: 0 for name in _HILBERT_CLASS_NAMES}
    ent_sum = 0.0
    max_ent = 0.0
    cells: list[tuple[int, int, float, str]] = []

    for i in range(ncell):
        cid = int(cls_arr[i]) if 0 <= int(cls_arr[i]) < len(_HILBERT_CLASS_NAMES) else 0
        counts[_HILBERT_CLASS_NAMES[cid]] += 1
        e_bits = _norm_hilbert_ent(ent_arr[i] if i < len(ent_arr) else 0)
        ent_sum += e_bits
        if e_bits > max_ent:
            max_ent = e_bits
        off = int(offs_arr[i]) if i < len(offs_arr) else i
        va = str(vas_arr[i]) if i < len(vas_arr) else "0x0"
        cells.append((off, cid, e_bits, va))

    cells.sort(key=lambda c: c[0])
    regions: list[dict[str, Any]] = []
    cur_run: list[tuple[int, int, float, str]] = []

    def _flush_run() -> None:
        if not cur_run:
            return
        cls_hist: dict[int, int] = {}
        e_tot = 0.0
        e_hi = 0.0
        first_va = "0x0"
        for _, cid, eb, va in cur_run:
            cls_hist[cid] = cls_hist.get(cid, 0) + 1
            e_tot += eb
            if eb > e_hi:
                e_hi = eb
            if first_va == "0x0" and va and va != "0x0":
                first_va = va
        dom_cid = max(cls_hist, key=lambda k: cls_hist[k])
        regions.append({
            "start_off": hex(cur_run[0][0]),
            "end_off": hex(cur_run[-1][0]),
            "start_va": first_va,
            "cells": len(cur_run),
            "avg_ent": round(e_tot / len(cur_run), 2),
            "max_ent": round(e_hi, 2),
            "dominant_class": _HILBERT_CLASS_NAMES[dom_cid],
        })
        cur_run.clear()

    for cell in cells:
        if cell[1] == 4 or cell[2] >= 6.5:
            cur_run.append(cell)
        else:
            _flush_run()
    _flush_run()

    regions.sort(key=lambda r: (r["max_ent"], r["cells"]), reverse=True)
    top_regions = regions[:12]
    if not top_regions and cells:
        peak = sorted(cells, key=lambda c: c[2], reverse=True)[:8]
        top_regions = [
            {
                "start_off": hex(off),
                "end_off": hex(off),
                "start_va": va,
                "cells": 1,
                "avg_ent": round(eb, 2),
                "max_ent": round(eb, 2),
                "dominant_class": _HILBERT_CLASS_NAMES[cid],
            }
            for off, cid, eb, va in peak
            if eb > 0.0
        ]

    pct = {
        name: round((cnt * 100.0) / ncell, 1) if ncell else 0.0
        for name, cnt in counts.items()
    }
    return {
        "ok": True,
        "order": order,
        "side": side,
        "ncell": ncell,
        "avg_entropy": round(ent_sum / ncell, 2) if ncell else 0.0,
        "max_entropy": round(max_ent, 2),
        "class_counts": counts,
        "class_pct": pct,
        "top_high_entropy_regions": top_regions,
    }


def _rpc_ok(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _write_msg(msg: dict[str, Any]) -> None:
    # raw utf-8 avoids crlf corruption
    raw = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def main() -> int:
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    srv = McpServer(initial_binary=initial)
    try:
        for raw in sys.stdin.buffer:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _write_msg(_rpc_err(None, -32700, "parse error"))
                continue
            if not isinstance(msg, dict):
                _write_msg(_rpc_err(None, -32600, "invalid request"))
                continue
            reply = srv.handle(msg)
            if reply is not None:
                _write_msg(reply)
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
