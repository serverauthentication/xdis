from __future__ import annotations

import html
import json
import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path
from typing import Any

__version__ = "3.0.0"
__all__ = ["XdisError", "Engine", "Function", "Binary", "Session", "open", "connect"]


class XdisError(RuntimeError):
    pass


def _is_omitted_va(va: Any) -> bool:
    return (
        va is None
        or (isinstance(va, int) and not isinstance(va, bool) and va == 0)
        or (isinstance(va, str) and not va.strip())
    )


def _va_int(va: int | str) -> int:
    if isinstance(va, bool) or not isinstance(va, (int, str)):
        raise ValueError(f"invalid virtual address: expected int or str, got {type(va).__name__}")
    if isinstance(va, int):
        if va < 0:
            raise ValueError(f"invalid virtual address: negative integer {va}")
        if va > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("virtual address out of 64-bit range")
        return va
    s = va.strip()
    if not s:
        raise ValueError("invalid virtual address: empty string")
    if s.startswith("-"):
        raise ValueError(f"invalid virtual address: negative value {va!r}")
    if s.startswith(("0x", "0X")):
        v = int(s, 16)
    elif any(c in "abcdefABCDEF" for c in s):
        v = int(s, 16)
    else:
        v = int(s, 0)
    if v < 0:
        raise ValueError(f"invalid virtual address: negative value {va!r}")
    if v > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("virtual address out of 64-bit range")
    return v


def _reg_u64(val: int | str) -> int:
    if isinstance(val, bool) or not isinstance(val, (int, str)):
        raise ValueError(f"invalid register value: expected int or str, got {type(val).__name__}")
    if isinstance(val, int):
        return val & 0xFFFFFFFFFFFFFFFF
    s = val.strip()
    if not s:
        raise ValueError("invalid register value: empty string")
    if s.startswith(("0x", "0X", "-0x", "-0X", "+0x", "+0X")):
        return int(s, 16) & 0xFFFFFFFFFFFFFFFF
    if any(c in "abcdefABCDEF" for c in s):
        return int(s, 16) & 0xFFFFFFFFFFFFFFFF
    return int(s, 0) & 0xFFFFFFFFFFFFFFFF


def _va_hex(va: int | str) -> str:
    return hex(_va_int(va))


def _perm_str(perm: int) -> str:
    return ("r" if perm & 1 else "-") + ("w" if perm & 2 else "-") + ("x" if perm & 4 else "-")


def _find_engine(exe: str | Path | None = None) -> Path:
    if exe is not None:
        p = Path(exe)
        if p.is_file():
            return p
        raise FileNotFoundError(f"xdis engine not found: {p}")

    root = Path(__file__).resolve().parent.parent
    candidates = [
        root / "xdis.exe",
        root / "xdis",
        Path.cwd() / "xdis.exe",
        Path.cwd() / "xdis",
    ]
    for c in candidates:
        if c.is_file():
            return c
    for name in ("xdis.exe", "xdis"):
        found = shutil.which(name)
        if found:
            return Path(found)
    raise FileNotFoundError("xdis engine not found")


class Engine:
    def __init__(
        self,
        exe: str | Path | None = None,
        port: int | None = None,
        host: str = "127.0.0.1",
        timeout: float = 30.0,
        spawn: bool = False,
        token: str = "",
    ) -> None:
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[bytes] | None = None
        self._sock: socket.socket | None = None
        self._rx: Any = None
        self._tx: Any = None
        self._closed = False

        env_port = os.environ.get("XDIS_RPC_PORT", "").strip()
        tcp_port = port if port is not None else (int(env_port) if env_port and not spawn and exe is None else None)
        auth_token = token if token else os.environ.get("XDIS_RPC_TOKEN", "")

        if tcp_port is not None:
            self._connect_tcp(host, tcp_port, timeout, token=auth_token)
        else:
            self._spawn_proc(_find_engine(exe))

    def _connect_tcp(self, host: str, port: int, timeout: float, token: str = "") -> None:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(None)
        self._sock = sock
        self._rx = sock.makefile("rb")
        self._tx = sock.makefile("wb")
        if token:
            try:
                res = self.call("auth", token=token)
            except XdisError as exc:
                self._closed = True
                self._close_sock()
                raise XdisError("bridge authentication failed") from exc
            if not res.get("ok"):
                self._closed = True
                self._close_sock()
                raise XdisError("bridge authentication failed")

    def _spawn_proc(self, exe: Path) -> None:
        # binary pipes avoid windows crlf mangling
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
        proc = subprocess.Popen(
            [str(exe), "--rpc"],
            cwd=str(exe.parent),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            creationflags=flags,
        )
        self._proc = proc
        self._rx = proc.stdout
        self._tx = proc.stdin

    @property
    def is_tcp(self) -> bool:
        return self._sock is not None

    def call(self, op: str, **params: Any) -> dict[str, Any]:
        with self._lock:
            if self._closed or self._tx is None or self._rx is None:
                raise XdisError("engine closed")
            req: dict[str, Any] = {"op": op}
            for k, v in params.items():
                if v is not None:
                    req[k] = v
            line = (json.dumps(req, separators=(",", ":")) + "\n").encode("utf-8")
            try:
                self._tx.write(line)
                self._tx.flush()
                raw = self._rx.readline()
            except OSError as exc:
                raise XdisError(f"rpc io error on {op}: {exc}") from exc
            if not raw:
                raise XdisError(f"rpc eof on {op}")
            try:
                return json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                raise XdisError(f"invalid rpc json on {op}: {exc}") from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._proc is not None:
                self._close_proc()
            elif self._sock is not None:
                # keep live gui engine alive
                self._close_sock()

    def _close_proc(self) -> None:
        proc = self._proc
        self._proc = None
        if self._tx is not None:
            try:
                self._tx.write(b'{"op":"quit"}\n')
                self._tx.flush()
            except OSError:
                pass
            try:
                self._tx.close()
            except OSError:
                pass
        if self._rx is not None:
            try:
                self._rx.close()
            except OSError:
                pass
        self._tx = self._rx = None
        if proc is not None:
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)

    def _close_sock(self) -> None:
        for obj in (self._tx, self._rx, self._sock):
            if obj is not None:
                try:
                    obj.close()
                except OSError:
                    pass
        self._tx = self._rx = self._sock = None

    def __enter__(self) -> Engine:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class Function:
    def __init__(self, db: Binary, va: int, size: int, name: str) -> None:
        self._db = db
        self.va = va
        self.size = size
        self.name = name

    def __repr__(self) -> str:
        return f"Function(va={hex(self.va)}, size={self.size}, name={self.name!r})"

    def disasm(self, n: int = 64) -> list[dict[str, Any]]:
        return self._db.disasm(self.va, n)

    def decompile(self) -> str:
        return self._db.decompile(self.va)

    def microcode(self) -> dict[str, Any]:
        return self._db.microcode(self.va)

    def ssa(self, tier: str = "mlir") -> dict[str, Any]:
        return self._db.ssa(self.va, tier=tier)

    def cfg(self) -> dict[str, Any]:
        return self._db.cfg(self.va)

    def callgraph(self) -> dict[str, Any]:
        return self._db.callgraph(self.va)

    def deobf(self) -> dict[str, Any]:
        return self._db.deobf(self.va)

    def cff(self) -> dict[str, Any]:
        return self._db.cff(self.va)

    def mba_scan(self) -> dict[str, Any]:
        return self._db.mba_scan(self.va)

    def vm_analyze(self) -> dict[str, Any]:
        return self._db.vm_analyze(self.va)

    def emulate(self, steps: int = 48) -> dict[str, Any]:
        return self._db.emulate(self.va, steps)

    def taint_run(self, reg: str = "rcx", buf_len: int = 0, steps: int = 128) -> dict[str, Any]:
        return self._db.taint_run(self.va, reg=reg, buf_len=buf_len, steps=steps)

    def xrefs(self) -> list[dict[str, Any]]:
        return self._db.xrefs(self.va)

    def switches(self) -> list[dict[str, Any]]:
        return self._db.switches(self.va)

    def make_sig(self) -> dict[str, Any]:
        return self._db.make_sig(self.va)

    def rename(self, name: str) -> bool:
        ok = self._db.rename(self.va, name)
        if ok:
            self.name = name
        return ok


class Binary:
    def __init__(self, engine: Engine, info: dict[str, Any] | None = None, owns_engine: bool = True) -> None:
        self.engine = engine
        self._info = info
        self._owns = owns_engine

    def close(self) -> None:
        if self._owns:
            self.engine.close()

    def __enter__(self) -> Binary:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @property
    def info(self) -> dict[str, Any]:
        if self._info is None:
            self._info = self.engine.call("info")
        return self._info

    def refresh_info(self) -> dict[str, Any]:
        self._info = self.engine.call("info")
        return self._info

    @property
    def entry(self) -> int:
        return _va_int(self.info.get("entry", "0x0"))

    @property
    def base(self) -> int:
        return _va_int(self.info.get("base", "0x0"))

    @property
    def path(self) -> str:
        return str(self.info.get("path", ""))

    @property
    def fmt(self) -> str:
        return str(self.info.get("fmt", ""))

    @property
    def arch(self) -> str:
        return str(self.info.get("arch", ""))

    @property
    def bits(self) -> int:
        return int(self.info.get("bits", 64))

    def _va(self, va: int | str) -> str:
        if isinstance(va, bool) or not isinstance(va, (int, str)):
            raise ValueError(f"invalid virtual address: expected int or str, got {type(va).__name__}")
        if isinstance(va, int):
            if va < 0:
                raise ValueError(f"invalid virtual address: negative integer {va}")
            if va > 0xFFFFFFFFFFFFFFFF:
                raise ValueError("virtual address out of 64-bit range")
            return hex(va)
        s = va.strip()
        if not s:
            raise ValueError("invalid virtual address: empty string")
        if s.startswith("-"):
            raise ValueError(f"invalid virtual address: negative value {va!r}")
        if s.startswith(("0x", "0X")):
            v = int(s, 16)
            if v < 0:
                raise ValueError(f"invalid virtual address: negative value {va!r}")
            if v > 0xFFFFFFFFFFFFFFFF:
                raise ValueError("virtual address out of 64-bit range")
            return hex(v)
        resolved = self.resolve(s)
        if resolved is not None:
            return hex(resolved)
        if s.lower() == "entry":
            return hex(self.entry)
        raise XdisError(f"unresolved address: {va}")

    def _list_paged(self, tab: str, q: str, limit: int, offset: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cur_off = max(0, int(offset))
        rem = max(0, int(limit))
        while rem > 0:
            # rpc caps single page at 300
            chunk = min(rem, 300)
            res = self.engine.call("list", tab=tab, q=q, off=cur_off, lim=chunk)
            items = res.get("items", [])
            if not items:
                break
            out.extend(items)
            if len(items) < chunk:
                break
            cur_off += len(items)
            rem -= len(items)
        return out

    def triage(self) -> dict[str, Any]:
        return self.engine.call("triage")

    def entropy_map(self) -> dict[str, Any]:
        return self.engine.call("entropy_map")

    def sections(self) -> list[dict[str, Any]]:
        return list(self.info.get("secs", []))

    def functions(self, q: str = "", limit: int = 200, offset: int = 0) -> list[Function]:
        items = self._list_paged("funcs", q, limit, offset)
        return [Function(self, _va_int(it["va"]), int(it.get("size", 0)), str(it.get("name", ""))) for it in items]

    def symbols(self, q: str = "", limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        return self._list_paged("syms", q, limit, offset)

    def strings(self, q: str = "", limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        return self._list_paged("strs", q, limit, offset)

    def marks(self, q: str = "", limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        return self._list_paged("marks", q, limit, offset)

    def resolve(self, query: str) -> int | None:
        res = self.engine.call("resolve", q=query)
        return _va_int(res["va"]) if res.get("ok") and "va" in res else None

    def disasm(self, va: int | str, n: int = 32) -> list[dict[str, Any]]:
        res = self.engine.call("dis", va=self._va(va), n=int(n))
        return list(res.get("rows", []))

    def step(self, va: int | str, n: int = 1, direction: str = "next") -> int:
        res = self.engine.call("step", va=self._va(va), n=int(n), dir=direction)
        return _va_int(res.get("va", "0x0"))

    def hex_rows(self, va: int | str, rows: int = 32) -> list[dict[str, Any]]:
        res = self.engine.call("hex", va=self._va(va), n=int(rows))
        return list(res.get("rows", []))

    def peek(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("peek", va=self._va(va))

    def decompile(self, va: int | str) -> str:
        res = self.engine.call("dec", va=self._va(va))
        if not res.get("ok"):
            return ""
        return "\n".join(str(ln.get("text", "")) for ln in res.get("lines", []))

    def decompile_raw(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("dec", va=self._va(va))

    def retype_var(self, func_va: int | str, orig: str, ctype: str, name: str = "") -> bool:
        res = self.engine.call("lvar", func_va=self._va(func_va), orig=orig, name=name, type=ctype)
        return bool(res.get("ok"))

    def microcode(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("ir", va=self._va(va))

    def ssa(self, va: int | str, tier: str = "mlir") -> dict[str, Any]:
        t = str(tier).lower().strip()
        if t not in ("mlir", "llir"):
            raise ValueError(f"unsupported ssa tier: {tier}")
        return self.engine.call("ssa", va=self._va(va), tier=t)

    def lang_info(self) -> dict[str, Any]:
        return self.engine.call("lang")

    def cfg(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("cfg", va=self._va(va))

    def callgraph(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("callgraph", va=self._va(va))

    def deobf(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("deobf", va=self._va(va))

    def cff(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("cff", va=self._va(va))

    def mba_eval(self, expr: str) -> dict[str, Any]:
        return self.engine.call("mba_eval", expr=str(expr))

    def mba_scan(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("mba_scan", va=self._va(va))

    def vm_analyze(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("vm", va=self._va(va))

    def resolve_hashes(self, apply: bool = False) -> list[dict[str, Any]]:
        res = self.engine.call("unp_hashes", apply=1 if apply else 0)
        return list(res.get("hits", [])) if res.get("ok") else []

    def decrypt_strings(self, va: int | str = 0, apply: bool = False) -> list[dict[str, Any]]:
        target = hex(self.entry) if _is_omitted_va(va) else self._va(va)
        res = self.engine.call("unp_strs", va=target, apply=1 if apply else 0)
        return list(res.get("hits", [])) if res.get("ok") else []

    def rebuild_pe(self, out_path: str | Path, base: int | str = 0, oep: int | str = 0) -> dict[str, Any]:
        return self.engine.call(
            "unp_rebuild",
            path=str(Path(out_path)),
            base=0 if _is_omitted_va(base) else hex(_va_int(base)),
            oep=0 if _is_omitted_va(oep) else hex(_va_int(oep)),
        )

    def emulate(self, va: int | str, steps: int = 48) -> dict[str, Any]:
        return self.engine.call("emu", va=self._va(va), n=int(steps))

    def inspect(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("inspect", va=self._va(va))

    def read(self, va: int | str, n: int = 64) -> bytes:
        base = _va_int(self._va(va))
        out = bytearray()
        rem = max(0, int(n))
        while rem > 0:
            # rpc caps single read at 2048
            chunk = min(rem, 2048)
            res = self.engine.call("read", va=hex(base + len(out)), n=chunk)
            if not res.get("ok"):
                break
            got = bytes.fromhex(res.get("hex", ""))
            if not got:
                break
            out.extend(got)
            if len(got) < chunk:
                break
            rem -= len(got)
        return bytes(out)

    def xrefs(self, va: int | str) -> list[dict[str, Any]]:
        res = self.engine.call("xrefs", va=self._va(va))
        return list(res.get("items", []))

    def xgraph(self, va: int | str, depth: int = 2) -> dict[str, Any]:
        return self.engine.call("xgraph", va=self._va(va), depth=int(depth))

    def pathfind(self, src_va: int | str, dst_va: int | str) -> list[dict[str, Any]]:
        res = self.engine.call("pathfind", **{"from": self._va(src_va), "to": self._va(dst_va)})
        return list(res.get("steps", [])) if res.get("ok") else []

    def find(self, pattern_or_text: str) -> list[dict[str, Any]]:
        res = self.engine.call("find", q=pattern_or_text)
        return list(res.get("hits", []))

    def crypto(self) -> list[dict[str, Any]]:
        res = self.engine.call("crypto")
        return list(res.get("items", [])) if res.get("ok") else []

    def vtables(self) -> list[dict[str, Any]]:
        res = self.engine.call("vtables")
        return list(res.get("items", [])) if res.get("ok") else []

    def switches(self, va: int | str) -> list[dict[str, Any]]:
        res = self.engine.call("switches", va=self._va(va))
        return list(res.get("items", [])) if res.get("ok") else []

    def diff(self, other_path: str | Path) -> dict[str, Any]:
        return self.engine.call("diff", path=str(Path(other_path)))

    def diff_decompile(self, va: int | str) -> str:
        res = self.engine.call("diff_dec", va=_va_hex(va))
        return "\n".join(res.get("lines", [])) if res.get("ok") else ""

    def demangle(self, name: str) -> str:
        res = self.engine.call("demangle", name=name)
        return str(res.get("name", name))

    def load_pdb(self, path: str | Path) -> int:
        res = self.engine.call("pdb_load", path=str(Path(path)))
        return int(res.get("added", 0)) if res.get("ok") else 0

    def load_pdb_msf(self, path: str | Path) -> dict[str, Any]:
        return self.engine.call("pdb_msf", path=str(Path(path)))

    def load_dwarf(self) -> dict[str, Any]:
        return self.engine.call("dwarf_load")

    def dotnet_info(self) -> dict[str, Any]:
        return self.engine.call("dotnet")

    def rename(self, va: int | str, name: str) -> bool:
        return bool(self.engine.call("rename", va=self._va(va), name=name).get("ok"))

    def comment(self, va: int | str, text: str) -> bool:
        return bool(self.engine.call("cmt", va=self._va(va), text=text).get("ok"))

    def lvar(self, func_va: int | str, orig: str, name: str = "", ctype: str = "") -> bool:
        res = self.engine.call("lvar", func_va=self._va(func_va), orig=orig, name=name, type=ctype)
        return bool(res.get("ok"))

    def mark(self, va: int | str, label: str) -> bool:
        return bool(self.engine.call("mark", va=self._va(va), label=label).get("ok"))

    def patch(self, va: int | str, hex_bytes: str | bytes | bytearray) -> int:
        raw = hex_bytes.hex() if isinstance(hex_bytes, (bytes, bytearray)) else str(hex_bytes)
        res = self.engine.call("patch_bytes", va=self._va(va), hex=raw)
        return int(res.get("n", 0)) if res.get("ok") else 0

    def assemble(self, va: int | str, asm_text: str, apply: bool = True) -> bytes:
        res = self.engine.call("asm", va=self._va(va), text=asm_text, apply=1 if apply else 0)
        if not res.get("ok"):
            raise XdisError(str(res.get("err", "assemble failed")))
        return bytes.fromhex(res.get("hex", ""))

    def patches(self) -> list[dict[str, Any]]:
        return list(self.engine.call("patches").get("items", []))

    def unpatch(self, va: int | str = 0) -> bool:
        target: int | str = 0 if _is_omitted_va(va) else self._va(va)
        return bool(self.engine.call("unpatch", va=target).get("ok"))

    def export_patched(self, path: str | Path) -> bool:
        return bool(self.engine.call("export_bin", path=str(Path(path))).get("ok"))

    def add_type(self, c_decl: str) -> bool:
        return bool(self.engine.call("type_add", decl=c_decl).get("ok"))

    def types(self) -> list[dict[str, Any]]:
        res = self.engine.call("types")
        return list(res.get("items", [])) if res.get("ok") else []

    def parse_header(self, text_or_path: str | Path, is_file: bool = False) -> dict[str, Any]:
        if is_file or isinstance(text_or_path, Path):
            p = Path(text_or_path)
            target = str(p.resolve()) if p.exists() else str(p)
            return self.engine.call("chdr_parse", path=target)
        return self.engine.call("chdr_parse", text=str(text_or_path))

    def load_stdlib_types(self, pack: str = "win32") -> int:
        res = self.engine.call("chdr_stdlib", pack=str(pack))
        return int(res.get("added", 0)) if res.get("ok") else 0

    def apply_struct(self, name: str, va: int | str) -> dict[str, Any]:
        return self.engine.call("struct_apply", name=str(name), va=self._va(va))

    def make_sig(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("make_sig", va=self._va(va))

    def sig_save(self, path: str | Path) -> bool:
        return bool(self.engine.call("sig_save", path=str(Path(path))).get("ok"))

    def sig_apply(self, path: str | Path) -> int:
        res = self.engine.call("sig_apply", path=str(Path(path)))
        return int(res.get("matched", 0)) if res.get("ok") else 0

    def save(self) -> bool:
        return bool(self.engine.call("save").get("ok"))

    def undo(self) -> dict[str, Any]:
        return self.engine.call("undo")

    def redo(self) -> dict[str, Any]:
        return self.engine.call("redo")

    def snap_save(self, name: str) -> bool:
        return bool(self.engine.call("snap_save", name=str(name)).get("ok"))

    def snap_list(self) -> list[dict[str, Any]]:
        res = self.engine.call("snap_list")
        return list(res.get("items", [])) if res.get("ok") else []

    def snap_load(self, name: str) -> bool:
        return bool(self.engine.call("snap_load", name=str(name)).get("ok"))

    def set_opt(self, upper: bool | None = None) -> dict[str, Any]:
        return self.engine.call("opt", upper=None if upper is None else (1 if upper else 0))

    def cmd(self, name: str, args: str = "") -> str:
        res = self.engine.call("cmd", name=name, args=args)
        return str(res.get("out", ""))

    def dbg_launch(self, path: str | Path = "", args: str = "") -> dict[str, Any]:
        return self.engine.call("dbg_launch", path=str(path), args=args)

    def dbg_attach(self, pid: int) -> dict[str, Any]:
        return self.engine.call("dbg_attach", pid=int(pid))

    def dbg_step(self) -> dict[str, Any]:
        return self.engine.call("dbg_step")

    def dbg_step_over(self) -> dict[str, Any]:
        return self.engine.call("dbg_step_over")

    def dbg_step_out(self) -> dict[str, Any]:
        return self.engine.call("dbg_step_out")

    def dbg_run_to(self, va: int | str) -> dict[str, Any]:
        return self.engine.call("dbg_run_to", va=self._va(va))

    def dbg_cont(self, ms: int = 1500) -> dict[str, Any]:
        return self.engine.call("dbg_cont", ms=int(ms))

    def dbg_pause(self) -> dict[str, Any]:
        return self.engine.call("dbg_pause")

    def dbg_set_reg(self, reg: str, val: int | str) -> dict[str, Any]:
        name = str(reg).strip().lower()
        if not name:
            raise ValueError("reg is required")
        v = _reg_u64(val)
        return self.engine.call("dbg_set_reg", reg=name, val=hex(v))

    def dbg_bp(self, va: int | str, remove: bool = False) -> dict[str, Any]:
        return self.engine.call("dbg_bp", va=self._va(va), **{"del": 1 if remove else 0})

    def dbg_bp_cond(self, va: int | str, cond: str) -> dict[str, Any]:
        return self.engine.call("dbg_bp", va=self._va(va), **{"del": 0}, cond=str(cond))

    def dbg_hwbp(
        self,
        va: int | str,
        kind: int = 0,
        size: int = 1,
        remove: bool = False,
        slot: int = 0,
    ) -> dict[str, Any]:
        addr = "0x0" if _is_omitted_va(va) else self._va(va)
        return self.engine.call(
            "dbg_hwbp",
            va=addr,
            kind=int(kind),
            size=int(size),
            **{"del": 1 if remove else 0},
            slot=int(slot),
        )

    def dbg_membp(self, va: int | str, size: int = 4096, remove: bool = False) -> dict[str, Any]:
        return self.engine.call("dbg_membp", va=self._va(va), size=int(size), **{"del": 1 if remove else 0})

    def dbg_snap(self, idx: int | None = None) -> dict[str, Any]:
        return self.engine.call("dbg_snap", idx=idx)

    def dbg_mods(self) -> list[dict[str, Any]]:
        return list(self.engine.call("dbg_mods").get("items", []))

    def dbg_threads(self) -> list[dict[str, Any]]:
        return list(self.engine.call("dbg_threads").get("items", []))

    def dbg_mmap(self) -> list[dict[str, Any]]:
        res = self.engine.call("dbg_mmap")
        return list(res.get("items", [])) if res.get("ok") else []

    def dbg_backtrace(self) -> list[dict[str, Any]]:
        res = self.engine.call("dbg_bt")
        return list(res.get("items", [])) if res.get("ok") else []

    def dbg_ttd_record(self, n: int = 128) -> dict[str, Any]:
        return self.engine.call("dbg_ttd_rec", n=int(n))

    def dbg_ttd_back(self) -> dict[str, Any]:
        return self.engine.call("dbg_ttd_back")

    def dbg_ttd_who_wrote(self, va: int | str = 0, reg: str = "") -> dict[str, Any]:
        target: int | str = 0 if _is_omitted_va(va) else self._va(va)
        return self.engine.call("dbg_ttd_who", va=target, reg=str(reg))

    def dbg_mem(self, va: int | str, n: int = 64) -> bytes:
        res = self.engine.call("dbg_mem", va=_va_hex(va), n=int(n))
        return bytes.fromhex(res.get("hex", "")) if res.get("ok") else b""

    def dbg_write_mem(self, va: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
        base = _va_int(self._va(va))
        if isinstance(data, (bytes, bytearray, memoryview)):
            raw = bytes(data)
        elif isinstance(data, str):
            cleaned = data.replace(",", " ")
            raw = bytes.fromhex(cleaned)
        else:
            raise ValueError(f"data must be bytes or hex string, got {type(data).__name__}")
        if not raw:
            raise ValueError("data must be non-empty")
        total = 0
        off = 0
        # chunk at 512 bytes to match rpc dbg_mem / dbg_write_mem buffer limits
        while off < len(raw):
            chunk = raw[off:off + 512]
            res = self.engine.call("dbg_write_mem", va=hex(base + off), hex=chunk.hex())
            if not res.get("ok"):
                if total > 0:
                    res = dict(res)
                    res["written"] = total
                return res
            w = int(res.get("written", len(chunk)))
            total += w
            off += len(chunk)
            if w < len(chunk):
                break
        return {"ok": True, "written": total}

    def dbg_detach(self) -> dict[str, Any]:
        return self.engine.call("dbg_detach")

    def dbg_kill(self) -> dict[str, Any]:
        return self.engine.call("dbg_kill")

    def gdb_connect(self, host: str = "127.0.0.1", port: int = 1234, ms: int = 2500) -> dict[str, Any]:
        return self.engine.call("gdb_connect", host=str(host), port=int(port), ms=int(ms))

    def gdb_step(self) -> dict[str, Any]:
        return self.engine.call("gdb_step")

    def gdb_cont(self, ms: int = 1500) -> dict[str, Any]:
        return self.engine.call("gdb_cont", ms=int(ms))

    def gdb_bp(self, va: int | str, hw: bool = False, remove: bool = False) -> dict[str, Any]:
        return self.engine.call("gdb_bp", va=self._va(va), hw=1 if hw else 0, **{"del": 1 if remove else 0})

    def gdb_mem(self, va: int | str, n: int = 64) -> bytes:
        res = self.engine.call("gdb_mem", va=_va_hex(va), n=int(n))
        return bytes.fromhex(res.get("hex", "")) if res.get("ok") else b""

    def gdb_disconnect(self) -> dict[str, Any]:
        return self.engine.call("gdb_disconnect")

    def dmp_open(self, path: str | Path) -> dict[str, Any]:
        p = Path(path)
        target = str(p.resolve()) if p.exists() else str(path)
        return self.engine.call("dmp_open", path=target)

    def dmp_mem(self, va: int | str, n: int = 64) -> bytes:
        res = self.engine.call("dmp_mem", va=_va_hex(va), n=int(n))
        return bytes.fromhex(res.get("hex", "")) if res.get("ok") else b""

    def taint_run(self, va: int | str, reg: str = "rcx", buf_len: int = 0, steps: int = 128) -> dict[str, Any]:
        return self.engine.call("taint", va=self._va(va), reg=str(reg), buf_len=int(buf_len), n=int(steps))

    def sym_solve(self, src_va: int | str, dst_va: int | str) -> dict[str, Any]:
        return self.engine.call("sym_solve", **{"from": self._va(src_va), "to": self._va(dst_va)})

    def yara_defaults(self) -> str:
        res = self.engine.call("yara_defaults")
        return str(res.get("rules", "")) if res.get("ok") else ""

    def yara_scan(self, rules: str = "") -> dict[str, Any]:
        return self.engine.call("yara", rules=str(rules))

    def carve(self) -> list[dict[str, Any]]:
        res = self.engine.call("carve")
        return list(res.get("items", [])) if res.get("ok") else []

    def extract_carve(self, off: int, size: int, path: str | Path) -> bool:
        res = self.engine.call("carve_extract", off=int(off), size=int(size), path=str(Path(path)))
        return bool(res.get("ok"))

    def extract_iocs(self) -> list[dict[str, Any]]:
        res = self.engine.call("iocs")
        return list(res.get("items", [])) if res.get("ok") else []

    def vuln_scan(self) -> dict[str, Any]:
        return self.engine.call("vuln")

    def patch_triage(self, other_path: str | Path = "") -> list[dict[str, Any]]:
        target = ""
        if other_path:
            p = Path(other_path)
            target = str(p.resolve()) if p.exists() else str(other_path)
        res = self.engine.call("pdiff", path=target)
        return list(res.get("items", [])) if res.get("ok") else []

    def hilbert_map(self, order: int = 6) -> dict[str, Any]:
        o = max(4, min(6, int(order)))
        return self.engine.call("hilbert", order=o)

    def propose(self, va: int | str, kind: str, val: str, reason: str = "", conf: int = 85) -> dict[str, Any]:
        k = str(kind).strip().lower()
        if k not in ("rename", "cmt", "type"):
            raise ValueError(f"unsupported suggestion kind: {kind}")
        addr = "0x0" if _is_omitted_va(va) else self._va(va)
        c = max(0, min(100, int(conf)))
        return self.engine.call("sug_add", va=addr, kind=k, val=str(val), reason=str(reason), conf=c)

    def suggestions(self) -> dict[str, Any]:
        return self.engine.call("sug_list")

    def decide_suggestion(self, sug_id: int = 0, accept: bool = True, min_conf: int = 0) -> dict[str, Any]:
        return self.engine.call(
            "sug_decide",
            id=int(sug_id),
            accept=1 if accept else 0,
            min_conf=int(min_conf),
        )

    def _collect_report(self) -> dict[str, Any]:
        info = self.info
        triage = self.triage()
        ent_map = self.entropy_map()
        ent_by_va = {s.get("va"): float(s.get("ent", 0.0)) for s in ent_map.get("secs", [])}
        secs = []
        for s in info.get("secs", []):
            row = dict(s)
            row["ent"] = ent_by_va.get(s.get("va"), 0.0)
            row["perm_str"] = _perm_str(int(s.get("perm", 0)))
            secs.append(row)
        entry_dec = self.decompile(self.entry) if self.entry else ""
        return {
            "info": info,
            "triage": triage if triage.get("ok") else {},
            "secs": secs,
            "crypto": self.crypto(),
            "vtables": self.vtables(),
            "entry_dec": entry_dec,
        }

    def export_report(self, path: str | Path, fmt: str = "html") -> str:
        kind = fmt.lower().strip()
        if kind not in ("html", "md", "markdown"):
            raise ValueError(f"unsupported report format: {fmt}")
        data = self._collect_report()
        text = _render_report_md(data) if kind in ("md", "markdown") else _render_report_html(data)
        out = Path(path)
        if out.parent and not out.parent.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return str(out.resolve())


Session = Binary


def _render_report_md(data: dict[str, Any]) -> str:
    info, tri = data["info"], data["triage"]
    lines = [
        f"# Investigation Report: {Path(info.get('path', 'unknown')).name}",
        "",
        "## Summary",
        f"- **Path**: `{info.get('path', '')}`",
        f"- **Format**: `{info.get('fmt', '')}` / `{info.get('arch', '')}` ({info.get('bits', 0)}-bit)",
        f"- **Size**: {info.get('size', 0)} bytes | **Base**: `{info.get('base', '0x0')}` | **Entry**: `{info.get('entry', '0x0')}`",
        f"- **Counts**: {info.get('nfunc', 0)} functions, {info.get('nsym', 0)} symbols, {info.get('nstr', 0)} strings, {info.get('nxref', 0)} xrefs",
        f"- **Verdict**: `{tri.get('verdict', 'n/a')}` | **Packer**: `{tri.get('packer', 'none')}` | **Compiler**: `{tri.get('compiler', 'unknown')}`",
        f"- **Scores**: pack={tri.get('pack_score', 0)}, obf={tri.get('obf_score', 0)}, max_entropy={tri.get('max_ent', 0.0):.2f}",
    ]
    for note in tri.get("notes", []):
        lines.append(f"- Note: {note}")

    lines += ["", "## Sections & Entropy", "| Name | VA | VSize | FSize | Perm | Entropy |", "|---|---:|---:|---:|:---:|---:|"]
    for s in data["secs"]:
        lines.append(
            f"| `{s.get('name', '')}` | `{s.get('va', '')}` | {s.get('vsize', 0)} | {s.get('fsize', 0)} | `{s['perm_str']}` | {s['ent']:.2f} |"
        )

    lines += ["", "## Capabilities"]
    caps = tri.get("caps", [])
    if not caps:
        lines.append("_None detected._")
    for c in caps:
        apis = ", ".join(f"`{it['name']}` ({it['va']})" for it in c.get("items", []))
        lines.append(f"- **{c.get('group', '')}**: {apis}")

    lines += ["", "## Hotspots"]
    spots = tri.get("spots", [])
    if not spots:
        lines.append("_None detected._")
    else:
        lines += ["| VA | Kind | Score | Name | Reason |", "|---|---|---:|---|---|"]
        for sp in spots:
            lines.append(
                f"| `{sp.get('va', '')}` | {sp.get('kind', '')} | {sp.get('score', 0)} | `{sp.get('name', '')}` | {sp.get('reason', '')} |"
            )

    lines += ["", "## Crypto Constants"]
    if not data["crypto"]:
        lines.append("_None detected._")
    else:
        lines += ["| VA | Algorithm | Detail |", "|---|---|---|"]
        for c in data["crypto"]:
            lines.append(f"| `{c.get('va', '')}` | {c.get('algo', '')} | {c.get('detail', '')} |")

    lines += ["", "## Vtables"]
    if not data["vtables"]:
        lines.append("_None detected._")
    else:
        lines += ["| VA | Entries | Class |", "|---|---:|---|"]
        for v in data["vtables"]:
            lines.append(f"| `{v.get('va', '')}` | {v.get('n', 0)} | `{v.get('cls', '')}` |")

    lines += ["", f"## Entry Decompilation (`{info.get('entry', '0x0')}`)", "```c", data["entry_dec"] or "// unavailable", "```", ""]
    return "\n".join(lines)


def _esc(val: Any) -> str:
    return html.escape(str(val), quote=True)


def _render_report_html(data: dict[str, Any]) -> str:
    info, tri = data["info"], data["triage"]
    title = _esc(Path(info.get("path", "binary")).name)
    sec_rows = "".join(
        f"<tr><td class='mono'>{_esc(s.get('name', ''))}</td>"
        f"<td class='mono muted'>{_esc(s.get('va', ''))}</td>"
        f"<td class='num'>{s.get('vsize', 0)}</td><td class='num'>{s.get('fsize', 0)}</td>"
        f"<td class='mono'>{_esc(s['perm_str'])}</td>"
        f"<td><span class='ent'>{s['ent']:.2f}</span>"
        f"<span class='bar'><i style='width:{min(100, int(s['ent'] / 8.0 * 100))}%'></i></span></td></tr>"
        for s in data["secs"]
    )
    cap_rows = "".join(
        f"<div class='cap'><span class='tag'>{_esc(c.get('group', ''))}</span>"
        + " ".join(f"<code>{_esc(it['name'])}</code>" for it in c.get("items", []))
        + "</div>"
        for c in tri.get("caps", [])
    ) or "<p class='muted'>None detected.</p>"
    spot_rows = "".join(
        f"<tr><td class='mono muted'>{_esc(sp.get('va', ''))}</td>"
        f"<td>{_esc(sp.get('kind', ''))}</td><td class='num'>{sp.get('score', 0)}</td>"
        f"<td class='mono'>{_esc(sp.get('name', ''))}</td><td>{_esc(sp.get('reason', ''))}</td></tr>"
        for sp in tri.get("spots", [])
    )
    crypto_rows = "".join(
        f"<tr><td class='mono muted'>{_esc(c.get('va', ''))}</td>"
        f"<td>{_esc(c.get('algo', ''))}</td><td>{_esc(c.get('detail', ''))}</td></tr>"
        for c in data["crypto"]
    )
    vtable_rows = "".join(
        f"<tr><td class='mono muted'>{_esc(v.get('va', ''))}</td>"
        f"<td class='num'>{v.get('n', 0)}</td><td class='mono'>{_esc(v.get('cls', ''))}</td></tr>"
        for v in data["vtables"]
    )
    notes_html = "".join(f"<li>{_esc(n)}</li>" for n in tri.get("notes", []))
    flags = [
        k for k, on in (
            ("RWX", tri.get("has_rwx")),
            ("High-Ent Exec", tri.get("high_ent")),
            ("EP Anomaly", tri.get("ep_anom")),
            ("Sparse Imports", tri.get("sparse_imp")),
        ) if on
    ]
    flag_html = " ".join(f"<span class='pill warn'>{_esc(f)}</span>" for f in flags)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>xdis report - {title}</title>
<style>
:root{{--bg:#17191d;--elev:#1d2026;--bdr:#262a32;--fg:#ced4de;--soft:#9aa3b2;--muted:#6c7585;--acc:#7da2bf;--warn:#d2a978;}}
*{{box-sizing:border-box;}}
body{{margin:0;padding:28px;background:var(--bg);color:var(--fg);font:13px/1.55 "Segoe UI",system-ui,sans-serif;}}
.wrap{{max-width:1100px;margin:0 auto;}}
h1{{margin:0 0 4px;font-size:20px;font-weight:600;}}
h2{{margin:24px 0 10px;font-size:14px;font-weight:600;color:var(--soft);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--bdr);padding-bottom:6px;}}
.meta{{color:var(--muted);font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;margin-bottom:18px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:10px;margin-bottom:14px;}}
.card{{background:var(--elev);border:1px solid var(--bdr);border-radius:6px;padding:10px 12px;}}
.card .k{{font-size:11px;color:var(--muted);text-transform:uppercase;}}
.card .v{{font-size:15px;font-weight:600;margin-top:2px;font-family:"Cascadia Mono",Consolas,monospace;}}
.pill{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;background:var(--elev);border:1px solid var(--bdr);color:var(--soft);margin-right:6px;}}
.pill.warn{{border-color:#5a4936;color:var(--warn);}}
table{{width:100%;border-collapse:collapse;background:var(--elev);border:1px solid var(--bdr);border-radius:6px;overflow:hidden;}}
th,td{{padding:7px 10px;border-bottom:1px solid var(--bdr);text-align:left;vertical-align:top;}}
th{{font-size:11px;color:var(--muted);text-transform:uppercase;background:#131518;}}
tr:last-child td{{border-bottom:none;}}
.mono{{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;}}
.num{{text-align:right;font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;}}
.muted{{color:var(--muted);}}
.ent{{display:inline-block;width:36px;font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;}}
.bar{{display:inline-block;width:90px;height:6px;background:#131518;border-radius:3px;overflow:hidden;vertical-align:middle;}}
.bar i{{display:block;height:100%;background:var(--acc);}}
.cap{{margin:6px 0;display:flex;flex-wrap:wrap;gap:6px;align-items:center;}}
.tag{{background:#131518;border:1px solid var(--bdr);color:var(--acc);padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600;}}
code{{background:var(--elev);border:1px solid var(--bdr);padding:1px 5px;border-radius:3px;font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;}}
pre{{background:#131518;border:1px solid var(--bdr);border-radius:6px;padding:12px 14px;overflow:auto;font:12px/1.55 "Cascadia Mono",Consolas,monospace;color:var(--fg);}}
ul{{margin:8px 0 0 18px;padding:0;color:var(--soft);}}
</style>
</head>
<body>
<div class="wrap">
  <h1>{title}</h1>
  <div class="meta">{_esc(info.get('path', ''))} &middot; {_esc(info.get('fmt', ''))} {_esc(info.get('arch', ''))} ({info.get('bits', 0)}-bit) &middot; {info.get('size', 0)} bytes &middot; base {_esc(info.get('base', '0x0'))} &middot; entry {_esc(info.get('entry', '0x0'))}</div>
  <div class="grid">
    <div class="card"><div class="k">Verdict</div><div class="v">{_esc(tri.get('verdict', 'n/a'))}</div></div>
    <div class="card"><div class="k">Pack / Obf Score</div><div class="v">{tri.get('pack_score', 0)} / {tri.get('obf_score', 0)}</div></div>
    <div class="card"><div class="k">Max Entropy</div><div class="v">{tri.get('max_ent', 0.0):.2f}</div></div>
    <div class="card"><div class="k">Packer</div><div class="v">{_esc(tri.get('packer') or 'none')}</div></div>
    <div class="card"><div class="k">Compiler</div><div class="v">{_esc(tri.get('compiler') or 'unknown')}</div></div>
    <div class="card"><div class="k">Functions / Xrefs</div><div class="v">{info.get('nfunc', 0)} / {info.get('nxref', 0)}</div></div>
  </div>
  <div>{flag_html}</div>
  {f"<ul>{notes_html}</ul>" if notes_html else ""}

  <h2>Sections &amp; Entropy</h2>
  <table><thead><tr><th>Name</th><th>VA</th><th class="num">VSize</th><th class="num">FSize</th><th>Perm</th><th>Entropy</th></tr></thead>
  <tbody>{sec_rows or "<tr><td colspan='6' class='muted'>None</td></tr>"}</tbody></table>

  <h2>Capabilities</h2>
  {cap_rows}

  <h2>Hotspots</h2>
  {"<table><thead><tr><th>VA</th><th>Kind</th><th class='num'>Score</th><th>Name</th><th>Reason</th></tr></thead><tbody>" + spot_rows + "</tbody></table>" if spot_rows else "<p class='muted'>None detected.</p>"}

  <h2>Crypto Constants</h2>
  {"<table><thead><tr><th>VA</th><th>Algorithm</th><th>Detail</th></tr></thead><tbody>" + crypto_rows + "</tbody></table>" if crypto_rows else "<p class='muted'>None detected.</p>"}

  <h2>Vtables</h2>
  {"<table><thead><tr><th>VA</th><th class='num'>Entries</th><th>Class</th></tr></thead><tbody>" + vtable_rows + "</tbody></table>" if vtable_rows else "<p class='muted'>None detected.</p>"}

  <h2>Entry Decompilation ({_esc(info.get('entry', '0x0'))})</h2>
  <pre>{_esc(data['entry_dec'] or '// unavailable')}</pre>
</div>
</body>
</html>
"""


def open(path: str | Path, exe: str | Path | None = None) -> Binary:
    eng = Engine(exe=exe)
    p = Path(path)
    target = str(p.resolve()) if p.exists() else str(path)
    res = eng.call("open", path=target)
    if not res.get("ok"):
        eng.close()
        raise XdisError(str(res.get("err", f"open failed: {target}")))
    return Binary(eng, info=res, owns_engine=True)


def connect(port: int | None = None, host: str = "127.0.0.1", token: str = "") -> Binary:
    env = os.environ.get("XDIS_RPC_PORT", "").strip()
    tcp_port = port if port is not None else (int(env) if env else None)
    if tcp_port is None:
        raise XdisError("XDIS_RPC_PORT is not set")
    eng = Engine(port=tcp_port, host=host, token=token)
    info = eng.call("info")
    if not info.get("ok"):
        eng.close()
        raise XdisError(str(info.get("err", "failed to query live session")))
    return Binary(eng, info=info, owns_engine=True)
