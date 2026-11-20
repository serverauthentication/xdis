from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk"))
import xdis

target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "xdis.exe"

with xdis.open(target) as db:
    tri = db.triage()
    print(f"{Path(db.path).name}: {db.fmt} {db.arch} ({db.bits}-bit) entry={hex(db.entry)} funcs={db.info.get('nfunc', 0)}")
    print(f"verdict={tri.get('verdict')} packer={tri.get('packer') or 'none'} pack={tri.get('pack_score')} obf={tri.get('obf_score')} max_ent={tri.get('max_ent', 0):.2f}")

    print("\nTop functions:")
    for fn in sorted(db.functions(limit=200), key=lambda f: f.size, reverse=True)[:8]:
        print(f"  {hex(fn.va):>14}  {fn.size:>6}B  {fn.name}")

    hits = db.crypto()
    print(f"\nCrypto hits ({len(hits)}):")
    for hit in hits[:8] or [{"va": "-", "algo": "none", "detail": ""}]:
        print(f"  {hit['va']:>14}  {hit['algo']:<12}  {hit['detail']}")

    print(f"\nEntry decompile ({hex(db.entry)}):")
    print("\n".join(db.decompile(db.entry).splitlines()[:24]) or "// unavailable")
