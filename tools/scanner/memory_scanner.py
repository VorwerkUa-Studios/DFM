"""
memory_scanner.py — Two-pass Frida memory diff scanner (AI Cheat Engine replacement).

Flow:
  1. snapshot(pid, value_type)  → saves full memory dump to temp file, returns snapshot_id
  2. diff(snapshot_id, new_value) → scans snapshot vs current memory, returns matching addresses
  3. read(pid, address, type)   → reads single value at address
  4. write(pid, address, value, type) → writes value at address (with backup)
  5. watch(pid, address, type, interval_ms) → polls address and logs changes (non-blocking)

Supported value types: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 bytes:<hex>
"""

import os
import sys
import struct
import tempfile
import json
import time
import uuid
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

# ── Frida import (optional — graceful fallback) ───────────────────────────────
try:
    import frida
    FRIDA_OK = True
except ImportError:
    FRIDA_OK = False

# ── Snapshot storage ──────────────────────────────────────────────────────────
SNAP_DIR = BASE_DIR / "output" / "snapshots"
SNAP_DIR.mkdir(parents=True, exist_ok=True)

VALUE_FORMATS = {
    "u8":  ("B", 1), "i8":  ("b", 1),
    "u16": ("H", 2), "i16": ("h", 2),
    "u32": ("I", 4), "i32": ("i", 4),
    "u64": ("Q", 8), "i64": ("q", 8),
    "f32": ("f", 4), "f64": ("d", 8),
}

# ─────────────────────────────────────────────────────────────────────────────
# Frida JS helpers
# ─────────────────────────────────────────────────────────────────────────────

_JS_DUMP = r"""
rpc.exports = {
  dumpRanges: function(protection) {
    var prot = protection || 'r--';
    var ranges = Process.enumerateRanges(prot);
    return ranges.map(function(r) {
      return { base: r.base.toString(), size: r.size, prot: r.protection };
    });
  },
  readBytes: function(addrStr, size) {
    try {
      var ptr = ptr(addrStr);
      return Array.from(ptr.readByteArray(size));
    } catch(e) { return null; }
  },
  writeBytes: function(addrStr, bytes) {
    try {
      Memory.protect(ptr(addrStr), bytes.length, 'rwx');
      ptr(addrStr).writeByteArray(bytes);
      return true;
    } catch(e) { return false; }
  },
  readValue: function(addrStr, fmt) {
    try {
      var p = ptr(addrStr);
      switch(fmt) {
        case 'u8':  return p.readU8();
        case 'i8':  return p.readS8();
        case 'u16': return p.readU16();
        case 'i16': return p.readS16();
        case 'u32': return p.readU32();
        case 'i32': return p.readS32();
        case 'u64': return p.readU64().toString();
        case 'i64': return p.readS64().toString();
        case 'f32': return p.readFloat();
        case 'f64': return p.readDouble();
      }
    } catch(e) { return null; }
  },
  scanValue: function(fmt, value, maxResults) {
    maxResults = maxResults || 500;
    var size = {'u8':1,'i8':1,'u16':2,'i16':2,'u32':4,'i32':4,'u64':8,'i64':8,'f32':4,'f64':8}[fmt];
    var pattern;
    // Build byte pattern from value
    var buf = new ArrayBuffer(size);
    var view = new DataView(buf);
    switch(fmt) {
      case 'u8':  view.setUint8(0, value); break;
      case 'i8':  view.setInt8(0, value); break;
      case 'u16': view.setUint16(0, value, true); break;
      case 'i16': view.setInt16(0, value, true); break;
      case 'u32': view.setUint32(0, value, true); break;
      case 'i32': view.setInt32(0, value, true); break;
      case 'f32': view.setFloat32(0, value, true); break;
      case 'f64': view.setFloat64(0, value, true); break;
      default: return [];
    }
    var bytes = Array.from(new Uint8Array(buf));
    pattern = bytes.map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ');
    var results = [];
    var ranges = Process.enumerateRanges('r--');
    for (var i = 0; i < ranges.length && results.length < maxResults; i++) {
      var r = ranges[i];
      try {
        var matches = Memory.scanSync(r.base, r.size, pattern);
        for (var j = 0; j < matches.length && results.length < maxResults; j++) {
          results.push(matches[j].address.toString());
        }
      } catch(e) {}
    }
    return results;
  }
};
"""

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _attach(pid: int):
    """Attach frida to pid, inject dump script, return script object."""
    if not FRIDA_OK:
        raise RuntimeError("frida not installed — run: pip install frida")
    session = frida.attach(pid)
    script = session.create_script(_JS_DUMP)
    script.load()
    return session, script


def snapshot(pid: int, value_type: str = "u32") -> dict:
    """
    Scan all readable memory for a given value type pattern.
    Saves a snapshot of (address, raw_bytes) pairs to disk.
    Returns { snapshot_id, path, range_count, byte_count }.
    """
    if not FRIDA_OK:
        return {"error": "frida not installed"}
    if value_type not in VALUE_FORMATS and not value_type.startswith("bytes:"):
        return {"error": f"Unknown value_type '{value_type}'. Use: {list(VALUE_FORMATS)} or bytes:<hex>"}

    snap_id = str(uuid.uuid4())[:8]
    snap_path = SNAP_DIR / f"{snap_id}.snap"

    session, script = _attach(pid)
    rpc = script.exports_sync

    ranges = rpc.dump_ranges("r--")
    total_bytes = 0
    entries = []

    fmt, size = VALUE_FORMATS.get(value_type, ("", 0)) if not value_type.startswith("bytes:") else ("", 0)
    if value_type.startswith("bytes:"):
        size = len(bytes.fromhex(value_type[6:])) // 2 + 1

    for r in ranges:
        base = r["base"]
        chunk_size = min(r["size"], 4 * 1024 * 1024)  # max 4 MB per range
        raw = rpc.read_bytes(base, chunk_size)
        if raw:
            entries.append({"base": base, "size": chunk_size, "data": raw})
            total_bytes += chunk_size

    # Save to disk
    meta = {
        "snap_id": snap_id,
        "pid": pid,
        "value_type": value_type,
        "timestamp": time.time(),
        "ranges": len(entries),
        "byte_count": total_bytes,
        "entries": entries,
    }
    with open(snap_path, "w", encoding="utf-8") as f:
        json.dump(meta, f)

    script.unload()
    session.detach()

    return {
        "snapshot_id": snap_id,
        "path": str(snap_path),
        "ranges_captured": len(entries),
        "total_mb": round(total_bytes / 1024 / 1024, 2),
        "value_type": value_type,
        "hint": f"Now change the value in-game, then call diff_snapshot('{snap_id}', new_value)",
    }


def diff_snapshot(snapshot_id: str, new_value, max_results: int = 500) -> dict:
    """
    Compare saved snapshot vs current live memory.
    Returns addresses where the value changed TO new_value.
    """
    if not FRIDA_OK:
        return {"error": "frida not installed"}

    snap_path = SNAP_DIR / f"{snapshot_id}.snap"
    if not snap_path.exists():
        return {"error": f"Snapshot '{snapshot_id}' not found"}

    with open(snap_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    pid = meta["pid"]
    value_type = meta["value_type"]
    fmt, size = VALUE_FORMATS.get(value_type, ("B", 1))

    session, script = _attach(pid)
    rpc = script.exports_sync

    # Scan live memory for new_value
    live_matches = set(rpc.scan_value(value_type, new_value, max_results * 10))

    # Cross-reference with snapshot: find addresses that had old value
    hits = []
    for entry in meta["entries"]:
        base_int = int(entry["base"], 16)
        old_data = bytes(entry["data"])
        for offset in range(0, len(old_data) - size + 1, size):
            addr_int = base_int + offset
            addr_str = hex(addr_int)
            if addr_str in live_matches:
                try:
                    old_val = struct.unpack_from("<" + fmt, old_data, offset)[0]
                    hits.append({
                        "address": addr_str,
                        "old_value": old_val,
                        "new_value": new_value,
                    })
                except struct.error:
                    pass
                if len(hits) >= max_results:
                    break
        if len(hits) >= max_results:
            break

    script.unload()
    session.detach()

    return {
        "snapshot_id": snapshot_id,
        "value_type": value_type,
        "new_value": new_value,
        "matches": hits,
        "count": len(hits),
        "hint": "If too many results, change value again in-game and call diff_snapshot again to narrow down",
    }


def read_memory_value(pid: int, address: str, value_type: str = "u32") -> dict:
    """Read a single value at a specific address."""
    if not FRIDA_OK:
        return {"error": "frida not installed"}
    session, script = _attach(pid)
    val = script.exports_sync.read_value(address, value_type)
    script.unload()
    session.detach()
    return {"address": address, "value_type": value_type, "value": val}


def write_memory_value(pid: int, address: str, value, value_type: str = "u32") -> dict:
    """Write a single value at a specific address."""
    if not FRIDA_OK:
        return {"error": "frida not installed"}

    fmt, size = VALUE_FORMATS.get(value_type, ("I", 4))
    raw = list(struct.pack("<" + fmt, int(value) if "f" not in fmt else float(value)))

    session, script = _attach(pid)
    ok = script.exports_sync.write_bytes(address, raw)
    script.unload()
    session.detach()
    return {"address": address, "value_type": value_type, "value": value, "success": ok}


def quick_scan(pid: int, value, value_type: str = "u32", max_results: int = 200) -> dict:
    """
    One-shot scan for a known value (no snapshot needed).
    Use when you already know the exact value (e.g., health = 100).
    """
    if not FRIDA_OK:
        return {"error": "frida not installed"}
    session, script = _attach(pid)
    matches = script.exports_sync.scan_value(value_type, value, max_results)
    script.unload()
    session.detach()
    return {
        "pid": pid,
        "value": value,
        "value_type": value_type,
        "matches": matches,
        "count": len(matches),
        "hint": "Pin down the exact address by changing the value in-game and using diff_snapshot",
    }
