"""
offset_vault.py — Persistent SQLite database for function signatures and memory offsets.

Purpose: When a game patches, function addresses change but byte patterns (AOB) stay the same.
         The vault stores AOB patterns → auto-rescans on game update → offsets stay valid.

Schema:
  game_offsets(id, game, version, name, address_hex, aob_pattern, module, notes, updated_at)
  scan_history(id, offset_id, old_addr, new_addr, found_at)
"""

import sqlite3
import time
import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH  = BASE_DIR / "output" / "offset_vault.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(BASE_DIR))


# ─────────────────────────────────────────────────────────────────────────────
# DB Init
# ─────────────────────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS game_offsets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            game        TEXT NOT NULL,
            version     TEXT NOT NULL DEFAULT 'any',
            name        TEXT NOT NULL,
            address_hex TEXT,
            aob_pattern TEXT,
            module      TEXT,
            notes       TEXT,
            updated_at  REAL NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            offset_id INTEGER NOT NULL REFERENCES game_offsets(id),
            old_addr  TEXT,
            new_addr  TEXT,
            found_at  REAL NOT NULL
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_game ON game_offsets(game)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_name ON game_offsets(game, name)")
    con.commit()
    return con


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def add_offset(
    game: str,
    name: str,
    address_hex: Optional[str] = None,
    aob_pattern: Optional[str] = None,
    module: Optional[str] = None,
    version: str = "any",
    notes: Optional[str] = None,
) -> dict:
    """Add or update an offset entry. At least one of address_hex or aob_pattern required."""
    if not address_hex and not aob_pattern:
        return {"error": "Provide at least address_hex or aob_pattern"}

    con = _connect()
    now = time.time()

    # Upsert by (game, name)
    existing = con.execute(
        "SELECT id FROM game_offsets WHERE game=? AND name=?", (game, name)
    ).fetchone()

    if existing:
        con.execute(
            """UPDATE game_offsets
               SET address_hex=?, aob_pattern=?, module=?, version=?, notes=?, updated_at=?
               WHERE id=?""",
            (address_hex, aob_pattern, module, version, notes, now, existing["id"]),
        )
        row_id = existing["id"]
        action = "updated"
    else:
        cur = con.execute(
            """INSERT INTO game_offsets
               (game, version, name, address_hex, aob_pattern, module, notes, updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (game, version, name, address_hex, aob_pattern, module, notes, now),
        )
        row_id = cur.lastrowid
        action = "created"

    con.commit()
    con.close()
    return {"id": row_id, "action": action, "game": game, "name": name}


def list_offsets(game: Optional[str] = None) -> dict:
    """List all offsets, optionally filtered by game name."""
    con = _connect()
    if game:
        rows = con.execute(
            "SELECT * FROM game_offsets WHERE game LIKE ? ORDER BY game, name",
            (f"%{game}%",),
        ).fetchall()
    else:
        rows = con.execute(
            "SELECT * FROM game_offsets ORDER BY game, name"
        ).fetchall()
    con.close()

    offsets = [dict(r) for r in rows]
    return {"count": len(offsets), "offsets": offsets}


def get_offset(game: str, name: str) -> dict:
    """Get a specific offset by game+name."""
    con = _connect()
    row = con.execute(
        "SELECT * FROM game_offsets WHERE game=? AND name=?", (game, name)
    ).fetchone()
    con.close()
    if not row:
        return {"error": f"No offset '{name}' for game '{game}'"}
    return dict(row)


def delete_offset(game: str, name: str) -> dict:
    """Delete an offset entry."""
    con = _connect()
    con.execute("DELETE FROM game_offsets WHERE game=? AND name=?", (game, name))
    con.commit()
    con.close()
    return {"deleted": True, "game": game, "name": name}


def rescan_offsets(game: str, binary_path: str) -> dict:
    """
    Re-scan a game binary for all AOB patterns stored in the vault for that game.
    Updates address_hex automatically. Logs old/new to scan_history.
    Returns list of updated offsets.
    """
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return {"error": f"File not found: {binary_path}"}

    con = _connect()
    rows = con.execute(
        "SELECT * FROM game_offsets WHERE game=? AND aob_pattern IS NOT NULL", (game,)
    ).fetchall()

    if not rows:
        con.close()
        return {"error": f"No AOB patterns stored for game '{game}'"}

    results = []
    now = time.time()

    for row in rows:
        pattern = row["aob_pattern"]
        old_addr = row["address_hex"]

        # Parse AOB pattern — supports "??" wildcards
        pattern_bytes = []
        masks = []
        for tok in pattern.strip().split():
            if tok in ("??", "?"):
                pattern_bytes.append(0x00)
                masks.append(False)
            else:
                pattern_bytes.append(int(tok, 16))
                masks.append(True)

        pat_len = len(pattern_bytes)
        new_addr = None

        # Brute-force scan
        for i in range(len(data) - pat_len):
            match = True
            for j, (b, m) in enumerate(zip(pattern_bytes, masks)):
                if m and data[i + j] != b:
                    match = False
                    break
            if match:
                new_addr = hex(i)
                break

        if new_addr and new_addr != old_addr:
            con.execute(
                "UPDATE game_offsets SET address_hex=?, updated_at=? WHERE id=?",
                (new_addr, now, row["id"]),
            )
            con.execute(
                "INSERT INTO scan_history (offset_id, old_addr, new_addr, found_at) VALUES (?,?,?,?)",
                (row["id"], old_addr, new_addr, now),
            )
            results.append({
                "name": row["name"],
                "old_address": old_addr,
                "new_address": new_addr,
                "status": "updated",
            })
        elif new_addr == old_addr:
            results.append({"name": row["name"], "address": new_addr, "status": "unchanged"})
        else:
            results.append({"name": row["name"], "status": "not_found", "pattern": pattern})

    con.commit()
    con.close()
    return {"game": game, "binary": binary_path, "results": results, "count": len(results)}


def export_vault(game: Optional[str] = None) -> dict:
    """Export vault to JSON-serializable dict (for sharing/backup)."""
    return list_offsets(game)


def import_offsets(entries: List[Dict[str, Any]]) -> dict:
    """Bulk import offsets from a list of dicts."""
    added = 0
    errors = []
    for e in entries:
        try:
            add_offset(
                game=e["game"],
                name=e["name"],
                address_hex=e.get("address_hex"),
                aob_pattern=e.get("aob_pattern"),
                module=e.get("module"),
                version=e.get("version", "any"),
                notes=e.get("notes"),
            )
            added += 1
        except Exception as ex:
            errors.append({"entry": e, "error": str(ex)})
    return {"imported": added, "errors": errors}
