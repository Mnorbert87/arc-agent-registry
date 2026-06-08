"""
SQLite persistence: a local index of agents, confirmed feedback, and a service directory.

Only facts that actually happened are written. Feedback and registrations are recorded with
their on-chain tx hash, so the local store never claims something the chain did not. The
service directory is the discovery layer: who sells what x402 endpoint, and at what price.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Optional

DEFAULT_DB = os.getenv("ARC_REGISTRY_DB", "arc_registry.db")


class Store:
    def __init__(self, path: str = DEFAULT_DB):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                agent_id     INTEGER PRIMARY KEY,
                owner        TEXT,
                name         TEXT,
                domain       TEXT,
                card_uri     TEXT,
                capabilities TEXT,
                tx_hash      TEXT,
                updated_at   INTEGER
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id   INTEGER,
                client     TEXT,
                score      INTEGER,
                tag        TEXT,
                tx_hash    TEXT,
                created_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS services (
                endpoint    TEXT PRIMARY KEY,
                agent_id    INTEGER,
                price       INTEGER,
                asset       TEXT,
                description TEXT,
                added_at    INTEGER
            );
            """
        )
        self.conn.commit()

    # -- agents --

    def upsert_agent(self, agent_id: int, owner: str, name: str, domain: str,
                     card_uri: str, capabilities: list[str], tx_hash: str) -> None:
        self.conn.execute(
            """INSERT INTO agents (agent_id, owner, name, domain, card_uri, capabilities, tx_hash, updated_at)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(agent_id) DO UPDATE SET
                 owner=excluded.owner, name=excluded.name, domain=excluded.domain,
                 card_uri=excluded.card_uri, capabilities=excluded.capabilities,
                 tx_hash=excluded.tx_hash, updated_at=excluded.updated_at""",
            (agent_id, owner, name, domain, card_uri, json.dumps(capabilities), tx_hash, int(time.time())),
        )
        self.conn.commit()

    def get_agent(self, agent_id: int) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return dict(row) if row else None

    def list_agents(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM agents ORDER BY agent_id").fetchall()]

    # -- feedback (only confirmed, always with a tx hash) --

    def record_feedback(self, agent_id: int, client: str, score: int, tag: str, tx_hash: str) -> None:
        if not tx_hash:
            raise ValueError("refusing to record feedback without a tx hash")
        self.conn.execute(
            "INSERT INTO feedback (agent_id, client, score, tag, tx_hash, created_at) VALUES (?,?,?,?,?,?)",
            (agent_id, client, score, tag, tx_hash, int(time.time())),
        )
        self.conn.commit()

    def feedback_for(self, agent_id: int) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM feedback WHERE agent_id=? ORDER BY id DESC", (agent_id,)).fetchall()]

    # -- service directory --

    def add_service(self, endpoint: str, agent_id: int, price: int, asset: str, description: str = "") -> None:
        self.conn.execute(
            """INSERT INTO services (endpoint, agent_id, price, asset, description, added_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(endpoint) DO UPDATE SET
                 agent_id=excluded.agent_id, price=excluded.price, asset=excluded.asset,
                 description=excluded.description""",
            (endpoint, agent_id, price, asset, description, int(time.time())),
        )
        self.conn.commit()

    def get_service(self, endpoint: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM services WHERE endpoint=?", (endpoint,)).fetchone()
        return dict(row) if row else None

    def list_services(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM services ORDER BY added_at DESC").fetchall()]

    def close(self) -> None:
        self.conn.close()
