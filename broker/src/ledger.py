"""Proof ledger: every verdict AXIOM issues, stored in DynamoDB."""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Attr, Key

FEED = "ledger"
# Verdicts are deterministic and the cache key includes the evaluator version, so arena results can be
# served for the whole judging window. Judges' scenario clicks then never depend on the daily review cap.
ARENA_CACHE_SECONDS = 21 * 24 * 3600
RECENT_CACHE_SECONDS = 5
_table = None
_recent_cache: dict = {}


def _ledger():
    global _table
    if _table is None:
        _table = boto3.resource("dynamodb").Table(os.environ["LEDGER_TABLE"])
    return _table


def canonical_hash(doc: dict) -> str:
    """SHA-256 over a canonical JSON encoding. The minted session carries this as a tag."""
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def put(record: dict) -> None:
    _recent_cache.clear()  # the next ledger view in this instance shows the new record
    _ledger().put_item(Item={
        "plan_id": record["plan_id"],
        "feed": FEED,
        "created_at": record["created_at"],
        "verdict": record["verdict"],
        "source": record["source"],
        "stack": record["stack"],
        "doc": json.dumps(record, default=str),
    })


def get(plan_id: str) -> dict | None:
    item = _ledger().get_item(Key={"plan_id": plan_id}).get("Item")
    return json.loads(item["doc"]) if item else None


def recent(limit: int = 25) -> list[dict]:
    """Latest verdicts. Cached for a few seconds so a flood of page loads cannot become a flood of reads."""
    if _recent_cache.get("expires", 0) > time.time():
        return _recent_cache["records"]
    items = _ledger().query(
        IndexName="byTime",
        KeyConditionExpression=Key("feed").eq(FEED),
        ScanIndexForward=False,
        Limit=limit,
    ).get("Items", [])
    records = [_summary(json.loads(i["doc"])) for i in items]
    _recent_cache.update(records=records, expires=time.time() + RECENT_CACHE_SECONDS)
    return records


def cached_arena(key: str) -> dict | None:
    """Return a recent arena record for an identical submission, so repeat clicks cost nothing."""
    item = _ledger().get_item(Key={"plan_id": f"cache#{key}"}).get("Item")
    if not item or int(item["expires_at"]) < time.time():
        return None
    return get(item["target"])


def remember_arena(key: str, plan_id: str) -> None:
    _ledger().put_item(Item={
        "plan_id": f"cache#{key}",
        "target": plan_id,
        "expires_at": int(time.time()) + ARENA_CACHE_SECONDS,
    })


def take_budget(kind: str, units: int, daily_cap: int) -> bool:
    """Atomically reserve `units` from today's arena budget of this kind (e.g. "checks", "reviews")."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        _ledger().update_item(
            Key={"plan_id": f"budget#{kind}#{day}"},
            UpdateExpression="ADD used :n",
            ConditionExpression=Attr("used").not_exists() | Attr("used").lte(daily_cap - units),
            ExpressionAttributeValues={":n": units},
        )
        return True
    except _ledger().meta.client.exceptions.ConditionalCheckFailedException:
        return False


def _summary(record: dict) -> dict:
    return {
        "plan_id": record["plan_id"],
        "created_at": record["created_at"],
        "source": record["source"],
        "stack": record["stack"],
        "intent": record.get("intent", ""),
        "verdict": record["verdict"],
        "headline": (record.get("assessment") or {}).get("headline", ""),
        "blocking": sum(1 for f in record.get("findings", []) if f.get("severity") == "BLOCK"),
        "proof_hash": record.get("proof_hash", ""),
        "credential_minted": bool(record.get("credential")),
    }

