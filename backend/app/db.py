"""
Storage layer. Tries to connect to a local MongoDB instance (as required by the
project spec). If MongoDB isn't running (common on a first-time student setup),
it transparently falls back to a simple JSON-file store with the SAME interface,
so the app is always runnable out of the box. Swap MONGO_URI in your environment
to point at a real MongoDB instance for the "production" path.
"""
import os
import json
import uuid
from datetime import datetime, timezone
from threading import Lock

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("MONGO_DB", "cyber_incident_intel")
FALLBACK_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "incidents_store.json")


class JsonFallbackStore:
    """Minimal drop-in replacement for the subset of pymongo collection methods we use."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._lock = Lock()
        if not os.path.exists(self.path):
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w") as f:
                json.dump([], f)

    def _read(self):
        with open(self.path, "r") as f:
            return json.load(f)

    def _write(self, data):
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def insert_one(self, doc):
        with self._lock:
            data = self._read()
            data.append(doc)
            self._write(data)
        return doc["_id"]

    def find(self, query=None, sort_desc=True):
        data = self._read()
        if sort_desc:
            data = sorted(data, key=lambda d: d.get("created_at", ""), reverse=True)
        return data

    def find_one(self, incident_id):
        data = self._read()
        for d in data:
            if d.get("_id") == incident_id:
                return d
        return None


class MongoStoreAdapter:
    """Thin adapter so main.py can call the same methods regardless of backend."""

    def __init__(self, collection):
        self.collection = collection

    def insert_one(self, doc):
        self.collection.insert_one(doc)
        return doc["_id"]

    def find(self, query=None, sort_desc=True):
        cursor = self.collection.find(query or {})
        if sort_desc:
            cursor = cursor.sort("created_at", -1)
        return list(cursor)

    def find_one(self, incident_id):
        return self.collection.find_one({"_id": incident_id})


def get_store():
    """Returns (store, backend_name) where backend_name is 'mongodb' or 'json_fallback'."""
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=800)
        client.admin.command("ping")  # will raise if no server available
        db = client[DB_NAME]
        return MongoStoreAdapter(db["incidents"]), "mongodb"
    except Exception:
        return JsonFallbackStore(FALLBACK_PATH), "json_fallback"


def new_id() -> str:
    return str(uuid.uuid4())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
