import os
import time
from pathlib import Path
from typing import Optional

# Firebase imports - will be None if not installed
try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    firebase_admin = None
    credentials = None
    firestore = None

from engine.types import BugResult, BugType

# Path to credentials file (relative to project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_CREDS_PATH = _PROJECT_ROOT / "firebase-credentials.json"

# Firestore client singleton
_db = None
_initialized = False


def _init_firebase() -> bool:
    """
    Initialize Firebase app with service account credentials.
    Returns True if successful, False otherwise.
    """
    global _db, _initialized

    if _initialized:
        return _db is not None

    _initialized = True

    if not FIREBASE_AVAILABLE:
        print("[firestore] firebase-admin not installed. Run: pip install firebase-admin")
        return False

    if not _CREDS_PATH.exists():
        print(f"[firestore] Credentials not found at {_CREDS_PATH}")
        print("[firestore] Firestore uploads disabled - results saved locally only")
        return False

    try:
        cred = credentials.Certificate(str(_CREDS_PATH))
        firebase_admin.initialize_app(cred)
        _db = firestore.client()
        print("[firestore] Connected to Firestore successfully")
        return True
    except Exception as e:
        print(f"[firestore] Failed to initialize: {e}")
        return False


def get_db():
    """Get Firestore client, initializing if needed."""
    if not _initialized:
        _init_firebase()
    return _db


def upload_bug(result: BugResult, run_id: str = "") -> Optional[str]:
    """
    Upload a bug result to Firestore.

    Collection: 'bugs'
    Document fields match BugResult dataclass.

    Returns the document ID if successful, None otherwise.
    """
    db = get_db()
    if db is None:
        return None

    try:
        doc_data = {
            "target": result.target,
            "bug_type": result.bug_type.name,
            "bug_key": result.bug_key,
            "input_data": result.input_data[:1000],  # Limit size
            "stdout": result.stdout[:500],
            "stderr": result.stderr[:500],
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "crashed": result.crashed,
            "strategy": result.strategy,
            "new_coverage": result.new_coverage,
            "exec_time_ms": result.exec_time_ms,
            "run_id": run_id,
            "timestamp": firestore.SERVER_TIMESTAMP,
        }

        doc_ref = db.collection("bugs").add(doc_data)
        return doc_ref[1].id
    except Exception as e:
        print(f"[firestore] Failed to upload bug: {e}")
        return None


def upload_stats(
    target: str,
    run_id: str,
    iteration: int,
    unique_bugs: int,
    corpus_size: int,
    elapsed_s: float,
    runs_per_sec: float,
) -> Optional[str]:
    """
    Upload fuzzing statistics snapshot to Firestore.

    Collection: 'stats'
    """
    db = get_db()
    if db is None:
        return None

    try:
        doc_data = {
            "target": target,
            "run_id": run_id,
            "iteration": iteration,
            "unique_bugs": unique_bugs,
            "corpus_size": corpus_size,
            "elapsed_s": elapsed_s,
            "runs_per_sec": runs_per_sec,
            "timestamp": firestore.SERVER_TIMESTAMP,
        }

        doc_ref = db.collection("stats").add(doc_data)
        return doc_ref[1].id
    except Exception as e:
        print(f"[firestore] Failed to upload stats: {e}")
        return None


def upload_crash(
    target: str,
    bug_key: str,
    input_data: str,
    error_type: str,
) -> Optional[str]:
    """
    Upload crash/timeout data to a dedicated 'crashes' collection.
    """
    db = get_db()
    if db is None:
        return None

    try:
        doc_data = {
            "target": target,
            "bug_key": bug_key,
            "input_data": input_data[:2000],
            "error_type": error_type,
            "timestamp": firestore.SERVER_TIMESTAMP,
        }

        doc_ref = db.collection("crashes").add(doc_data)
        return doc_ref[1].id
    except Exception as e:
        print(f"[firestore] Failed to upload crash: {e}")
        return None


def upload_coverage(
    target: str,
    run_id: str,
    iteration: int,
    total_inputs: int,
    tracking_mode: str,
    statement_coverage: float,
    branch_coverage: float,
    function_coverage: float,
    new_path_found: bool,
    behavioral_metric: float = 0.0,
    execution_metric: float = 0.0,
    coverage_source: str = "proxy",
) -> Optional[str]:
    """
    Upload one coverage snapshot to Firestore.

    Collection: 'coverage'
    """
    db = get_db()
    if db is None:
        return None

    try:
        doc_data = {
            "target": target,
            "run_id": run_id,
            "iteration": iteration,
            "total_inputs": total_inputs,
            "tracking_mode": tracking_mode,
            "statement_coverage": float(statement_coverage),
            "branch_coverage": float(branch_coverage),
            "function_coverage": float(function_coverage),
            "behavioral_metric": float(behavioral_metric),
            "execution_metric": float(execution_metric),
            "coverage_source": str(coverage_source),
            "new_path_found": bool(new_path_found),
            "timestamp": firestore.SERVER_TIMESTAMP,
        }

        doc_ref = db.collection("coverage").add(doc_data)
        return doc_ref[1].id
    except Exception as e:
        print(f"[firestore] Failed to upload coverage: {e}")
        return None
