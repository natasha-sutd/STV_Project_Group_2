'''
Firestore client module for uploading fuzzing results to Firebase Firestore.
'''
# Suppress gRPC debug logs
import os
os.environ["GRPC_VERBOSITY"] = "ERROR"
os.environ["GRPC_TRACE"] = ""

from pathlib import Path
from typing import Optional, Tuple

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    firebase_admin = None
    credentials = None
    firestore = None

from engine.types import BugResult

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_ARCHIVE_CREDS_PATH = _PROJECT_ROOT / "firebase-credentials.json"
_CURRENT_CREDS_PATH = _PROJECT_ROOT / "firebase-credentials-current.json"

# Singleton Firestore clients
_archive_db = None
_current_db = None
_archive_initialized = False
_current_initialized = False
_current_run_id = None


def _init_firebase_archive() -> bool:
    """
    Initialize Archive Firebase app with service account credentials.
    Returns True if successful, False otherwise.
    """
    global _archive_db, _archive_initialized

    if _archive_initialized:
        return _archive_db is not None

    _archive_initialized = True

    if not FIREBASE_AVAILABLE:
        print(
            "[firestore-archive] firebase-admin not installed. Run: pip install firebase-admin")
        return False

    if not _ARCHIVE_CREDS_PATH.exists():
        print(
            f"[firestore-archive] Credentials not found at {_ARCHIVE_CREDS_PATH}")
        print(
            "[firestore-archive] Archive uploads disabled - results saved locally only")
        return False

    try:
        cred = credentials.Certificate(str(_ARCHIVE_CREDS_PATH))
        app = firebase_admin.initialize_app(cred, name='archive')
        _archive_db = firestore.client(app)
        print("[firestore-archive] Connected to Archive Firestore successfully")
        return True
    except Exception as e:
        print(f"[firestore-archive] Failed to initialize: {e}")
        return False


def _init_firebase_current() -> bool:
    """
    Initialize Current Firebase app with service account credentials.
    Returns True if successful, False otherwise.
    """
    global _current_db, _current_initialized

    if _current_initialized:
        return _current_db is not None

    _current_initialized = True

    if not FIREBASE_AVAILABLE:
        print(
            "[firestore-current] firebase-admin not installed. Run: pip install firebase-admin")
        return False

    if not _CURRENT_CREDS_PATH.exists():
        print(
            f"[firestore-current] Credentials not found at {_CURRENT_CREDS_PATH}")
        print(
            "[firestore-current] Current uploads disabled - results saved locally only")
        return False

    try:
        cred = credentials.Certificate(str(_CURRENT_CREDS_PATH))
        app = firebase_admin.initialize_app(cred, name='current')
        _current_db = firestore.client(app)
        print("[firestore-current] Connected to Current Firestore successfully")
        return True
    except Exception as e:
        print(f"[firestore-current] Failed to initialize: {e}")
        return False


def get_db():
    """Get Archive Firestore client (backwards compatibility), initializing if needed."""
    if not _archive_initialized:
        _init_firebase_archive()
    return _archive_db


def get_archive_db():
    """Get Archive Firestore client, initializing if needed."""
    if not _archive_initialized:
        _init_firebase_archive()
    return _archive_db


def get_current_db():
    """Get Current Firestore client, initializing if needed."""
    if not _current_initialized:
        _init_firebase_current()
    return _current_db


def get_both_dbs() -> Tuple[Optional[object], Optional[object]]:
    """
    Get both Archive and Current Firestore clients.
    Returns (archive_db, current_db) tuple.
    """
    return get_archive_db(), get_current_db()


def clear_current_db(run_id: str) -> bool:
    """
    Clear all collections in the Current database before starting a new run.
    This ensures only the latest run data is stored.

    Args:
        run_id: The new run ID that will be stored

    Returns:
        True if successful, False otherwise
    """
    global _current_run_id

    db = get_current_db()
    if db is None:
        return False

    try:
        collections = ['bugs', 'stats', 'crashes', 'coverage']

        for collection_name in collections:
            collection_ref = db.collection(collection_name)
            docs = collection_ref.stream()

            deleted_count = 0
            for doc in docs:
                doc.reference.delete()
                deleted_count += 1

            if deleted_count > 0:
                print(
                    f"[firestore-current] Cleared {deleted_count} documents from '{collection_name}' collection")

        _current_run_id = run_id
        print(f"[firestore-current] Database cleared for new run: {run_id}")
        return True

    except Exception as e:
        print(f"[firestore-current] Failed to clear database: {e}")
        return False


def upload_bug(result: BugResult, run_id: str = "", is_representative: bool = False) -> Optional[str]:
    """
    Upload a bug result to both Archive and Current Firestore databases.

    Collection: 'bugs'
    Document fields match BugResult dataclass.

    Returns the document ID from archive if successful, None otherwise.
    """
    archive_db, current_db = get_both_dbs()

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
        "is_representative": is_representative,
        "timestamp": firestore.SERVER_TIMESTAMP if FIREBASE_AVAILABLE else None,
    }

    doc_id = None

    # Upload to archive database
    if archive_db is not None:
        try:
            doc_ref = archive_db.collection("bugs").add(doc_data)
            doc_id = doc_ref[1].id
        except Exception as e:
            print(f"[firestore-archive] Failed to upload bug: {e}")

    # Upload to current database
    if current_db is not None:
        try:
            current_db.collection("bugs").add(doc_data)
        except Exception as e:
            print(f"[firestore-current] Failed to upload bug: {e}")

    return doc_id


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
    Upload fuzzing statistics snapshot to both Archive and Current Firestore databases.

    Collection: 'stats'
    """
    archive_db, current_db = get_both_dbs()

    doc_data = {
        "target": target,
        "run_id": run_id,
        "iteration": iteration,
        "unique_bugs": unique_bugs,
        "corpus_size": corpus_size,
        "elapsed_s": elapsed_s,
        "runs_per_sec": runs_per_sec,
        "timestamp": firestore.SERVER_TIMESTAMP if FIREBASE_AVAILABLE else None,
    }

    doc_id = None

    # Upload to archive database
    if archive_db is not None:
        try:
            doc_ref = archive_db.collection("stats").add(doc_data)
            doc_id = doc_ref[1].id
        except Exception as e:
            print(f"[firestore-archive] Failed to upload stats: {e}")

    # Upload to current database
    if current_db is not None:
        try:
            current_db.collection("stats").add(doc_data)
        except Exception as e:
            print(f"[firestore-current] Failed to upload stats: {e}")

    return doc_id


def upload_crash(
    target: str,
    bug_key: str,
    input_data: str,
    error_type: str,
) -> Optional[str]:
    """
    Upload crash/timeout data to both Archive and Current 'crashes' collection.
    """
    archive_db, current_db = get_both_dbs()

    doc_data = {
        "target": target,
        "bug_key": bug_key,
        "input_data": input_data[:2000],
        "error_type": error_type,
        "timestamp": firestore.SERVER_TIMESTAMP if FIREBASE_AVAILABLE else None,
    }

    doc_id = None

    # Upload to archive database
    if archive_db is not None:
        try:
            doc_ref = archive_db.collection("crashes").add(doc_data)
            doc_id = doc_ref[1].id
        except Exception as e:
            print(f"[firestore-archive] Failed to upload crash: {e}")

    # Upload to current database
    if current_db is not None:
        try:
            current_db.collection("crashes").add(doc_data)
        except Exception as e:
            print(f"[firestore-current] Failed to upload crash: {e}")

    return doc_id


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
    Upload one coverage snapshot to both Archive and Current Firestore databases.

    Collection: 'coverage'
    """
    archive_db, current_db = get_both_dbs()

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
        "timestamp": firestore.SERVER_TIMESTAMP if FIREBASE_AVAILABLE else None,
    }

    doc_id = None

    # Upload to archive database
    if archive_db is not None:
        try:
            doc_ref = archive_db.collection("coverage").add(doc_data)
            doc_id = doc_ref[1].id
        except Exception as e:
            print(f"[firestore-archive] Failed to upload coverage: {e}")

    # Upload to current database
    if current_db is not None:
        try:
            current_db.collection("coverage").add(doc_data)
        except Exception as e:
            print(f"[firestore-current] Failed to upload coverage: {e}")

    return doc_id