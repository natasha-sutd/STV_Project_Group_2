"""
Simple test to verify both Firestore databases are connected and working.
Pushes a test document to both archive and current databases.
"""

import sys
from pathlib import Path
from datetime import datetime

# Add forza to path
sys.path.insert(0, str(Path(__file__).parent / "forza"))

def test_firestore_connection():
    """Test connection to both Firestore databases."""
    print("=" * 60)
    print("FIRESTORE CONNECTION TEST")
    print("=" * 60)

    # Import firestore_client
    try:
        from engine import firestore_client
        print("\n[OK] firestore_client imported")
    except Exception as e:
        print(f"\n[FAIL] Could not import firestore_client: {e}")
        return False

    # Get both databases
    print("\n" + "-" * 60)
    print("Initializing databases...")
    print("-" * 60)

    archive_db = firestore_client.get_archive_db()
    current_db = firestore_client.get_current_db()

    # Check if databases are available
    if archive_db is None:
        print("[INFO] Archive database not available (no credentials)")
    else:
        print("[OK] Archive database initialized")

    if current_db is None:
        print("[INFO] Current database not available (no credentials)")
    else:
        print("[OK] Current database initialized")

    if archive_db is None and current_db is None:
        print("\n[FAIL] Neither database is available. Please add credential files.")
        print("  - firebase-credentials.json (for archive database)")
        print("  - firebase-credentials-current.json (for current database)")
        return False

    # Create test message
    test_message = {
        "message": "Test connection successful",
        "timestamp": datetime.now().isoformat(),
        "source": "test_firestore_connection.py",
        "test_id": "connection_test_001"
    }

    print("\n" + "-" * 60)
    print("Pushing test document to 'test' collection...")
    print("-" * 60)
    print(f"Test data: {test_message}")

    success_count = 0

    # Test archive database
    if archive_db is not None:
        try:
            doc_ref = archive_db.collection("test").add(test_message)
            doc_id = doc_ref[1].id
            print(f"\n[OK] Archive database - Document added with ID: {doc_id}")
            success_count += 1
        except Exception as e:
            print(f"\n[FAIL] Archive database error: {e}")

    # Test current database
    if current_db is not None:
        try:
            doc_ref = current_db.collection("test").add(test_message)
            doc_id = doc_ref[1].id
            print(f"[OK] Current database - Document added with ID: {doc_id}")
            success_count += 1
        except Exception as e:
            print(f"[FAIL] Current database error: {e}")

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    if success_count == 2:
        print("[SUCCESS] Both databases connected and working!")
        print("  - Archive database: OK")
        print("  - Current database: OK")
    elif success_count == 1:
        print("[PARTIAL] One database connected successfully")
        if archive_db is not None:
            print("  - Archive database: OK")
        if current_db is not None:
            print("  - Current database: OK")
    else:
        print("[FAIL] No databases could be connected")

    print("\nNext steps:")
    print("  - Check your Firebase Console to see the test documents")
    print("  - Collection: 'test'")
    print("  - The test documents should appear in both databases")
    print("=" * 60)

    return success_count > 0


if __name__ == "__main__":
    success = test_firestore_connection()
    sys.exit(0 if success else 1)
