import csv
import os
from forza.engine import firestore_client

# Add the project root to the Python path to allow imports from the 'forza' package
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def export_collection_to_csv(db, collection_name, output_file):
   
    if not db:
        print(f"Firestore database not available. Cannot export '{collection_name}'.")
        return

    print(f"Exporting '{collection_name}' collection to '{output_file}'...")
    collection_ref = db.collection(collection_name)
    docs = collection_ref.stream()

    all_field_names = set()
    all_docs_data = []
    for doc in docs:
        doc_data = doc.to_dict()
        all_docs_data.append(doc_data)
        all_field_names.update(doc_data.keys())

    if not all_docs_data:
        print(f"Collection '{collection_name}' is empty. No data to export.")
        return

    sorted_field_names = sorted(list(all_field_names))

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=sorted_field_names)
        writer.writeheader()
        for doc_data in all_docs_data:
            writer.writerow(doc_data)

    print(f"Successfully exported {len(all_docs_data)} documents to '{output_file}'.")

def main():
    """
    Main function to initialize Firestore and export all collections.
    """
    print("Initializing connection to archive Firestore database...")
    archive_db = firestore_client.get_archive_db()

    if not archive_db:
        print("Failed to initialize archive Firestore database.")
        print("Please ensure 'firebase-credentials.json' is present and valid.")
        return

    print("Database connection successful.")

    # Define collections to export
    collections_to_export = ["bugs", "stats", "crashes", "coverage"]

    # Create an 'exports' directory if it doesn't exist
    output_dir = "firestore_exports"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for collection in collections_to_export:
        output_file = os.path.join(output_dir, f"{collection}.csv")
        export_collection_to_csv(archive_db, collection, output_file)

if __name__ == "__main__":
    main()
