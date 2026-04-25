from pymongo import MongoClient
from datetime import datetime
import hashlib

MONGO_URI = "mongodb+srv://mongo_admin:mongo_admin@chain.eo0luzb.mongodb.net/?appName=chain"
client = MongoClient(MONGO_URI)
db = client["evidence_db"]
evidence_versions_collection = db.evidence_versions

def get_evidence_by_hash(file_hash):
    return evidence_versions_collection.find_one({"file_hash": file_hash})

def get_latest_version(evidence_code, case_id):
    result = evidence_versions_collection.find_one(
        {"evidence_code": evidence_code, "case_id": case_id},
        sort=[("version", -1)]
    )
    return result["version"] if result else 0

def store_evidence_version(
    evidence_id,
    case_id,
    evidence_code,
    file_hash,
    file_size,
    filename,
    version,
    storage_path,
    content_hash,
    uploaded_by,
    is_duplicate=False,
    parent_version=None
):
    document = {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "evidence_code": evidence_code,
        "file_hash": file_hash,
        "content_hash": content_hash,
        "file_size": file_size,
        "filename": filename,
        "version": version,
        "storage_path": storage_path,
        "uploaded_by": uploaded_by,
        "uploaded_at": datetime.utcnow(),
        "is_duplicate": is_duplicate,
        "parent_version": parent_version,
        "status": "active"
    }
    
    result = evidence_versions_collection.insert_one(document)
    return str(result.inserted_id)

def check_file_similarity(file_hash, evidence_code, case_id, threshold=0.95):
    exact_match = evidence_versions_collection.find_one({
        "file_hash": file_hash,
        "evidence_code": evidence_code,
        "case_id": case_id
    })
    
    if exact_match:
        return True, exact_match
    return False, None

def get_version_history(evidence_code, case_id):
    versions = evidence_versions_collection.find({
        "evidence_code": evidence_code,
        "case_id": case_id
    }).sort("version", 1)
    
    return list(versions)

def get_duplicate_upload_attempts(case_id=None, limit=50):
    query = {"is_duplicate": True}
    if case_id:
        query["case_id"] = case_id
    
    attempts = evidence_versions_collection.find(query).sort("uploaded_at", -1).limit(limit)
    return list(attempts)

def mark_version_as_deleted(version_id):
    evidence_versions_collection.update_one(
        {"_id": version_id},
        {"$set": {"status": "deleted", "deleted_at": datetime.utcnow()}}
    )

def get_evidence_stats(case_id):
    pipeline = [
        {"$match": {"case_id": case_id}},
        {
            "$group": {
                "_id": "$evidence_code",
                "total_versions": {"$sum": 1},
                "total_size": {"$sum": "$file_size"},
                "duplicate_attempts": {
                    "$sum": {"$cond": ["$is_duplicate", 1, 0]}
                },
                "latest_version": {"$max": "$version"},
                "first_uploaded": {"$min": "$uploaded_at"},
                "last_uploaded": {"$max": "$uploaded_at"}
            }
        }
    ]
    
    return list(evidence_versions_collection.aggregate(pipeline))