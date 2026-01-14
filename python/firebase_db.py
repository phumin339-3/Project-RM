import os
import firebase_admin
from firebase_admin import credentials, firestore

_app = None
_db = None

def init_firebase():
    global _app, _db
    if _app:
        return _db

    base_dir = os.path.dirname(os.path.abspath(__file__))
    key_path = os.path.join(base_dir, "serviceAccountKey.json")

    cred = credentials.Certificate(key_path)
    _app = firebase_admin.initialize_app(cred)
    _db = firestore.client()
    return _db

def save_history(uid: str, record: dict):
    db = init_firebase()
    # เก็บเป็น: users/{uid}/history/{autoId}
    db.collection("users").document(uid).collection("history").add(record)

def get_history(uid: str, limit: int = 50):
    db = init_firebase()
    q = (db.collection("users")
            .document(uid)
            .collection("history")
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(limit))
    return [doc.to_dict() for doc in q.stream()]
