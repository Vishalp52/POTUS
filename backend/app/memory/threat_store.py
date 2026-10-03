from typing import List, Dict, Any, Tuple
from app.memory.similarity import cosine_similarity

class ThreatStore:
    def __init__(self):
        self._stored_incidents: List[Dict[str, Any]] = []

    def insert_incident(self, incident_id: str, vector: list[float], category: str, disposition: str, evidence_hash: str):
        if disposition not in {"CONFIRMED_INCIDENT", "SIMULATED_ATTACK"}:
            return
        self._stored_incidents.append({
            "incident_id": incident_id,
            "vector": vector,
            "category": category,
            "disposition": disposition,
            "evidence_hash": evidence_hash
        })

    def find_max_similarity(self, target_vector: list[float]) -> Tuple[float, str]:
        if not self._stored_incidents:
            return 0.0, ""
        
        max_sim = 0.0
        matched_id = ""
        for inc in self._stored_incidents:
            sim = cosine_similarity(target_vector, inc["vector"])
            if sim > max_sim:
                max_sim = sim
                matched_id = inc["incident_id"]
        return max_sim, matched_id