from sqlalchemy.orm import Session
from app.db.models import AccessRequestModel, IncidentModel, AuditEventModel

class Repository:
    def __init__(self, session: Session):
        self.session = session

    def save_request(self, request_id: str, wallet: str, resource_id: str, action: str):
        record = AccessRequestModel(
            request_id=request_id,
            wallet=wallet,
            resource_id=resource_id,
            action=action
        )
        self.session.add(record)
        self.session.commit()

    def record_audit(self, actor: str, event_type: str, object_id: str, payload_hash: str):
        event = AuditEventModel(
            actor=actor,
            event_type=event_type,
            object_id=object_id,
            payload_hash=payload_hash
        )
        self.session.add(event)
        self.session.commit()