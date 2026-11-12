"""Small user lookups for audit adapters wired in the API composition root."""

from uuid import UUID

from sqlalchemy.orm import Session

from app.modules.identity.infrastructure.persistence.models import UserModel


def user_organization_id(db: Session, user_id: UUID) -> UUID | None:
    user = db.get(UserModel, user_id)
    return None if user is None else user.organization_id
