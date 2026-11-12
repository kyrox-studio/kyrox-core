from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class AuthorizationContext:
    user_id: UUID
    organization_id: UUID
    email: str
    is_super_admin: bool = False
    # Session of the access token; audit rows carry it when known (F-C13).
    session_id: UUID | None = None


@dataclass(frozen=True)
class AuthenticatedOrganizationContext:
    user_id: UUID
    organization_id: UUID
    email: str
    session_id: UUID
    is_super_admin: bool = False
