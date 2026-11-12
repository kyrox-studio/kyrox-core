"""Authorization context types; defined in the application layer so services can use them
(BACKEND_ARCHITECTURE_STANDARDS §4.2). Re-exported here for API dependencies."""

from app.modules.identity.application.authorization.context import (
    AuthenticatedOrganizationContext,
    AuthorizationContext,
)

__all__ = ["AuthenticatedOrganizationContext", "AuthorizationContext"]
