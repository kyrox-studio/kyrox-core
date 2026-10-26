class AuthenticationError(Exception):
    """Base class for authentication failures."""


class InvalidCredentialsError(AuthenticationError):
    """Email or password is invalid."""


class InactiveUserError(AuthenticationError):
    """User account is not active."""


class LockedUserError(AuthenticationError):
    """User account is locked."""


class LoginThrottledError(AuthenticationError):
    """Too many failed sign-in attempts for this account/client (temporary)."""


class InvalidRefreshTokenError(AuthenticationError):
    """Refresh token is missing, malformed, or otherwise invalid."""


class ExpiredRefreshTokenError(InvalidRefreshTokenError):
    """Refresh token has expired."""


class RevokedRefreshTokenError(InvalidRefreshTokenError):
    """Refresh token has been revoked."""


class PublicSignupValidationError(AuthenticationError):
    """Public signup request failed Core domain validation."""


class PublicSignupConflictError(AuthenticationError):
    """Public signup conflicts with an existing account or organization."""


class PublicSignupProvisioningError(AuthenticationError):
    """Public signup could not be provisioned atomically."""


class InvalidActivationTokenError(AuthenticationError):
    """Activation token is invalid, unavailable, expired, replayed, or inconsistent."""


class ActivationPasswordPolicyError(AuthenticationError):
    """Activation password does not satisfy the shared Core password policy."""


class InvalidPasswordResetTokenError(AuthenticationError):
    """Password-reset token is invalid, unavailable, expired, replayed, or inconsistent."""


class PasswordResetPolicyError(AuthenticationError):
    """Reset password does not satisfy the shared Core password policy."""


class InvalidCurrentPasswordError(AuthenticationError):
    """Authenticated password change supplied the wrong current password."""


class PasswordChangePolicyError(AuthenticationError):
    """New password does not satisfy the shared Core password policy."""


class SamePasswordError(AuthenticationError):
    """New password is the same as the current password."""


class PasswordChangeUnavailableError(AuthenticationError):
    """Target account is not eligible for authenticated password change."""
