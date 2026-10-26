import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.modules.identity.domain.authorization.entities import (
    Permission,
    PermissionGroup,
    Role,
    RolePermission,
    UserRole,
)
from app.modules.identity.domain.authorization.enums import AssignmentStatus, RoleScope
from app.modules.identity.domain.authorization.value_objects.identity import (
    OrganizationId,
    PermissionGroupId,
    PermissionId,
    RoleId,
    UserId,
    UserRoleId,
)
from app.modules.identity.domain.authorization.value_objects.rbac import (
    PermissionCode,
    PermissionGroupCode,
    PermissionModule,
    RoleSlug,
)
from app.modules.identity.domain.entities import Organization, User
from app.modules.identity.domain.enums import OrganizationStatus, UserStatus
from app.modules.identity.infrastructure.authorization.persistence import models as authz_models  # noqa: F401
from app.modules.identity.infrastructure.authorization.repositories import (
    SqlAlchemyPermissionGroupRepository,
    SqlAlchemyPermissionRepository,
    SqlAlchemyRolePermissionRepository,
    SqlAlchemyRoleRepository,
    SqlAlchemyUserRoleRepository,
)
from app.modules.identity.infrastructure.authorization.services.sqlalchemy_permission_checker import (
    SqlAlchemyPermissionChecker,
)
from app.modules.identity.infrastructure.authorization.services.sqlalchemy_platform_user_reader import (
    SqlAlchemyPlatformUserReader,
)
from app.modules.identity.infrastructure.persistence.models import OrganizationModel, UserModel
from app.modules.identity.infrastructure.repositories import (
    SqlAlchemyOrganizationRepository,
    SqlAlchemyUserRepository,
)


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(
        engine,
        tables=[
            UserModel.__table__,
            OrganizationModel.__table__,
            authz_models.PermissionGroupModel.__table__,
            authz_models.PermissionModel.__table__,
            authz_models.RoleModel.__table__,
            authz_models.RolePermissionModel.__table__,
            authz_models.UserRoleModel.__table__,
        ],
    )
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _now() -> datetime:
    return datetime(2026, 7, 1, 12, 0, 0, tzinfo=UTC)


def _seed_user_and_org(db_session: Session) -> tuple[User, Organization]:
    user_repo = SqlAlchemyUserRepository(db_session)
    org_repo = SqlAlchemyOrganizationRepository(db_session)
    user = user_repo.create(
        User(
            id=uuid.uuid4(),
            email="member@example.com",
            password_hash="hash",
            status=UserStatus.ACTIVE,
            is_super_admin=False,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    org = org_repo.create(
        Organization(
            id=uuid.uuid4(),
            name="Acme",
            slug="acme",
            status=OrganizationStatus.ACTIVE,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    db_session.flush()
    return user, org


def test_sqlalchemy_role_repository_add_update_remove(db_session: Session) -> None:
    repo = SqlAlchemyRoleRepository(db_session)
    role = Role(
        id=RoleId(uuid.uuid4()),
        name="Member",
        slug=RoleSlug.create("member"),
        scope=RoleScope.ORGANIZATION,
        is_system=True,
        created_at=_now(),
        updated_at=_now(),
    )

    created = repo.add(role)
    db_session.commit()
    assert repo.get_by_slug(RoleSlug.create("member"), RoleScope.ORGANIZATION) is not None

    created.name = "Updated Member"
    created.updated_at = _now()
    repo.update(created)
    db_session.commit()
    assert repo.get_by_id(created.id).name == "Updated Member"

    repo.remove(created.id)
    db_session.commit()
    assert repo.get_by_id(created.id) is None


def test_sqlalchemy_permission_group_and_permission_repositories(db_session: Session) -> None:
    group_repo = SqlAlchemyPermissionGroupRepository(db_session)
    permission_repo = SqlAlchemyPermissionRepository(db_session)

    group = PermissionGroup(
        id=PermissionGroupId(uuid.uuid4()),
        code=PermissionGroupCode.create("core.users"),
        name="Users",
        module=PermissionModule.create("core"),
        description="Core user permissions",
        sort_order=1,
        is_system=True,
        created_at=_now(),
        updated_at=_now(),
    )
    created_group = group_repo.add(group)
    permission = Permission(
        id=PermissionId(uuid.uuid4()),
        group_id=created_group.id,
        code=PermissionCode.create("core.user.read"),
        description="Read users",
        is_system=True,
        created_at=_now(),
        updated_at=_now(),
    )
    created_permission = permission_repo.add(permission)
    db_session.commit()

    assert group_repo.get_by_code(PermissionGroupCode.create("core.users")) is not None
    assert permission_repo.get_by_code(PermissionCode.create("core.user.read")) == created_permission
    assert len(permission_repo.list_by_group_id(created_group.id)) == 1


def test_sqlalchemy_role_permission_repository(db_session: Session) -> None:
    role_repo = SqlAlchemyRoleRepository(db_session)
    group_repo = SqlAlchemyPermissionGroupRepository(db_session)
    permission_repo = SqlAlchemyPermissionRepository(db_session)
    role_permission_repo = SqlAlchemyRolePermissionRepository(db_session)

    role = role_repo.add(
        Role(
            id=RoleId(uuid.uuid4()),
            name="Member",
            slug=RoleSlug.create("member"),
            scope=RoleScope.ORGANIZATION,
            is_system=True,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    group = group_repo.add(
        PermissionGroup(
            id=PermissionGroupId(uuid.uuid4()),
            code=PermissionGroupCode.create("core.users"),
            name="Users",
            module=PermissionModule.create("core"),
            description="Core user permissions",
            sort_order=1,
            is_system=True,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    permission = permission_repo.add(
        Permission(
            id=PermissionId(uuid.uuid4()),
            group_id=group.id,
            code=PermissionCode.create("core.user.read"),
            description="Read users",
            is_system=True,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    role_permission_repo.grant(RolePermission(role_id=role.id, permission_id=permission.id))
    db_session.commit()

    assert role_permission_repo.has_permission(role.id, permission.id) is True
    assert PermissionId(permission.id.value) in role_permission_repo.list_permission_ids_for_role(role.id)


def test_sqlalchemy_user_role_repository(db_session: Session) -> None:
    user, org = _seed_user_and_org(db_session)
    role_repo = SqlAlchemyRoleRepository(db_session)
    user_role_repo = SqlAlchemyUserRoleRepository(db_session)

    role = role_repo.add(
        Role(
            id=RoleId(uuid.uuid4()),
            name="Member",
            slug=RoleSlug.create("member"),
            scope=RoleScope.ORGANIZATION,
            is_system=True,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    user_role = user_role_repo.add(
        UserRole(
            id=UserRoleId(uuid.uuid4()),
            user_id=UserId(user.id),
            organization_id=OrganizationId(org.id),
            role_id=role.id,
            status=AssignmentStatus.ACTIVE,
            assigned_at=_now(),
        )
    )
    db_session.commit()

    effective = user_role_repo.list_effective_by_user_and_organization(
        UserId(user.id),
        OrganizationId(org.id),
    )
    assert len(effective) == 1
    assert effective[0].id.value == user_role.id.value

    user_role_repo.revoke(user_role.id)
    db_session.commit()
    assert user_role_repo.list_effective_by_user_and_organization(
        UserId(user.id),
        OrganizationId(org.id),
    ) == []


def test_sqlalchemy_permission_checker_evaluates_user_role_graph(db_session: Session) -> None:
    user, org = _seed_user_and_org(db_session)
    role_repo = SqlAlchemyRoleRepository(db_session)
    group_repo = SqlAlchemyPermissionGroupRepository(db_session)
    permission_repo = SqlAlchemyPermissionRepository(db_session)
    role_permission_repo = SqlAlchemyRolePermissionRepository(db_session)
    user_role_repo = SqlAlchemyUserRoleRepository(db_session)
    checker = SqlAlchemyPermissionChecker(db_session)

    role = role_repo.add(
        Role(
            id=RoleId(uuid.uuid4()),
            name="Member",
            slug=RoleSlug.create("member"),
            scope=RoleScope.ORGANIZATION,
            is_system=True,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    group = group_repo.add(
        PermissionGroup(
            id=PermissionGroupId(uuid.uuid4()),
            code=PermissionGroupCode.create("core.users"),
            name="Users",
            module=PermissionModule.create("core"),
            description="Core user permissions",
            sort_order=1,
            is_system=True,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    permission = permission_repo.add(
        Permission(
            id=PermissionId(uuid.uuid4()),
            group_id=group.id,
            code=PermissionCode.create("core.user.read"),
            description="Read users",
            is_system=True,
            created_at=_now(),
            updated_at=_now(),
        )
    )
    role_permission_repo.grant(RolePermission(role_id=role.id, permission_id=permission.id))
    user_role_repo.add(
        UserRole(
            id=UserRoleId(uuid.uuid4()),
            user_id=UserId(user.id),
            organization_id=OrganizationId(org.id),
            role_id=role.id,
            status=AssignmentStatus.ACTIVE,
            assigned_at=_now(),
        )
    )
    db_session.commit()

    assert checker.has_permission(
        UserId(user.id),
        OrganizationId(org.id),
        PermissionCode.create("core.user.read"),
    ) is True
    assert checker.has_permission(
        UserId(user.id),
        OrganizationId(org.id),
        PermissionCode.create("core.user.create"),
    ) is False

    # Products (Fair Stand) rely on this: a non-active organization grants nothing.
    db_session.get(OrganizationModel, org.id).status = OrganizationStatus.SUSPENDED.value
    db_session.commit()
    assert checker.has_permission(
        UserId(user.id),
        OrganizationId(org.id),
        PermissionCode.create("core.user.read"),
    ) is False


def test_sqlalchemy_platform_user_reader_returns_snapshot(db_session: Session) -> None:
    user, _org = _seed_user_and_org(db_session)
    db_session.commit()
    reader = SqlAlchemyPlatformUserReader(db_session)

    snapshot = reader.get_snapshot(UserId(user.id))
    assert snapshot is not None
    assert snapshot.is_active is True
    assert snapshot.is_super_admin is False
    assert snapshot.can_be_authorized() is True


def test_sqlalchemy_platform_user_reader_preserves_super_admin_flag_before_account_state(
    db_session: Session,
) -> None:
    user, _org = _seed_user_and_org(db_session)
    model = db_session.get(UserModel, user.id)
    assert model is not None
    model.is_super_admin = True
    model.status = "suspended"
    model.deleted_at = _now()
    db_session.commit()

    snapshot = SqlAlchemyPlatformUserReader(db_session).get_snapshot(UserId(user.id))

    assert snapshot is not None
    assert snapshot.is_super_admin is True
    assert snapshot.is_active is False
    assert snapshot.is_deleted is True
    assert snapshot.can_be_authorized() is False
