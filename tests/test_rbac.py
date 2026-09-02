"""tests/test_rbac.py — Role and permission enforcement tests."""


def _create_role_and_permission(client, admin_headers, role_name="editor", perm_code="posts:write"):
    role_resp = client.post("/roles", json={"name": role_name}, headers=admin_headers)
    perm_resp = client.post("/roles/permissions", json={"code": perm_code}, headers=admin_headers)
    return role_resp.json()["data"]["id"], perm_resp.json()["data"]["id"]


def test_create_role(client, admin_headers):
    resp = client.post("/roles", json={"name": "moderator", "description": "Can moderate content"}, headers=admin_headers)
    assert resp.status_code == 201
    assert resp.json()["data"]["name"] == "moderator"


def test_create_role_non_admin_forbidden(client, auth_headers):
    resp = client.post("/roles", json={"name": "hacker"}, headers=auth_headers)
    assert resp.status_code == 403


def test_create_duplicate_role(client, admin_headers):
    client.post("/roles", json={"name": "editor"}, headers=admin_headers)
    resp = client.post("/roles", json={"name": "editor"}, headers=admin_headers)
    assert resp.status_code == 409


def test_create_permission(client, admin_headers):
    resp = client.post("/roles/permissions", json={"code": "reports:read"}, headers=admin_headers)
    assert resp.status_code == 201
    assert resp.json()["data"]["code"] == "reports:read"


def test_assign_permission_to_role(client, admin_headers):
    role_id, perm_id = _create_role_and_permission(client, admin_headers)
    resp = client.post(f"/roles/{role_id}/permissions", json={"permission_id": perm_id}, headers=admin_headers)
    assert resp.status_code == 200
    codes = [p["code"] for p in resp.json()["data"]["permissions"]]
    assert "posts:write" in codes


def test_remove_permission_from_role(client, admin_headers):
    role_id, perm_id = _create_role_and_permission(client, admin_headers)
    client.post(f"/roles/{role_id}/permissions", json={"permission_id": perm_id}, headers=admin_headers)
    resp = client.delete(f"/roles/{role_id}/permissions/{perm_id}", headers=admin_headers)
    assert resp.status_code == 200
    codes = [p["code"] for p in resp.json()["data"]["permissions"]]
    assert "posts:write" not in codes


def test_assign_role_to_user(client, admin_headers, verified_user, db):
    from app.models.user import User
    user = db.query(User).filter(User.email == verified_user["email"]).first()
    role_resp = client.post("/roles", json={"name": "writer"}, headers=admin_headers)
    role_id = role_resp.json()["data"]["id"]

    resp = client.post(f"/roles/users/{user.id}/roles", json={"role_id": role_id}, headers=admin_headers)
    assert resp.status_code == 200

    db.refresh(user)
    assert any(r.name == "writer" for r in user.roles)


def test_require_permission_blocks_unauthorized(client, auth_headers):
    """A user without required permission should be denied."""
    # /roles is admin-only — regular user should get 403
    resp = client.post("/roles", json={"name": "test"}, headers=auth_headers)
    assert resp.status_code == 403


def test_superuser_bypasses_permission_check(client, admin_headers):
    """Superusers bypass all role/permission checks."""
    resp = client.get("/roles", headers=admin_headers)
    assert resp.status_code == 200


def test_list_users_admin_only(client, auth_headers, admin_headers):
    # Regular user denied
    resp = client.get("/users", headers=auth_headers)
    assert resp.status_code == 403
    # Admin allowed
    resp = client.get("/users", headers=admin_headers)
    assert resp.status_code == 200
