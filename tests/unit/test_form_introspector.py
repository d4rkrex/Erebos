"""Tests for VT-Spec AUTH-03: Form introspection for adaptive auth."""

import pytest

from erebos.auth.form_introspector import (
    FormField,
    FormSpec,
    build_login_payload,
    build_registration_payload,
    find_login_form,
    find_register_form,
    parse_forms,
)


DVNA_REGISTER_HTML = """
<form id="register" name="register" action="/register" method="post">
    <div class="form-group">
        <input type="text" name="name" value="" id="register_name"
               class="form-control" placeholder="Enter full name" />
    </div>
    <div class="form-group">
        <input type="text" name="username" value="" id="register_login"
               class="form-control" placeholder="Enter username" />
    </div>
    <div class="form-group">
        <input type="text" name="email" value="" id="register_email"
               class="form-control" placeholder="Enter email address" />
    </div>
    <div class="form-group">
        <input type="password" name="password" id="register_password"
               class="form-control" placeholder="Enter password" />
    </div>
    <div class="form-group">
        <input type="password" name="cpassword" id="register_passwordConfirmation"
               class="form-control" placeholder="Confirm password" />
    </div>
    <input type="submit" value="Submit" id="register_0" class="btn btn-primary" />
</form>
"""

DVNA_LOGIN_HTML = """
<form id="login" name="login" action="/login" method="post">
    <div class="form-group">
        <input type="text" name="username" value="" id="login_login"
               class="form-control" placeholder="Enter login" />
    </div>
    <div class="form-group">
        <input type="password" name="password" id="login_password"
               class="form-control" placeholder="Enter password" />
    </div>
    <input type="submit" value="Submit" id="login_0" class="btn btn-primary" />
</form>
"""

JUICE_SHOP_LOGIN_HTML = """
<form>
    <input type="email" name="email" placeholder="Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <input type="hidden" name="_csrf" value="abc123" />
    <button type="submit">Login</button>
</form>
"""


class TestParseFormsBasic:
    """Test basic HTML form parsing."""

    def test_parse_dvna_register(self):
        forms = parse_forms(DVNA_REGISTER_HTML)
        assert len(forms) == 1
        form = forms[0]
        assert form.action == "/register"
        assert form.method == "POST"
        assert len(form.field_names) == 5  # name, username, email, password, cpassword

    def test_parse_dvna_login(self):
        forms = parse_forms(DVNA_LOGIN_HTML)
        assert len(forms) == 1
        form = forms[0]
        assert form.action == "/login"
        assert "username" in form.field_names
        assert "password" in form.field_names

    def test_parse_hidden_fields(self):
        forms = parse_forms(JUICE_SHOP_LOGIN_HTML)
        assert len(forms) == 1
        assert forms[0].hidden_fields == {"_csrf": "abc123"}


class TestFormClassification:
    """Test form type detection and field classification."""

    def test_dvna_register_is_register_form(self):
        form = find_register_form(DVNA_REGISTER_HTML)
        assert form is not None
        assert form.is_register_form()
        assert not form.is_login_form()

    def test_dvna_login_is_login_form(self):
        form = find_login_form(DVNA_LOGIN_HTML)
        assert form is not None
        assert form.is_login_form()
        assert not form.is_register_form()

    def test_classify_dvna_register_fields(self):
        form = find_register_form(DVNA_REGISTER_HTML)
        field_map = form.classify_fields()
        assert field_map["username"] == "username"
        assert field_map["email"] == "email"
        assert field_map["name"] == "name"
        assert field_map["password"] == "password"
        assert field_map["password_confirm"] == "cpassword"

    def test_classify_dvna_login_fields(self):
        form = find_login_form(DVNA_LOGIN_HTML)
        field_map = form.classify_fields()
        assert field_map["username"] == "username"
        assert field_map["password"] == "password"

    def test_classify_email_based_login(self):
        form = find_login_form(JUICE_SHOP_LOGIN_HTML)
        assert form is not None
        field_map = form.classify_fields()
        assert field_map["email"] == "email"
        assert field_map["password"] == "password"


class TestPayloadBuilding:
    """Test adaptive payload construction."""

    def test_build_dvna_registration_payload(self):
        form = find_register_form(DVNA_REGISTER_HTML)
        payload = build_registration_payload(
            form=form,
            username="testuser",
            password="TestPass123!",
            email="test@test.local",
            name="Test User",
        )
        assert payload["username"] == "testuser"
        assert payload["email"] == "test@test.local"
        assert payload["name"] == "Test User"
        assert payload["password"] == "TestPass123!"
        assert payload["cpassword"] == "TestPass123!"  # confirm = same as password

    def test_build_dvna_login_payload(self):
        form = find_login_form(DVNA_LOGIN_HTML)
        payload = build_login_payload(
            form=form,
            username="testuser",
            password="TestPass123!",
        )
        assert payload["username"] == "testuser"
        assert payload["password"] == "TestPass123!"

    def test_build_login_with_csrf(self):
        form = find_login_form(JUICE_SHOP_LOGIN_HTML)
        payload = build_login_payload(
            form=form,
            username="test@test.local",
            password="pass123",
        )
        # Should include CSRF hidden field
        assert payload["_csrf"] == "abc123"
        assert payload["email"] == "test@test.local"
        assert payload["password"] == "pass123"

    def test_build_registration_preserves_hidden_fields(self):
        html = """
        <form action="/register" method="post">
            <input type="hidden" name="_token" value="xyz789" />
            <input type="text" name="login" placeholder="Username" />
            <input type="email" name="email" placeholder="Email" />
            <input type="password" name="pass" placeholder="Password" />
            <input type="password" name="pass_confirm" placeholder="Confirm" />
        </form>
        """
        form = find_register_form(html)
        assert form is not None
        payload = build_registration_payload(
            form=form,
            username="myuser",
            password="mypass",
            email="me@test.com",
        )
        assert payload["_token"] == "xyz789"
        assert payload["login"] == "myuser"
        assert payload["email"] == "me@test.com"


class TestEdgeCases:
    """Test edge cases and unusual form structures."""

    def test_no_forms_returns_empty(self):
        assert parse_forms("<html><body>No forms here</body></html>") == []

    def test_no_login_form_returns_none(self):
        assert find_login_form("<html><body>No forms</body></html>") is None

    def test_no_register_form_returns_none(self):
        assert find_register_form("<html><body>No forms</body></html>") is None

    def test_form_with_no_password_not_login(self):
        html = """
        <form action="/search">
            <input type="text" name="q" placeholder="Search..." />
            <input type="submit" value="Go" />
        </form>
        """
        assert find_login_form(html) is None

    def test_multiple_forms_picks_correct_one(self):
        html = """
        <form action="/search">
            <input type="text" name="q" />
        </form>
        <form action="/login" method="post">
            <input type="text" name="user" placeholder="Username" />
            <input type="password" name="pass" />
            <input type="submit" />
        </form>
        """
        form = find_login_form(html)
        assert form is not None
        assert form.action == "/login"
