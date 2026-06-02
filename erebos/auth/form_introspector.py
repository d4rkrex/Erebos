"""Adaptive form introspection for authentication flows.

VT-Spec AUTH-03: Parse real HTML forms to discover field names, types,
and required values. Enables auto-registration and login against any
web application without hardcoded assumptions.

The LLM decision gap this solves:
- System detects /login and /register exist
- But doesn't know what fields they expect (username vs email vs login)
- Without form introspection, auth attempts fail silently
- With it, the system adapts to any app's auth convention
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """A single form input field."""

    name: str
    field_type: str = "text"  # text, password, email, hidden, submit
    value: str = ""  # Pre-filled value (for hidden fields)
    placeholder: str = ""
    required: bool = False
    id: str = ""


@dataclass
class FormSpec:
    """Parsed specification of an HTML form."""

    action: str = ""
    method: str = "POST"
    fields: List[FormField] = field(default_factory=list)
    encoding: str = "application/x-www-form-urlencoded"

    @property
    def field_names(self) -> List[str]:
        """All field names (excluding submit buttons)."""
        return [f.name for f in self.fields if f.field_type != "submit" and f.name]

    @property
    def password_fields(self) -> List[FormField]:
        """Password-type fields."""
        return [f for f in self.fields if f.field_type == "password"]

    @property
    def text_fields(self) -> List[FormField]:
        """Non-password, non-hidden, non-submit fields."""
        return [f for f in self.fields if f.field_type in ("text", "email", "tel") and f.name]

    @property
    def hidden_fields(self) -> Dict[str, str]:
        """Hidden fields with their pre-filled values (CSRF tokens, etc.)."""
        return {f.name: f.value for f in self.fields if f.field_type == "hidden" and f.name}

    def is_login_form(self) -> bool:
        """Heuristic: login forms have 1 password field and 1-2 text fields."""
        return len(self.password_fields) == 1 and 1 <= len(self.text_fields) <= 2

    def is_register_form(self) -> bool:
        """Heuristic: register forms have 2+ password fields (password + confirm)."""
        return len(self.password_fields) >= 2 and len(self.text_fields) >= 1

    def classify_fields(self) -> Dict[str, str]:
        """Map semantic roles to actual field names.

        Returns dict like:
            {"username": "login", "password": "password", "email": "email", ...}
        """
        mapping: Dict[str, str] = {}

        for f in self.fields:
            name_lower = f.name.lower()
            placeholder_lower = f.placeholder.lower()
            id_lower = f.id.lower()
            combined = f"{name_lower} {placeholder_lower} {id_lower}"

            if f.field_type == "password":
                if any(kw in combined for kw in ("confirm", "repeat", "cpassword", "re_")):
                    mapping["password_confirm"] = f.name
                elif "password" not in mapping:
                    mapping["password"] = f.name

            elif f.field_type in ("text", "email"):
                if any(kw in combined for kw in ("email", "e-mail", "correo")):
                    mapping["email"] = f.name
                elif any(kw in combined for kw in ("user", "login", "username", "usuario", "nick")):
                    mapping["username"] = f.name
                elif any(kw in combined for kw in ("name", "nombre", "full")):
                    if "name" not in mapping:
                        mapping["name"] = f.name
                elif "username" not in mapping:
                    # Default first text field to username if no better match
                    mapping["username"] = f.name

            elif f.field_type == "hidden":
                mapping[f"hidden_{f.name}"] = f.name

        return mapping


class _FormHTMLParser(HTMLParser):
    """Stdlib HTML parser that extracts form specifications."""

    def __init__(self, target_action: Optional[str] = None):
        super().__init__()
        self._target_action = target_action
        self._in_form = False
        self._current_form: Optional[FormSpec] = None
        self.forms: List[FormSpec] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_dict = {k: (v or "") for k, v in attrs}

        if tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "POST").upper()
            enctype = attr_dict.get("enctype", "application/x-www-form-urlencoded")
            self._current_form = FormSpec(action=action, method=method, encoding=enctype)
            self._in_form = True

        elif tag == "input" and self._in_form and self._current_form:
            name = attr_dict.get("name", "")
            field_type = attr_dict.get("type", "text").lower()
            value = attr_dict.get("value", "")
            placeholder = attr_dict.get("placeholder", "")
            required = "required" in attr_dict
            field_id = attr_dict.get("id", "")

            if name:  # Only track named inputs
                self._current_form.fields.append(
                    FormField(
                        name=name,
                        field_type=field_type,
                        value=value,
                        placeholder=placeholder,
                        required=required,
                        id=field_id,
                    )
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None
            self._in_form = False


def parse_forms(html: str, target_action: Optional[str] = None) -> List[FormSpec]:
    """Parse all forms from an HTML page.

    Args:
        html: Raw HTML content
        target_action: If set, only return forms whose action matches

    Returns:
        List of FormSpec objects
    """
    parser = _FormHTMLParser(target_action=target_action)
    parser.feed(html)

    if target_action:
        return [f for f in parser.forms if target_action in f.action or f.action == target_action]
    return parser.forms


def find_login_form(html: str) -> Optional[FormSpec]:
    """Find the most likely login form in an HTML page."""
    forms = parse_forms(html)

    # Prefer forms with action containing "login"
    for form in forms:
        if "login" in form.action.lower() and form.is_login_form():
            return form

    # Fallback: any form that looks like a login form
    for form in forms:
        if form.is_login_form():
            return form

    return None


def find_register_form(html: str) -> Optional[FormSpec]:
    """Find the most likely registration form in an HTML page."""
    forms = parse_forms(html)

    # Prefer forms with action containing "register" or "signup"
    for form in forms:
        if any(kw in form.action.lower() for kw in ("register", "signup", "sign-up")):
            if form.is_register_form():
                return form

    # Fallback: any form that looks like a registration form
    for form in forms:
        if form.is_register_form():
            return form

    return None


def build_registration_payload(
    form: FormSpec,
    username: str,
    password: str,
    email: str,
    name: str = "Erebos Test",
) -> Dict[str, str]:
    """Build a form submission payload using classified fields.

    Maps semantic values to actual field names discovered via introspection.
    """
    field_map = form.classify_fields()
    payload: Dict[str, str] = {}

    # Fill hidden fields (CSRF tokens, etc.)
    payload.update(form.hidden_fields)

    # Fill semantic fields
    if "username" in field_map:
        payload[field_map["username"]] = username
    if "email" in field_map:
        payload[field_map["email"]] = email
    if "name" in field_map:
        payload[field_map["name"]] = name
    if "password" in field_map:
        payload[field_map["password"]] = password
    if "password_confirm" in field_map:
        payload[field_map["password_confirm"]] = password

    return payload


def build_login_payload(
    form: FormSpec,
    username: str,
    password: str,
) -> Dict[str, str]:
    """Build a login form submission payload."""
    field_map = form.classify_fields()
    payload: Dict[str, str] = {}

    # Fill hidden fields (CSRF tokens)
    payload.update(form.hidden_fields)

    # Fill credentials — use username field (could be named "login", "username", "email", etc.)
    username_field = field_map.get("username") or field_map.get("email")
    if username_field:
        payload[username_field] = username
    if "password" in field_map:
        payload[field_map["password"]] = password

    return payload
