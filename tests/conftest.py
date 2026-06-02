"""Pytest fixtures for Erebos tests."""

import pytest

from erebos.core.orchestrator import reset_kill_switch


@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset global state between tests."""
    reset_kill_switch()
    yield
    reset_kill_switch()
