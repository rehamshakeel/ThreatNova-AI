"""Pytest configuration and global fixtures."""

import pytest
from app.database import init_db


@pytest.fixture(autouse=True, scope="session")
def setup_test_database():
    """Ensure database schema is created before test execution."""
    init_db()
