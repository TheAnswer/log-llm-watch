"""Shared test fixtures."""
import sqlite3
import tempfile
from unittest.mock import patch

import pytest

from core import config
from core.database import init_db


@pytest.fixture(autouse=True)
def tmp_db(tmp_path):
    """Use a temporary SQLite database for every test."""
    db_path = str(tmp_path / "test.sqlite3")
    with patch.object(config, "DB_PATH", db_path):
        init_db()
        yield db_path
