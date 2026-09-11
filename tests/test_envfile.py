import os

import pytest

from netconfig_mirror import envfile


@pytest.fixture
def clean_env(monkeypatch):
    for name in ("PGHOST", "PGUSER", "PGPASSWORD", "PGSSLMODE"):
        monkeypatch.delenv(name, raising=False)


def test_loads_key_value_pairs(tmp_path, clean_env):
    path = tmp_path / ".env"
    path.write_text("PGHOST=10.1.1.5\nPGUSER=extractor_ro\n")
    assert set(envfile.load(path)) == {"PGHOST", "PGUSER"}
    assert os.environ["PGHOST"] == "10.1.1.5"


def test_real_environment_wins_over_the_file(tmp_path, monkeypatch, clean_env):
    """So one setting can be overridden for a single run, and a scheduled job's
    explicit configuration cannot be replaced by a stale .env left in the
    directory."""
    monkeypatch.setenv("PGHOST", "from-the-shell")
    path = tmp_path / ".env"
    path.write_text("PGHOST=from-the-file\n")
    envfile.load(path)
    assert os.environ["PGHOST"] == "from-the-shell"


def test_comments_blanks_and_export_prefix(tmp_path, clean_env):
    path = tmp_path / ".env"
    path.write_text("# a comment\n\nexport PGUSER=ops\n")
    envfile.load(path)
    assert os.environ["PGUSER"] == "ops"


def test_quoted_value_keeps_spaces_and_hashes(tmp_path, clean_env):
    """A generated password can contain both; unquoted parsing would truncate
    at the '#' and produce an authentication failure with no obvious cause."""
    path = tmp_path / ".env"
    path.write_text('PGPASSWORD="a b#c"\n')
    envfile.load(path)
    assert os.environ["PGPASSWORD"] == "a b#c"


def test_empty_assignment_is_an_unfilled_template_line(tmp_path, monkeypatch, clean_env):
    """`.env.example` ships with `PGPASSWORD=`; copying it must not blank out a
    password that is already set in the environment."""
    monkeypatch.setenv("PGPASSWORD", "real")
    path = tmp_path / ".env"
    path.write_text("PGPASSWORD=\n")
    envfile.load(path, override=True)
    assert os.environ["PGPASSWORD"] == "real"


def test_missing_file_is_not_an_error(tmp_path, clean_env):
    assert envfile.load(tmp_path / "nope.env") == []
