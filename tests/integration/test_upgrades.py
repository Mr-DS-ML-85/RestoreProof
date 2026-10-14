"""Upgrading an existing installation with real history must work (SQLite rebuilds tables on ALTER)."""

from __future__ import annotations

import pytest
from alembic import command

from tests.conftest import REPO_PASSWORD
from tests.helpers import client, file_definition, make_app, make_source, run_test

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("from_rev", ["0005"])
def test_upgrade_with_existing_history(env, restic_repo, from_rev):
    from restoreproof.db.migrations import alembic_config, upgrade
    from restoreproof.db.session import get_engine

    if get_engine().dialect.name != "sqlite":
        pytest.skip("SQLite-specific table rebuild path")
    repo, src, _ = restic_repo
    c, h = client()
    aid = make_app(c, h, make_source(c, h, repo, REPO_PASSWORD), file_definition("history", src))
    job = run_test(c, h, aid)  # real jobs, attempts, checks, artifacts referencing the app
    cfg = alembic_config()
    get_engine().dispose()
    # Go back to an older schema keeping data where possible, then upgrade again like a real update would.
    if from_rev == "0005":
        command.downgrade(cfg, "0005")
    upgrade()
    assert c.get(f"/api/v1/jobs/{job['id']}", headers=h).json()["status"] == "passed"
    assert c.delete(f"/api/v1/apps/{aid}?keep_history=true", headers=h).status_code == 200
