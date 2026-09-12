"""Exercises MirrorRepo against a real git repository in a temp directory."""
import subprocess

import pytest
import yaml

from netconfig_mirror.gitops import GitError, MirrorRepo, SyncReport, build_message


def _git(path, *args):
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    path = tmp_path / "mirror"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "Test")
    (path / ".keep").write_text("")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "init")
    return MirrorRepo(path)


def _write(repo, relative="inventory/dc4/r1", config="hostname r1\n", meta=None):
    changed = repo.write_content(relative, f"device:\n  hostname: r1\n", config)
    if changed:
        repo.write_meta(relative, yaml.safe_dump(
            meta or {"source": {"device_id": "dev-1", "collected_at": "2026-09-12"}}))
    return changed


def test_first_write_is_a_change_and_commits(repo):
    assert _write(repo)
    assert repo.commit("sync: 1 changed") is not None


def test_identical_content_produces_no_commit(repo):
    """The whole point. A network that did not change must produce silence, not
    a daily commit saying nothing happened."""
    _write(repo)
    repo.commit("first")
    assert not _write(repo)
    assert repo.commit("second") is None


def test_changed_content_commits_again(repo):
    _write(repo)
    repo.commit("first")
    assert _write(repo, config="hostname r1\ninterface Gi0/0\n")
    assert repo.commit("second") is not None


def test_provenance_is_not_rewritten_when_content_is_unchanged(repo):
    """`collected_at` moves on every capture. Rewriting meta.yaml regardless
    would dirty every device nightly and commit a change that is not one."""
    _write(repo, meta={"source": {"device_id": "dev-1", "collected_at": "2026-09-11"}})
    repo.commit("first")

    changed = repo.write_content("inventory/dc4/r1", "device:\n  hostname: r1\n",
                                 "hostname r1\n")
    assert not changed  # so the caller never writes meta.yaml

    meta = yaml.safe_load((repo.path / "inventory/dc4/r1/meta.yaml").read_text())
    assert meta["source"]["collected_at"] == "2026-09-11"
    assert repo.commit("second") is None


def test_existing_devices_is_read_from_the_repository_itself(repo):
    _write(repo)
    repo.commit("first")
    assert repo.existing_devices() == {"dev-1": "inventory/dc4/r1"}


def test_a_rename_moves_and_keeps_history(repo):
    """A renamed device must not appear as one deletion and one birth."""
    _write(repo)
    repo.commit("first")

    repo.move("inventory/dc4/r1", "inventory/dc4/r1-renamed")
    _write(repo, relative="inventory/dc4/r1-renamed")
    assert repo.commit("rename") is not None

    log = subprocess.run(["git", "log", "--follow", "--oneline", "--",
                          "inventory/dc4/r1-renamed/raw.cfg"],
                         cwd=repo.path, capture_output=True, text=True).stdout
    assert len(log.strip().splitlines()) >= 2  # history survived the move


def test_prune_removes_a_device_that_left_the_database(repo):
    for name in ("r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"):
        repo.write_content(f"inventory/dc4/{name}", "device: {}\n", "hostname x\n")
        repo.write_meta(f"inventory/dc4/{name}",
                        yaml.safe_dump({"source": {"device_id": name}}))
    repo.commit("ten devices")

    keep = {f"inventory/dc4/r{n}" for n in range(1, 10)}
    assert repo.prune(keep, complete_run=True) == ["inventory/dc4/r10"]


def test_prune_refuses_a_landslide(repo):
    """A collector that stopped reporting looks exactly like a mass
    decommissioning. An upstream outage must not be able to empty the mirror."""
    for name in ("r1", "r2", "r3", "r4"):
        repo.write_content(f"inventory/dc4/{name}", "device: {}\n", "hostname x\n")
        repo.write_meta(f"inventory/dc4/{name}",
                        yaml.safe_dump({"source": {"device_id": name}}))
    repo.commit("four devices")

    with pytest.raises(GitError) as error:
        repo.prune({"inventory/dc4/r1"}, complete_run=True)
    assert "outage" in str(error.value)


def test_prune_does_nothing_on_a_filtered_run(repo):
    """A run covering one site says nothing about devices at the others."""
    _write(repo)
    repo.commit("first")
    assert repo.prune(set(), complete_run=False) == []
    assert (repo.path / "inventory/dc4/r1").is_dir()


def test_a_dirty_repository_is_refused(repo):
    (repo.path / "hand-edited.txt").write_text("someone was here\n")
    with pytest.raises(GitError) as error:
        repo.ensure_ready()
    assert "overwrite" in str(error.value)


def test_a_directory_that_is_not_a_repository_is_refused(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(GitError) as error:
        MirrorRepo(plain).ensure_ready()
    assert "git init" in str(error.value)


def test_a_missing_directory_says_how_to_create_it(tmp_path):
    with pytest.raises(GitError) as error:
        MirrorRepo(tmp_path / "nope").ensure_ready()
    assert "does not exist" in str(error.value)


def test_readme_is_created_once_and_warns_the_repo_is_sensitive(repo):
    repo.ensure_readme()
    text = (repo.path / "README.md").read_text()
    assert "private" in text
    (repo.path / "README.md").write_text("edited\n")
    repo.ensure_readme()
    assert (repo.path / "README.md").read_text() == "edited\n"


def test_commit_message_says_what_happened():
    report = SyncReport(changed=["inventory/dc4/r1"],
                        renamed=[("inventory/dc4/old", "inventory/dc4/new")],
                        removed=["inventory/ld5/gone"])
    message = build_message(report)
    assert message.splitlines()[0] == "sync: 1 changed, 1 renamed, 1 removed"
    assert "renamed  inventory/dc4/old -> inventory/dc4/new" in message


def test_commit_message_when_nothing_moved():
    assert build_message(SyncReport()).startswith("sync: no device changes")
