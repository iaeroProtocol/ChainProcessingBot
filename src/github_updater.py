"""GitHub publication with snapshot reads and atomic multi-file measurement generations."""
import base64
import json
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from github import Github, InputGitTreeElement

logger = logging.getLogger(__name__)


def _missing(error):
    return getattr(error, "status", None) == 404 or isinstance(error, FileNotFoundError)


def _stable_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class GitHubUpdater:
    def __init__(self, token, repo_name, branch="main", repo=None):
        self.g = None if repo is not None else Github(token)
        self.repo = repo if repo is not None else self.g.get_repo(repo_name)
        self.branch = branch
        self._pending = None

    def read_text_or_none(self, path):
        try:
            f = self.repo.get_contents(path, ref=self.branch)
            if getattr(f, "encoding", "base64") == "none":
                f = self.repo.get_git_blob(f.sha)
            return base64.b64decode(f.content).decode()
        except Exception as error:
            if _missing(error):
                return None
            raise

    def read_json_or_none(self, path):
        text = self.read_text_or_none(path)
        return None if text is None else json.loads(text)

    def _sha(self, path, ref):
        try:
            return self.repo.get_contents(path, ref=ref).sha
        except Exception as error:
            if _missing(error):
                return None
            raise

    @contextmanager
    def transaction(self):
        """Read one immutable input revision; commit related outputs together, without overwriting concurrent work."""
        if self._pending is not None:
            raise RuntimeError("Nested publication transaction")
        branch = self.branch
        base = self.repo.get_git_ref("heads/" + branch).object.sha
        pending = {}
        self._pending, self.branch = pending, base
        try:
            yield
            if not pending:
                return
            for attempt in range(3):
                ref = self.repo.get_git_ref("heads/" + branch)
                current = ref.object.sha
                if current != base:
                    for path in pending:
                        if self._sha(path, base) != self._sha(path, current):
                            raise RuntimeError("Concurrent measurement update; refusing to overwrite " + path)
                parent = self.repo.get_git_commit(current)
                entries = [InputGitTreeElement(path, "100644", "blob", content=content)
                           for path, content in sorted(pending.items())]
                tree = self.repo.create_git_tree(entries, base_tree=parent.tree)
                commit = self.repo.create_git_commit("Publish measured earnings generation", tree, [parent])
                try:
                    ref.edit(commit.sha, force=False)
                    logger.info("Published %s files atomically at %s", len(pending), commit.sha)
                    return
                except Exception as error:
                    if getattr(error, "status", None) not in (409, 422) or attempt == 2:
                        raise
            raise RuntimeError("Publication conflict")
        finally:
            self._pending, self.branch = None, branch

    def update_file(self, path=None, content=None, commit_message=None, file_path=None):
        path = path if path is not None else file_path
        if self._pending is not None:
            self._pending[path] = content
            return
        message = commit_message or "Update " + path
        sha = self._sha(path, self.branch)
        if sha is None:
            self.repo.create_file(path=path, message=message, content=content, branch=self.branch)
        else:
            self.repo.update_file(path=path, message=message, content=content, sha=sha, branch=self.branch)

    def update_json(self, path, data):
        now = datetime.now(timezone.utc)
        out = dict(data, lastUpdated=now.isoformat(), updateTimestamp=int(now.timestamp()))
        self.update_file(path, json.dumps(out, indent=2, sort_keys=True))

    def update_json_if_changed(self, path, data):
        previous = self.read_json_or_none(path)
        stable = lambda d: {k: v for k, v in (d or {}).items() if k not in ("lastUpdated", "updateTimestamp")}
        if _stable_json_bytes(stable(previous)) == _stable_json_bytes(stable(data)):
            return False
        self.update_json(path, data)
        return True
