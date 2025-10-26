# github_updater.py  (replace your file with this or add the new methods)

from github import Github
import json
import base64
import hashlib
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def _stable_json_bytes(obj) -> bytes:
    # stable formatting ensures reproducible hashes
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

class GitHubUpdater:
    def __init__(self, token, repo_name, branch='main'):
        self.g = Github(token)
        self.repo = self.g.get_repo(repo_name)
        self.branch = branch

    # ---------- NEW: read helpers ----------
    def read_text_or_none(self, file_path: str) -> str | None:
        try:
            f = self.repo.get_contents(file_path, ref=self.branch)
            return base64.b64decode(f.content).decode("utf-8")
        except Exception as e:
            logger.info(f"[GitHubUpdater] {file_path} not found on {self.branch}: {e}")
            return None

    def read_json_or_none(self, file_path: str):
        txt = self.read_text_or_none(file_path)
        if txt is None:
            return None
        try:
            return json.loads(txt)
        except Exception as e:
            logger.warning(f"[GitHubUpdater] Failed to parse JSON in {file_path}: {e}")
            return None

    # ---------- legacy (kept) ----------
    def update_file(self, file_path, content, commit_message=None):
        if commit_message is None:
            commit_message = f"Update {file_path} - {datetime.utcnow().isoformat()}"
        try:
            file = self.repo.get_contents(file_path, ref=self.branch)
            self.repo.update_file(
                path=file_path,
                message=commit_message,
                content=content,
                sha=file.sha,
                branch=self.branch
            )
            logger.info(f"Updated {file_path}")
        except Exception:
            try:
                self.repo.create_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    branch=self.branch
                )
                logger.info(f"Created {file_path}")
            except Exception as create_error:
                logger.error(f"Error updating/creating file: {create_error}")
                raise

    # ---------- NEW: only update if changed ----------
    def update_json_if_changed(self, file_path: str, data: dict) -> bool:
        data = dict(data)  # copy
        data['lastUpdated'] = datetime.utcnow().isoformat()
        data['updateTimestamp'] = int(datetime.utcnow().timestamp())

        new_bytes = _stable_json_bytes(data)
        try:
            cur = self.repo.get_contents(file_path, ref=self.branch)
            cur_bytes = base64.b64decode(cur.content)
            if hashlib.sha256(cur_bytes).digest() == hashlib.sha256(new_bytes).digest():
                logger.info(f"[GitHubUpdater] {file_path} unchanged")
                return False
            self.repo.update_file(
                file_path,
                f"Update {file_path} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                new_bytes.decode("utf-8"),
                cur.sha,
                branch=self.branch
            )
            logger.info(f"Updated {file_path}")
            return True
        except Exception:
            # file probably doesn't exist yet
            self.repo.create_file(
                file_path,
                f"Create {file_path} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                new_bytes.decode("utf-8"),
                branch=self.branch
            )
            logger.info(f"Created {file_path}")
            return True

    # ---------- legacy (kept, but now optional) ----------
    def update_json(self, file_path, data):
        data = dict(data)
        data['lastUpdated'] = datetime.utcnow().isoformat()
        data['updateTimestamp'] = int(datetime.utcnow().timestamp())
        json_content = json.dumps(data, indent=2, sort_keys=True)
        self.update_file(
            file_path=file_path,
            content=json_content,
            commit_message=f"Update reward tokens - {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        )
