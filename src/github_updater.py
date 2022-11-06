from github import Github
import json
import base64
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class GitHubUpdater:
    def __init__(self, token, repo_name, branch='main'):
        self.g = Github(token)
        self.repo = self.g.get_repo(repo_name)
        self.branch = branch
        
    def update_file(self, file_path, content, commit_message=None):
        """Update or create a file in the repository"""
        
        if commit_message is None:
            commit_message = f"Update {file_path} - {datetime.utcnow().isoformat()}"
        
        try:
            # Try to get the existing file
            file = self.repo.get_contents(file_path, ref=self.branch)
            
            # Update existing file
            self.repo.update_file(
                path=file_path,
                message=commit_message,
                content=content,
                sha=file.sha,
                branch=self.branch
            )
            logger.info(f"Updated {file_path}")
            
        except Exception as e:
            # File doesn't exist, create it
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
    
    def update_json(self, file_path, data):
        """Update a JSON file in the repository"""
        
        # Add metadata
        data['lastUpdated'] = datetime.utcnow().isoformat()
        data['updateTimestamp'] = int(datetime.utcnow().timestamp())
        
        # Convert to formatted JSON
        json_content = json.dumps(data, indent=2, sort_keys=True)
        
        self.update_file(
            file_path=file_path,
            content=json_content,
            commit_message=f"Update reward tokens - {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        )
