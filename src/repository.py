# src/repository.py
from pathlib import Path
import git
import json
from typing import List, Dict

class Repository:
    def __init__(self, path: Path):
        self.path = path
        self.repo = git.Repo(path)
        self.rules: Dict[Path, dict] = {}
        self.load_rules()
    
    def load_rules(self):
        """Load all JSON rules from the repository."""
        for json_file in self.path.glob("**/*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    if self._is_sentinel_rule(data):
                        self.rules[json_file] = data
            except json.JSONDecodeError:
                continue
    
    def _is_sentinel_rule(self, data: dict) -> bool:
        """Check if JSON file is a Sentinel rule."""
        return (isinstance(data, dict) and 
                "resources" in data and 
                any("alertRules" in resource.get("type", "") 
                    for resource in data.get("resources", [])))
    
    def save_rule(self, path: Path, data: dict):
        """Save modified rule back to file."""
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
    
    def commit_and_push(self, message: str):
        """Commit changes and push to remote."""
        self.repo.index.add("*")
        self.repo.index.commit(message)
        self.repo.remote().push()