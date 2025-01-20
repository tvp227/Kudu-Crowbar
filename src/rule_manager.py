# src/rule_manager.py
from pathlib import Path
from typing import Dict, List
from .repository import Repository

class RuleManager:
    def __init__(self):
        self.repositories: Dict[Path, Repository] = {}
    
    def add_repository(self, path: str):
        """Add a repository to manage."""
        repo_path = Path(path).resolve()
        if repo_path.exists():
            self.repositories[repo_path] = Repository(repo_path)
    
    def get_all_rules(self) -> Dict[Path, dict]:
        """Get all rules from all repositories."""
        rules = {}
        for repo in self.repositories.values():
            rules.update(repo.rules)
        return rules
    
    def modify_rules(self, rules: List[Path], modifications: Dict):
        """Apply modifications to selected rules."""
        for rule_path in rules:
            repo_path = self._get_repo_path(rule_path)
            if repo_path and repo_path in self.repositories:
                rule_data = self.repositories[repo_path].rules[rule_path]
                self._apply_modifications(rule_data, modifications)
                self.repositories[repo_path].save_rule(rule_path, rule_data)
    
    def _get_repo_path(self, rule_path: Path) -> Path:
        """Get repository path for a rule."""
        for repo_path in self.repositories:
            if repo_path in rule_path.parents:
                return repo_path
        return None
    
    def _apply_modifications(self, rule_data: dict, modifications: Dict):
        """Apply modifications to a rule."""
        for resource in rule_data.get("resources", []):
            if "alertRules" in resource.get("type", ""):
                props = resource.get("properties", {})
                if "enabled" in modifications:
                    props["enabled"] = modifications["enabled"]
                if "severity" in modifications:
                    props["severity"] = modifications["severity"]
                if "queryPeriod" in modifications:
                    props["queryPeriod"] = modifications["queryPeriod"]
    
    def commit_all(self, message: str):
        """Commit and push changes to all modified repositories."""
        for repo in self.repositories.values():
            try:
                repo.commit_and_push(message)
            except git.GitCommandError as e:
                print(f"Error pushing to repository {repo.path}: {e}")
