# src/ui/window.py
import tkinter as tk
from tkinter import ttk
import json
from pathlib import Path
from typing import Dict, List
from ..rule_manager import RuleManager

class MainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Sentinel Rules Manager")
        self.rule_manager = RuleManager()
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the main UI components."""
        # Left panel - Rule list
        self.rule_frame = ttk.Frame(self.root)
        self.rule_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Rule list with checkboxes
        self.rule_list = ttk.Treeview(self.rule_frame, selectmode='extended')
        self.rule_list.pack(fill=tk.BOTH, expand=True)
        
        # Right panel - Actions
        self.action_frame = ttk.Frame(self.root)
        self.action_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Quick action buttons
        ttk.Button(self.action_frame, text="Enable Selected", 
                command=lambda: self.modify_rules({"enabled": True})).pack()
        ttk.Button(self.action_frame, text="Disable Selected", 
                command=lambda: self.modify_rules({"enabled": False})).pack()
        
        # Severity modifier
        ttk.Label(self.action_frame, text="Severity:").pack()
        self.severity_var = tk.StringVar()
        severity_combo = ttk.Combobox(self.action_frame, 
                                    textvariable=self.severity_var,
                                    values=["Low", "Medium", "High"])
        severity_combo.pack()
        
        # Time period modifier
        ttk.Label(self.action_frame, text="Time Period:").pack()
        self.period_var = tk.StringVar()
        period_combo = ttk.Combobox(self.action_frame, 
                                textvariable=self.period_var,
                                values=["P1D", "P2D", "P3D", "P7D"])
        period_combo.pack()
        
        # Commit and push button
        ttk.Button(self.action_frame, text="Commit & Push Changes", 
                command=self.commit_changes).pack(pady=20)
    
    def load_repositories(self, paths: List[str]):
        """Load repositories and populate rule list."""
        for path in paths:
            self.rule_manager.add_repository(path)
        self.refresh_rule_list()
    
    def refresh_rule_list(self):
        """Refresh the rule list display."""
        self.rule_list.delete(*self.rule_list.get_children())
        for path, rule in self.rule_manager.get_all_rules().items():
            self.rule_list.insert("", "end", text=str(path), 
                                values=(self._get_rule_name(rule),))
    
    def _get_rule_name(self, rule: dict) -> str:
        """Extract rule name from rule data."""
        for resource in rule.get("resources", []):
            if "alertRules" in resource.get("type", ""):
                return resource.get("properties", {}).get("displayName", "Unnamed Rule")
        return "Unnamed Rule"
    
    def modify_rules(self, modifications: Dict):
        """Apply modifications to selected rules."""
        selected = self.rule_list.selection()
        if not selected:
            return
        
        rules = [Path(self.rule_list.item(item)["text"]) for item in selected]
        self.rule_manager.modify_rules(rules, modifications)
        self.refresh_rule_list()
    
    def commit_changes(self):
        """Commit and push changes to all repositories."""
        commit_message = "Updated Sentinel rules via Rules Manager"
        self.rule_manager.commit_all(commit_message)

