# src/ui/window.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import shutil
import re
from pathlib import Path
from typing import Dict, List, Optional
from ..rule_manager import RuleManager

class MainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Kudu Crowbar")
        self.rule_manager = RuleManager()
        
        # Track currently selected rule for KQL editing
        self.current_rule_path = None
        
        # Set default window size
        self.root.geometry("1440x1020")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('Bold.TLabel', font=('TkDefaultFont', 9, 'bold'))
        self.style.configure('Footer.TLabel', font=('TkDefaultFont', 8), foreground='gray')
        
        # Load logo image
        try:
            logo_path = Path("assets/cyber-kudulogo.png")
            if not logo_path.exists():
                self.logo_image = None
            else:
                # Load and resize the logo
                original_image = tk.PhotoImage(file=str(logo_path.absolute()))
                # Subsample by factor of 4 to make it smaller (adjust this number to change size)
                self.logo_image = original_image.subsample(4, 4)
        except Exception as e:
            self.logo_image = None

        self.setup_ui()

    def setup_ui(self):
        """Setup the main UI components."""
        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True)

        # Left panel - Rule list
        left_frame = ttk.Frame(main_container)
        main_container.add(left_frame, weight=1)
        
        # Filter and import section
        toolbar_frame = ttk.Frame(left_frame)
        toolbar_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Search/filter
        filter_frame = ttk.Frame(toolbar_frame)
        filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', self.filter_rules)
        ttk.Entry(filter_frame, textvariable=self.filter_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Import button
        ttk.Button(toolbar_frame, text="Import Rule", command=self.import_rule).pack(side=tk.RIGHT, padx=5)
        
        # Rule tree with checkboxes and scrollbar
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.rule_tree = ttk.Treeview(tree_frame, selectmode='extended', columns=('status',))
        self.rule_tree.heading('#0', text='Repository / Rule Name')
        self.rule_tree.heading('status', text='Status')
        
        # Add scrollbar to rule tree
        rule_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.rule_tree.yview)
        
        # Pack scrollbar and tree
        rule_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rule_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.rule_tree.configure(yscrollcommand=rule_scrollbar.set)
        self.rule_tree.bind('<<TreeviewSelect>>', self.on_rule_select)
        
        # Middle panel - Rule details
        middle_frame = ttk.Frame(main_container)
        main_container.add(middle_frame, weight=2)
        
        # Settings preview
        settings_frame = ttk.LabelFrame(middle_frame, text="Current Settings")
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.settings_text = tk.Text(settings_frame, height=10, wrap=tk.WORD, font=('Consolas', 10))
        self.settings_text.pack(fill=tk.X, padx=5, pady=5)
        
        # JSON preview
        json_frame = ttk.LabelFrame(middle_frame, text="JSON Content")
        json_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        json_container = ttk.Frame(json_frame)
        json_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.json_text = tk.Text(json_container, wrap=tk.NONE, font=('Consolas', 10))
        json_v_scroll = ttk.Scrollbar(json_container, orient="vertical", command=self.json_text.yview)
        json_h_scroll = ttk.Scrollbar(json_container, orient="horizontal", command=self.json_text.xview)
        
        self.json_text.configure(yscrollcommand=json_v_scroll.set, xscrollcommand=json_h_scroll.set)
        
        self.json_text.grid(row=0, column=0, sticky="nsew")
        json_v_scroll.grid(row=0, column=1, sticky="ns")
        json_h_scroll.grid(row=1, column=0, sticky="ew")
        
        json_container.grid_rowconfigure(0, weight=1)
        json_container.grid_columnconfigure(0, weight=1)

        # Right panel - Actions
        right_frame = ttk.Frame(main_container)
        main_container.add(right_frame, weight=1)
        
        # Logo and Title container
        logo_container = ttk.Frame(right_frame)
        logo_container.pack(anchor="ne", padx=5, pady=5)
        
        # Title
        title_label = ttk.Label(logo_container, text="Cyber Kudu", style='Bold.TLabel', font=('TkDefaultFont', 14, 'bold'))
        title_label.pack(side=tk.LEFT, padx=(0,10))
        
        # Logo
        if hasattr(self, 'logo_image') and self.logo_image:
            logo_label = ttk.Label(logo_container, image=self.logo_image)
            logo_label.image = self.logo_image  # Keep a reference!
        else:
            logo_label = ttk.Label(logo_container, text="[Logo]")
        logo_label.pack(side=tk.LEFT)
        
        # Actions header
        ttk.Label(right_frame, text="Actions", style='Bold.TLabel').pack(padx=5, pady=5)
        
        # Quick actions
        actions_frame = ttk.LabelFrame(right_frame, text="Quick Actions")
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(actions_frame, text="Enable Selected", 
                command=lambda: self.modify_rules({"enabled": True})).pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(actions_frame, text="Disable Selected", 
                command=lambda: self.modify_rules({"enabled": False})).pack(fill=tk.X, padx=5, pady=2)
        
        # Modifications frame
        mods_frame = ttk.LabelFrame(right_frame, text="Modify Properties")
        mods_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Severity modifier
        ttk.Label(mods_frame, text="Severity:").pack(padx=5, pady=(5,2))
        self.severity_var = tk.StringVar()
        severity_combo = ttk.Combobox(mods_frame, 
                                    textvariable=self.severity_var,
                                    values=["Low", "Medium", "High", "Informational"])
        severity_combo.pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(mods_frame, text="Apply Severity", 
                command=self.apply_severity).pack(fill=tk.X, padx=5, pady=2)
        
        # Time period modifier
        ttk.Label(mods_frame, text="Time Period:").pack(padx=5, pady=(10,2))
        self.period_var = tk.StringVar()
        period_combo = ttk.Combobox(mods_frame, 
                                textvariable=self.period_var,
                                values=["P1D", "P2D", "P3D", "P7D", "P14D", "P30D"])
        period_combo.pack(fill=tk.X, padx=5, pady=2)
        ttk.Button(mods_frame, text="Apply Time Period", 
                command=self.apply_time_period).pack(fill=tk.X, padx=5, pady=2)
        
        # KQL Editor
        ttk.Label(mods_frame, text="KQL Query Editor:", style='Bold.TLabel').pack(padx=5, pady=(15,2))
        
        # Add KQL editor frame
        kql_frame = ttk.Frame(mods_frame)
        kql_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        # Add KQL editor with syntax highlighting
        self.kql_text = scrolledtext.ScrolledText(kql_frame, height=10, wrap=tk.WORD, font=('Consolas', 10))
        self.kql_text.pack(fill=tk.BOTH, expand=True)
        
        # Add KQL update button
        ttk.Button(mods_frame, text="Update KQL", command=self.update_kql).pack(fill=tk.X, padx=5, pady=2)
        
        # Git operations
        git_frame = ttk.LabelFrame(right_frame, text="Git Operations")
        git_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(git_frame, text="Commit Message:").pack(padx=5, pady=(5,2))
        self.commit_message = tk.Text(git_frame, height=3, wrap=tk.WORD)
        self.commit_message.pack(fill=tk.X, padx=5, pady=2)
        self.commit_message.insert('1.0', "Updated Sentinel rules via the Kudu Crowbar")
        
        ttk.Button(git_frame, text="Commit & Push Changes", 
                command=self.commit_changes).pack(fill=tk.X, padx=5, pady=(5,2))

        # Footer
        footer_frame = ttk.Frame(self.root)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
        footer_label = ttk.Label(footer_frame, text="kudu-crowbar by Thomas Porter", style='Footer.TLabel')
        footer_label.pack(side=tk.RIGHT)

    def load_repositories(self, paths: List[str]):
        """Load repositories and populate rule tree."""
        for path in paths:
            self.rule_manager.add_repository(path)
        self.refresh_rule_list()

    def import_rule(self):
        """Import a rule file to selected repositories."""
        # Get selected repositories (should be parent nodes in the tree)
        selected = self.rule_tree.selection()
        repo_items = [item for item in selected if not self.rule_tree.parent(item)]
        
        if not repo_items:
            messagebox.showwarning(
                "No Repository Selected", 
                "Please select at least one repository to import the rule into."
            )
            return

        # Ask user for the rule file
        file_path = filedialog.askopenfilename(
            title="Select Rule File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return

        try:
            # Validate JSON and check if it's a valid rule
            with open(file_path, 'r') as f:
                rule_data = json.load(f)
                
            if not self._is_valid_rule(rule_data):
                messagebox.showerror(
                    "Invalid Rule", 
                    "The selected file does not appear to be a valid Sentinel rule."
                )
                return

            # Get rule name for the new file
            rule_name = self._get_rule_name(rule_data)
            file_name = Path(file_path).name

            # Copy to each selected repository
            for repo_item in repo_items:
                repo_name = self.rule_tree.item(repo_item)['text']
                repo_path = self._find_repo_path_by_name(repo_name)
                
                if repo_path:
                    # Create AnalyticRules directory if it doesn't exist
                    rules_dir = repo_path / "AnalyticRules"
                    rules_dir.mkdir(exist_ok=True)
                    
                    # Copy the rule file
                    destination = rules_dir / file_name
                    shutil.copy2(file_path, destination)

            self.refresh_rule_list()
            messagebox.showinfo(
                "Import Successful", 
                f"Rule '{rule_name}' has been imported to the selected repositories."
            )

        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import rule: {str(e)}")

    def _is_valid_rule(self, data: dict) -> bool:
        """Check if the JSON data represents a valid Sentinel rule."""
        try:
            return (isinstance(data, dict) and 
                    "resources" in data and 
                    any("alertRules" in resource.get("type", "") 
                        for resource in data.get("resources", [])))
        except:
            return False

    def _find_repo_path_by_name(self, repo_name: str) -> Optional[Path]:
        """Find repository path by its name."""
        for repo_path in self.rule_manager.repositories:
            if repo_path.name == repo_name:
                return repo_path
        return None

    def refresh_rule_list(self):
        """Refresh the rule tree display."""
        self.rule_tree.delete(*self.rule_tree.get_children())
        
        # Create a dictionary to store repo paths and their corresponding tree IDs
        repo_nodes = {}
        
        for path, rule in self.rule_manager.get_all_rules().items():
            # Get repository path and create/get repo node
            repo_path = self._get_repo_path(path)
            if repo_path not in repo_nodes:
                # Create repository node using the last part of the path
                repo_name = repo_path.name
                repo_id = self.rule_tree.insert("", "end", text=repo_name, values=("",))
                repo_nodes[repo_path] = repo_id
            
            # Insert rule under repository node
            name = self._get_rule_name(rule)
            status = self._get_rule_status(rule)
            self.rule_tree.insert(repo_nodes[repo_path], "end", text=name, values=(status,), tags=(str(path),))

    def filter_rules(self, *args):
        """Filter rules based on search text."""
        search_text = self.filter_var.get().lower()
        self.refresh_rule_list()  # Reset the tree
        
        if not search_text:  # If no search text, we're done
            return
            
        # Iterate through all items
        for repo_item in self.rule_tree.get_children():
            keep_repo = False
            rule_items = self.rule_tree.get_children(repo_item)
            
            # Check each rule in the repo
            for rule_item in rule_items:
                rule_text = self.rule_tree.item(rule_item)['text'].lower()
                if search_text not in rule_text:
                    self.rule_tree.detach(rule_item)
                else:
                    keep_repo = True
            
            # Remove repo node if it has no matching rules
            if not keep_repo:
                self.rule_tree.detach(repo_item)

    def on_rule_select(self, event):
        """Handle rule selection event."""
        selected = self.rule_tree.selection()
        if not selected:
            self.clear_preview()
            self.current_rule_path = None
            self.kql_text.delete('1.0', tk.END)
            return
        
        # Get the last selected item
        item = selected[-1]
        
        # Check if it's a rule (not a repository)
        if not self.rule_tree.parent(item):  # If no parent, it's a repo node
            self.clear_preview()
            self.current_rule_path = None
            self.kql_text.delete('1.0', tk.END)
            return
            
        # Get the rule path from the item's tags
        path = Path(self.rule_tree.item(item)["tags"][0])
        self.current_rule_path = path
        
        # Find the repository containing this rule
        repo_path = self._get_repo_path(path)
        if repo_path and repo_path in self.rule_manager.repositories:
            rule_data = self.rule_manager.repositories[repo_path].rules[path]
            self.update_preview(rule_data)
            
            # Update KQL editor
            self.kql_text.delete('1.0', tk.END)
            for resource in rule_data.get("resources", []):
                if "alertRules" in resource.get("type", ""):
                    if "properties" in resource and "query" in resource["properties"]:
                        encoded_kql = resource["properties"]["query"]
                        decoded_kql = self._decode_kql_from_json(encoded_kql)
                        self.kql_text.insert('1.0', decoded_kql)
                        break

    def update_preview(self, rule_data: dict):
        """Update the preview panels with rule data."""
        # Clear existing content
        self.settings_text.delete('1.0', tk.END)
        self.json_text.delete('1.0', tk.END)
        
        # Update settings preview
        for resource in rule_data.get("resources", []):
            if "alertRules" in resource.get("type", ""):
                props = resource.get("properties", {})
                settings = [
                    "• Rule Name:",
                    f"  {props.get('displayName', 'N/A')}",
                    "",
                    "• Status:",
                    f"  {'Enabled' if props.get('enabled', False) else 'Disabled'}",
                    "",
                    "• Severity:",
                    f"  {props.get('severity', 'N/A')}",
                    "",
                    "• Time Settings:",
                    f"  - Query Period: {props.get('queryPeriod', 'N/A')}",
                    f"  - Query Frequency: {props.get('queryFrequency', 'N/A')}",
                    "",
                    "• Tactics:",
                    f"  {', '.join(props.get('tactics', ['N/A']))}",
                    "",
                    "• Description:",
                    f"  {props.get('description', 'N/A')[:200]}..."
                ]
                self.settings_text.insert('1.0', '\n'.join(settings))
        
        # Update JSON preview
        formatted_json = json.dumps(rule_data, indent=2)
        self.json_text.insert('1.0', formatted_json)

    def clear_preview(self):
        """Clear all preview panels."""
        self.settings_text.delete('1.0', tk.END)
        self.json_text.delete('1.0', tk.END)
        self.kql_text.delete('1.0', tk.END)

    def modify_rules(self, modifications: Dict):
        """Apply modifications to selected rules."""
        selected = self.rule_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select at least one rule to modify.")
            return
        
        # Filter out repository nodes
        rule_items = [item for item in selected if self.rule_tree.parent(item)]
        
        if not rule_items:
            messagebox.showwarning("No Rules Selected", "Please select rules to modify (not repositories).")
            return
        
        rules = []
        for item in rule_items:
            path_str = self.rule_tree.item(item)["tags"][0]
            rules.append(Path(path_str))
        
        self.rule_manager.modify_rules(rules, modifications)
        self.refresh_rule_list()
        
        # Update preview if a modified rule is selected
        if len(rule_items) == 1:
            self.on_rule_select(None)

    def _decode_kql_from_json(self, encoded_kql: str) -> str:
        """Convert JSON-encoded KQL to readable format."""
        # Replace common encoded characters
        replacements = {
            r'\n': '\n',    # Newlines
            r'\r': '',      # Carriage returns
            r'\t': '    ',  # Tabs to spaces
            r'\"': '"',     # Quotes
            r'\\': '\\',    # Backslashes
        }
        
        decoded = encoded_kql
        for encoded, decoded_char in replacements.items():
            decoded = decoded.replace(encoded, decoded_char)
        
        return decoded

    def _encode_kql_for_json(self, kql: str) -> str:
        """Convert readable KQL to JSON-encoded format."""
        # Replace characters that need encoding
        replacements = {
            '\\': r'\\',    # Backslashes
            '"': r'\"',     # Quotes
            '\n': r'\n',    # Newlines
            '\t': r'\t',    # Tabs
        }
        
        encoded = kql
        for raw, encoded_char in replacements.items():
            encoded = encoded.replace(raw, encoded_char)
        
        return encoded

    def update_kql(self):
        """Update the KQL query in the selected rule."""
        if not self.current_rule_path:
            messagebox.showwarning("No Rule Selected", "Please select a rule to update its KQL.")
            return
        
        try:
            # Get the updated KQL from the editor
            new_kql = self.kql_text.get('1.0', tk.END).strip()
            
            # Encode special characters for JSON
            encoded_kql = self._encode_kql_for_json(new_kql)
            
            # Find the repository and rule
            repo_path = self._get_repo_path(self.current_rule_path)
            if not repo_path or repo_path not in self.rule_manager.repositories:
                return
                
            rule_data = self.rule_manager.repositories[repo_path].rules[self.current_rule_path]
            
            # Update the query in the rule data
            for resource in rule_data.get("resources", []):
                if "alertRules" in resource.get("type", ""):
                    if "properties" in resource:
                        resource["properties"]["query"] = encoded_kql
            
            # Save the updated rule
            with open(self.current_rule_path, 'w') as f:
                json.dump(rule_data, f, indent=4)
            
            # Update the preview
            self.update_preview(rule_data)
            messagebox.showinfo("Success", "KQL query updated successfully.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update KQL: {str(e)}")

    def apply_severity(self):
        """Apply selected severity to rules."""
        severity = self.severity_var.get()
        if not severity:
            messagebox.showwarning("No Severity", "Please select a severity level.")
            return
        self.modify_rules({"severity": severity})

    def apply_time_period(self):
        """Apply selected time period to rules."""
        period = self.period_var.get()
        if not period:
            messagebox.showwarning("No Time Period", "Please select a time period.")
            return
        self.modify_rules({"queryPeriod": period})

    def commit_changes(self):
        """Commit and push changes to all repositories."""
        message = self.commit_message.get('1.0', tk.END).strip()
        if not message:
            messagebox.showwarning("No Message", "Please enter a commit message.")
            return
        
        try:
            self.rule_manager.commit_all(message)
            messagebox.showinfo("Success", "Changes committed and pushed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to commit changes: {str(e)}")

    def _get_rule_name(self, rule: dict) -> str:
        """Extract rule name from rule data."""
        for resource in rule.get("resources", []):
            if "alertRules" in resource.get("type", ""):
                return resource.get("properties", {}).get("displayName", "Unnamed Rule")
        return "Unnamed Rule"

    def _get_rule_status(self, rule: dict) -> str:
        """Get the enabled/disabled status of a rule."""
        for resource in rule.get("resources", []):
            if "alertRules" in resource.get("type", ""):
                return "Enabled" if resource.get("properties", {}).get("enabled", False) else "Disabled"
        return "Unknown"

    def _get_repo_path(self, rule_path: Path) -> Optional[Path]:
        """Get repository path for a rule."""
        for repo_path in self.rule_manager.repositories:
            if repo_path in rule_path.parents:
                return repo_path
        return None