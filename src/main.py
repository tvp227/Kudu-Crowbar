# src/main.py
import tkinter as tk
from pathlib import Path
from .ui.window import MainWindow
from dotenv import load_dotenv
import os

def load_repository_paths():
    """Load repository paths from environment variables."""
    # Load .env file
    load_dotenv()
    
    # Get all environment variables that start with REPO_PATH_
    repos = []
    for key, value in os.environ.items():
        if key.startswith('REPO_PATH_'):
            path = Path(value)
            if path.exists() and path.is_dir():
                repos.append(path)
            else:
                print(f"Warning: Repository path {value} from {key} does not exist or is not a directory")
    
    return repos

def main():
    root = tk.Tk()
    app = MainWindow(root)
    
    # Load repositories from environment variables
    repos = load_repository_paths()
    if not repos:
        print("Warning: No valid repository paths found in .env file")
    
    app.load_repositories(repos)
    root.mainloop()

if __name__ == "__main__":
    main()