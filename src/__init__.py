# src/__init__.py
"""
KUDU-Crowbar - A tool for managing Sentinel rules across multiple repositories.
"""

__version__ = '0.1.0'

from .repository import Repository
from .rule_manager import RuleManager
from .ui.window import MainWindow

__all__ = ['Repository', 'RuleManager', 'MainWindow']