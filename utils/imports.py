"""
Universal Import Handler
Solves all import issues across the project
"""

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.absolute()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def safe_import(module_path: str, items: list):
    """
    Safe import with fallback
    
    Args:
        module_path: Module path like 'database.db_config'
        items: List of items to import like ['get_db_connection', 'release_db_connection']
    
    Returns:
        Dictionary of imported items
    
    Example:
        imports = safe_import('database.db_config', ['get_db_connection'])
        get_db_connection = imports['get_db_connection']
    """
    result = {}
    
    try:
        full_path = f"SDNMFA.{module_path}"
        module = __import__(full_path, fromlist=items)
        for item in items:
            result[item] = getattr(module, item)
        return result
    except (ImportError, ModuleNotFoundError):
        pass
    
    try:
        module = __import__(module_path, fromlist=items)
        for item in items:
            result[item] = getattr(module, item)
        return result
    except (ImportError, ModuleNotFoundError) as e:
        raise ImportError(
            f"Failed to import {items} from {module_path}. "
            f"Make sure you're running from project root: "
            f"cd 'My Thesis Project/SDNMFA' && python3.9 <script>"
        ) from e
