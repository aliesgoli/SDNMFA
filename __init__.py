"""
SDN Multi-Factor Authentication System
Root package initializer
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.absolute()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

__version__ = "2.0.0"
__author__ = "Ali Esmaeili Goli"
