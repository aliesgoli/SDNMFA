"""
SDN Multi-Factor Authentication System
Root package initializer
"""

import sys
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.absolute()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

__version__ = "1.0.0"
__author__ = "Ali Esmaeili Goli"

