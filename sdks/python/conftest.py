"""Make the SDK importable when pytest runs from the repository root.

The package lives at sdks/python/traceguard; adding this directory to
sys.path lets tests import it without an editable install.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
