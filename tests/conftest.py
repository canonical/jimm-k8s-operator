import sys
from pathlib import Path

# Include the project root and relevant subdirectories in sys.path 
# so that imports work correctly during testing.
# I.e. `source venv/bin/activate && python -m pytest tests/unit/test_charm.py` 
# should work without needing to set PYTHONPATH manually.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYTHONPATH_ENTRIES = (PROJECT_ROOT, PROJECT_ROOT / "lib", PROJECT_ROOT / "src")

for entry in reversed(PYTHONPATH_ENTRIES):
    entry_str = str(entry)
    if entry_str not in sys.path:
        sys.path.insert(0, entry_str)
