"""Ensure the project root is importable so `import src...` works in tests."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
