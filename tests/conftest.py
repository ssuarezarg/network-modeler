import sys
from pathlib import Path

# Fixtures below are synthetic. Customer configurations are never committed to
# this repository, not even as test data -- see docs/ARCHITECTURE.md §4.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
