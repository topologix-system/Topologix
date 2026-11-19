"""Backend test package; puts this directory on sys.path so test modules import alike as tests.<module>."""
import os
import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TESTS_DIR not in sys.path:
    sys.path.append(_TESTS_DIR)
