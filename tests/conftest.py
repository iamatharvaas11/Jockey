import pytest
import sys
import os

# Add project root to sys.path as fallback if not installed via pip install -e .
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

@pytest.fixture
def sample_jocky_script():
    return """
    TARGET SYSTEM;
    SCAN PROCESSES;
    SCAN NETWORK;
    FIND IOC;
    BUILD TIMELINE;
    EXPORT REPORT;
    """
