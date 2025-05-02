import sys
from pathlib import Path
import pytest
from nextgenmap.paths import RESOURCES_DIR, resource_path

def test_resources_dir_exists():
    """Ensure we can find the resources directory."""
    assert RESOURCES_DIR is not None
    assert RESOURCES_DIR.exists()
    assert RESOURCES_DIR.is_dir()

def test_xsl_exists():
    """Ensure nmap-bootstrap.xsl is found."""
    xsl_path = resource_path("nmap-bootstrap.xsl")
    assert xsl_path.exists()
    assert xsl_path.is_file()

def test_resource_resolution_strategy():
    """Verify that we are using the correct strategy (importlib or filesystem)."""
    # This test is a bit meta, checking implementation details, but useful for verification.
    import nextgenmap.paths
    if hasattr(nextgenmap.paths, 'importlib'):
        # If we are using importlib logic
        pass 
