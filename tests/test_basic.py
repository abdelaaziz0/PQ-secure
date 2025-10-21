"""Basic sanity tests"""

import pytest


def test_imports():
    """Test that all modules can be imported"""
    from src.crypto import engine, keystore, trust
    assert True


def test_python_version():
    """Test Python version is adequate"""
    import sys
    assert sys.version_info >= (3, 8)


def test_oqs_import():
    """Test that oqs can be imported"""
    try:
        import oqs
        version = oqs.oqs_version()
        assert len(version) > 0
    except ImportError as e:
        pytest.fail(f"oqs not available: {e}")
