#!/usr/bin/env python3
"""
Basic test script to verify the VDAgent structure.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing imports...")

    try:
        from config.settings import settings
        print("✓ config.settings imported")

        from core.agent import VDAgent, FunctionInfo, VulnerabilityFinding
        print("✓ core.agent imported")

        from integrations.base import ReverseEngineeringTool
        print("✓ integrations.base imported")

        from models.deepseek import DeepSeekAnalyzer
        print("✓ models.deepseek imported")

        from analyzers.vulnerability import VulnerabilityAnalyzer
        print("✓ analyzers.vulnerability imported")

        from utils.file_utils import is_binary_file
        print("✓ utils.file_utils imported")

        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_data_structures():
    """Test data structure creation."""
    print("\nTesting data structures...")

    try:
        # Test FunctionInfo
        func = FunctionInfo(
            name="test_func",
            address="0x08048400",
            pseudocode="void test_func() {\n    int x = 0;\n}",
            size=100,
            complexity=0.5
        )
        print(f"✓ FunctionInfo created: {func.name} at {func.address}")

        # Test VulnerabilityFinding
        finding = VulnerabilityFinding(
            function_name="test_func",
            address="0x08048400",
            vulnerability_type="buffer_overflow",
            confidence=0.85,
            description="Potential buffer overflow in stack variable",
            pseudocode_snippet="char buffer[64];\nstrcpy(buffer, input);",
            remediation="Use strncpy with size limit",
            cwe_id="CWE-120"
        )
        print(f"✓ VulnerabilityFinding created: {finding.vulnerability_type}")

        return True
    except Exception as e:
        print(f"✗ Data structure error: {e}")
        return False

def test_settings():
    """Test settings loading."""
    print("\nTesting settings...")

    try:
        from config.settings import settings

        print(f"  DEEPSEEK_API_KEY: {settings.DEEPSEEK_API_KEY[:10]}...")
        print(f"  MAX_FUNCTIONS_PER_ANALYSIS: {settings.MAX_FUNCTIONS_PER_ANALYSIS}")
        print(f"  OUTPUT_DIR: {settings.OUTPUT_DIR}")
        print(f"  LOG_LEVEL: {settings.LOG_LEVEL}")

        # Create a test setting update
        original_value = settings.MAX_FUNCTIONS_PER_ANALYSIS
        settings.MAX_FUNCTIONS_PER_ANALYSIS = 50
        print(f"  Updated MAX_FUNCTIONS_PER_ANALYSIS: {settings.MAX_FUNCTIONS_PER_ANALYSIS}")

        # Restore original value
        settings.MAX_FUNCTIONS_PER_ANALYSIS = original_value

        print("✓ Settings loaded and modifiable")
        return True
    except Exception as e:
        print(f"✗ Settings error: {e}")
        return False

def test_agent_initialization():
    """Test agent initialization (without actual tools)."""
    print("\nTesting agent initialization...")

    try:
        # Mock tool paths to test initialization
        import os
        os.environ['DEEPSEEK_API_KEY'] = 'test_key'

        # This should fail due to missing tool paths, but we can catch the expected error
        try:
            agent = VDAgent(tool_preference="auto")
            print("⚠ Agent initialized (unexpected - tools might be configured)")
        except (ValueError, RuntimeError) as e:
            print(f"✓ Agent initialization failed as expected (no tools configured): {e}")

        return True
    except Exception as e:
        print(f"✗ Agent initialization test error: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("VDAgent Basic Structure Test")
    print("=" * 60)

    tests = [
        test_imports,
        test_data_structures,
        test_settings,
        test_agent_initialization,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("✓ All tests passed! Basic structure is valid.")
        return 0
    else:
        print("⚠ Some tests failed. Check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())