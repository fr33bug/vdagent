#!/usr/bin/env python3
"""
Demonstration script for VDAgent.
This script shows how to use the Vulnerability Detection Agent.
"""

import os
import sys
from pathlib import Path

# Set environment variables for demonstration
os.environ['DEEPSEEK_API_KEY'] = 'GZQKEY'  # Placeholder - replace with actual key

def main():
    print("VDAgent Demonstration")
    print("=" * 60)

    try:
        # Import the agent
        from vdagent.core.agent import VDAgent
        from vdagent.core.models import FunctionInfo, VulnerabilityFinding

        print("✓ Successfully imported VDAgent modules")

        # Create a sample function for demonstration
        sample_function = FunctionInfo(
            name="vulnerable_function",
            address="0x08048400",
            pseudocode="""void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Potential buffer overflow
    printf("%s", buffer);
}""",
            size=100,
            complexity=0.7
        )

        print(f"\n✓ Created sample function: {sample_function.name}")
        print(f"  Address: {sample_function.address}")
        print(f"  Size: {sample_function.size} bytes")
        print(f"  Complexity: {sample_function.complexity}")

        # Create a sample vulnerability finding
        sample_finding = VulnerabilityFinding(
            function_name="vulnerable_function",
            address="0x08048400",
            vulnerability_type="buffer_overflow",
            confidence=0.85,
            description="Potential buffer overflow due to unsafe strcpy usage",
            pseudocode_snippet="strcpy(buffer, input);",
            remediation="Use strncpy with buffer size limit",
            cwe_id="CWE-120"
        )

        print(f"\n✓ Created sample vulnerability finding:")
        print(f"  Type: {sample_finding.vulnerability_type}")
        print(f"  Confidence: {sample_finding.confidence:.2f}")
        print(f"  CWE: {sample_finding.cwe_id}")

        # Test settings
        from vdagent.config.settings import settings
        print(f"\n✓ Loaded settings:")
        print(f"  API Key: {settings.DEEPSEEK_API_KEY[:10]}...")
        print(f"  Max Functions: {settings.MAX_FUNCTIONS_PER_ANALYSIS}")
        print(f"  Output Directory: {settings.OUTPUT_DIR}")

        # Test agent initialization (without actual tools)
        print(f"\n⚠ Note: This is a demonstration only.")
        print("  To actually analyze binaries, you need:")
        print("  1. IDA Pro or Ghidra installed and configured")
        print("  2. A valid DeepSeek API key")
        print("  3. Binary files to analyze")

        print("\n" + "=" * 60)
        print("Demo completed successfully!")
        print("\nTo use VDAgent:")
        print("1. Configure .env file with your settings")
        print("2. Run: python -m vdagent path/to/binary.elf")
        print("3. Or use the Python API:")
        print("""
   from vdagent.core.agent import VDAgent

   agent = VDAgent(tool_preference=\"auto\")
   findings = agent.analyze_binary(\"path/to/binary.elf\")
   for finding in findings:
       print(f\"Found: {finding.vulnerability_type}\")
""")

        return 0

    except ImportError as e:
        print(f"✗ Import error: {e}")
        print("\nMake sure you have installed VDAgent:")
        print("  pip install -e .")
        return 1
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())