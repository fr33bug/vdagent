#!/usr/bin/env python3
"""
Vulnerability Detection Agent - Main Entry Point
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.agent import VDAgent
from utils.file_utils import validate_binary_file
from config.settings import settings


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Detection Agent - AI-powered binary vulnerability analysis"
    )
    parser.add_argument(
        "binary",
        help="Path to binary file to analyze (.elf, .exe, .dll, .so, etc.)"
    )
    parser.add_argument(
        "--tool", "-t",
        choices=["auto", "ida", "ghidra"],
        default="auto",
        help="Reverse engineering tool to use (default: auto)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for reports (default: ./output)"
    )
    parser.add_argument(
        "--max-functions", "-m",
        type=int,
        default=100,
        help="Maximum number of functions to analyze (default: 100)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching of AI analysis results"
    )
    parser.add_argument(
        "--config",
        help="Path to configuration file"
    )

    args = parser.parse_args()

    # Update settings from arguments
    if args.output:
        settings.OUTPUT_DIR = args.output
    if args.max_functions:
        settings.MAX_FUNCTIONS_PER_ANALYSIS = args.max_functions
    if args.no_cache:
        settings.USE_CACHE = False
    if args.verbose:
        settings.LOG_LEVEL = "DEBUG"

    # Validate binary file
    binary_path = Path(args.binary)
    is_valid, error_msg = validate_binary_file(binary_path)
    if not is_valid:
        print(f"Error: {error_msg}", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing binary: {binary_path.name}")
    print(f"File size: {binary_path.stat().st_size:,} bytes")
    print(f"Using tool: {args.tool}")
    print(f"Max functions: {args.max_functions}")
    print("-" * 50)

    try:
        # Initialize and run agent
        agent = VDAgent(tool_preference=args.tool)
        findings = agent.analyze_binary(binary_path)

        # Print summary
        print("\n" + "=" * 50)
        print("ANALYSIS SUMMARY")
        print("=" * 50)
        print(f"Total findings: {len(findings)}")

        if findings:
            # Group by vulnerability type
            by_type = {}
            for finding in findings:
                if finding.vulnerability_type not in by_type:
                    by_type[finding.vulnerability_type] = []
                by_type[finding.vulnerability_type].append(finding)

            print("\nFindings by type:")
            for vuln_type, type_findings in sorted(by_type.items()):
                high_conf = sum(1 for f in type_findings if f.confidence >= 0.7)
                print(f"  {vuln_type}: {len(type_findings)} (high confidence: {high_conf})")

            # Print top findings
            print("\nTop findings (by confidence):")
            for i, finding in enumerate(findings[:5], 1):
                print(f"  {i}. {finding.function_name} - {finding.vulnerability_type} "
                      f"(confidence: {finding.confidence:.2f})")

        print(f"\nReport saved to: {settings.OUTPUT_DIR}/")
        print("=" * 50)

        # Cleanup
        agent.cleanup()

    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError during analysis: {e}", file=sys.stderr)
        import traceback
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()