import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    # When installed as package
    from vdagent.config.settings import settings
    from vdagent.integrations.ida import IDAIntegration
    from vdagent.integrations.ghidra import GhidraIntegration
    from vdagent.models.deepseek import DeepSeekAnalyzer
    from vdagent.analyzers.vulnerability import VulnerabilityAnalyzer
    from vdagent.core.models import BinaryFormat, FunctionInfo, VulnerabilityFinding
except ImportError:
    # When running from source
    from ..config.settings import settings
    from ..integrations.ida import IDAIntegration
    from ..integrations.ghidra import GhidraIntegration
    from ..models.deepseek import DeepSeekAnalyzer
    from ..analyzers.vulnerability import VulnerabilityAnalyzer
    from .models import BinaryFormat, FunctionInfo, VulnerabilityFinding


logger = logging.getLogger(__name__)


class VDAgent:
    """Vulnerability Detection Agent."""

    def __init__(self, tool_preference: str = "auto"):
        """
        Initialize the agent.

        Args:
            tool_preference: Which reverse engineering tool to use.
                Options: "ida", "ghidra", "auto"
        """
        self.tool_preference = tool_preference
        self.tool_integration = None
        self.ai_analyzer = None
        self.vuln_analyzer = None
        self.setup_logging()
        self.initialize_components()

    def setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=getattr(logging, settings.LOG_LEVEL),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

    def initialize_components(self):
        """Initialize all components."""
        # Initialize reverse engineering tool integration
        self.tool_integration = self._initialize_tool_integration()

        # Initialize AI analyzer
        self.ai_analyzer = DeepSeekAnalyzer(
            api_key=settings.DEEPSEEK_API_KEY,
            base_url=settings.DEEPSEEK_API_BASE,
            model=settings.DEEPSEEK_MODEL
        )

        # Initialize vulnerability analyzer
        self.vuln_analyzer = VulnerabilityAnalyzer(self.ai_analyzer)

    def _initialize_tool_integration(self):
        """Initialize the reverse engineering tool integration."""
        if self.tool_preference == "ida":
            if not settings.IDA_PATH:
                raise ValueError("IDA_PATH not set in configuration")
            return IDAIntegration(ida_path=settings.IDA_PATH)

        elif self.tool_preference == "ghidra":
            if not settings.GHIDRA_PATH:
                raise ValueError("GHIDRA_PATH not set in configuration")
            return GhidraIntegration(
                ghidra_path=settings.GHIDRA_PATH,
                projects_dir=settings.GHIDRA_PROJECTS_DIR
            )

        elif self.tool_preference == "auto":
            # Try IDA first, then Ghidra
            if settings.IDA_PATH:
                return IDAIntegration(ida_path=settings.IDA_PATH)
            elif settings.GHIDRA_PATH:
                return GhidraIntegration(
                    ghidra_path=settings.GHIDRA_PATH,
                    projects_dir=settings.GHIDRA_PROJECTS_DIR
                )
            else:
                raise ValueError("No reverse engineering tool configured. Set IDA_PATH or GHIDRA_PATH.")

        else:
            raise ValueError(f"Unknown tool preference: {self.tool_preference}")

    def analyze_binary(self, binary_path: str) -> List[VulnerabilityFinding]:
        """
        Analyze a binary file for vulnerabilities.

        Args:
            binary_path: Path to the binary file.

        Returns:
            List of vulnerability findings.
        """
        binary_path = Path(binary_path)
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        logger.info(f"Starting analysis of binary: {binary_path.name}")

        # Step 1: Decompile binary using reverse engineering tool
        functions = self.decompile_binary(binary_path)

        if not functions:
            logger.warning("No functions found in binary")
            return []

        # Step 2: Analyze functions for vulnerabilities
        findings = self.vuln_analyzer.analyze_functions(functions)

        # Step 3: Generate report
        self.generate_report(binary_path, findings)

        logger.info(f"Analysis complete. Found {len(findings)} potential vulnerabilities.")
        return findings

    def decompile_binary(self, binary_path: Path) -> List[FunctionInfo]:
        """
        Decompile binary and extract function pseudocode.

        Args:
            binary_path: Path to binary file.

        Returns:
            List of FunctionInfo objects.
        """
        logger.info(f"Decompiling binary using {self.tool_integration.tool_name}...")

        # Get binary format
        binary_format = self.detect_binary_format(binary_path)
        logger.info(f"Detected binary format: {binary_format.value}")

        # Decompile functions
        functions = self.tool_integration.decompile_functions(
            binary_path,
            max_functions=settings.MAX_FUNCTIONS_PER_ANALYSIS
        )

        # Calculate complexity for each function
        for func in functions:
            func.complexity = self._calculate_function_complexity(func.pseudocode)

        logger.info(f"Decompiled {len(functions)} functions")
        return functions

    def detect_binary_format(self, binary_path: Path) -> BinaryFormat:
        """Detect the format of a binary file."""
        # Simple detection based on file extension
        suffix = binary_path.suffix.lower()

        if suffix in ['.elf', '.so']:
            return BinaryFormat.ELF
        elif suffix in ['.exe', '.dll', '.sys']:
            return BinaryFormat.PE
        elif suffix in ['.dylib', '.bundle']:
            return BinaryFormat.MACHO
        else:
            # Try to read magic bytes for more accurate detection
            try:
                with open(binary_path, 'rb') as f:
                    magic = f.read(4)
                    if magic[:4] == b'\x7fELF':
                        return BinaryFormat.ELF
                    elif magic[:2] == b'MZ':
                        return BinaryFormat.PE
                    elif magic[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                        return BinaryFormat.MACHO
            except Exception:
                pass

            return BinaryFormat.UNKNOWN

    def _calculate_function_complexity(self, pseudocode: str) -> float:
        """
        Calculate a simple complexity score for a function.

        This is a placeholder implementation. In production,
        you might want to use more sophisticated metrics.
        """
        lines = pseudocode.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]

        if not non_empty_lines:
            return 0.0

        # Simple metric: lines of code / 100
        complexity = len(non_empty_lines) / 100.0
        return min(complexity, 1.0)  # Cap at 1.0

    def generate_report(self, binary_path: Path, findings: List[VulnerabilityFinding]):
        """Generate a report of the findings."""
        output_dir = Path(settings.OUTPUT_DIR)
        output_dir.mkdir(exist_ok=True)

        report_path = output_dir / f"{binary_path.stem}_vuln_report.md"

        with open(report_path, 'w') as f:
            f.write(f"# Vulnerability Report for {binary_path.name}\n\n")
            f.write(f"**Analysis Date:** {self._get_current_date()}\n")
            f.write(f"**Tool Used:** {self.tool_integration.tool_name}\n")
            f.write(f"**Total Findings:** {len(findings)}\n\n")

            if findings:
                # Group by vulnerability type
                by_type = {}
                for finding in findings:
                    if finding.vulnerability_type not in by_type:
                        by_type[finding.vulnerability_type] = []
                    by_type[finding.vulnerability_type].append(finding)

                f.write("## Summary by Vulnerability Type\n\n")
                for vuln_type, type_findings in by_type.items():
                    f.write(f"- **{vuln_type}**: {len(type_findings)} findings\n")

                f.write("\n## Detailed Findings\n\n")
                for i, finding in enumerate(findings, 1):
                    f.write(f"### Finding {i}: {finding.vulnerability_type}\n\n")
                    f.write(f"**Function:** `{finding.function_name}`\n")
                    f.write(f"**Address:** `{finding.address}`\n")
                    f.write(f"**Confidence:** {finding.confidence:.2f}\n")
                    if finding.cwe_id:
                        f.write(f"**CWE-ID:** {finding.cwe_id}\n")
                    f.write(f"\n**Description:**\n\n{finding.description}\n\n")
                    f.write(f"**Pseudocode Snippet:**\n```c\n{finding.pseudocode_snippet}\n```\n\n")
                    if finding.remediation:
                        f.write(f"**Remediation:**\n\n{finding.remediation}\n\n")
                    f.write("---\n\n")
            else:
                f.write("## No vulnerabilities found\n\n")
                f.write("No potential vulnerabilities were identified in this binary.\n")

        logger.info(f"Report generated: {report_path}")

    def _get_current_date(self):
        """Get current date in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()

    def cleanup(self):
        """Cleanup resources."""
        if self.tool_integration:
            self.tool_integration.cleanup()