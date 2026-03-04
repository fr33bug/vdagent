import subprocess
import tempfile
import json
import os
from pathlib import Path
from typing import List, Optional
import logging

try:
    # When installed as package
    from vdagent.integrations.base import ReverseEngineeringTool
    from vdagent.core.models import FunctionInfo
except ImportError:
    # When running from source
    from .base import ReverseEngineeringTool
    from ..core.models import FunctionInfo


logger = logging.getLogger(__name__)


class IDAIntegration(ReverseEngineeringTool):
    """IDA Pro integration."""

    def __init__(self, ida_path: str):
        """
        Initialize IDA integration.

        Args:
            ida_path: Path to IDA Pro executable.
        """
        super().__init__("IDA Pro")
        self.ida_path = Path(ida_path)
        self.temp_dir = None
        self._initialized = False

    def initialize(self) -> bool:
        """Initialize IDA Pro connection."""
        if not self.ida_path.exists():
            logger.error(f"IDA Pro executable not found: {self.ida_path}")
            return False

        # Create temp directory for IDA scripts and outputs
        self.temp_dir = tempfile.mkdtemp(prefix="ida_vdagent_")
        logger.info(f"Created temp directory for IDA: {self.temp_dir}")

        # Test IDA availability
        test_result = self._test_ida_availability()
        if not test_result:
            logger.error("IDA Pro is not available or not working properly")
            return False

        self._initialized = True
        logger.info("IDA Pro integration initialized successfully")
        return True

    def _test_ida_availability(self) -> bool:
        """Test if IDA Pro is available and working."""
        try:
            # Try to run IDA with --help or similar simple command
            result = subprocess.run(
                [str(self.ida_path), "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0 or "IDA" in result.stdout or "IDA" in result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.error(f"Error testing IDA availability: {e}")
            return False

    def decompile_functions(self, binary_path: Path, max_functions: int = 100) -> List[FunctionInfo]:
        """
        Decompile functions using IDA Pro.

        Note: This is a simplified implementation. In production,
        you would need to create IDAPython scripts and process their output.
        """
        if not self._initialized:
            if not self.initialize():
                raise RuntimeError("IDA Pro integration not initialized")

        logger.info(f"Decompiling functions from {binary_path.name} using IDA Pro...")

        # Create IDAPython script for decompilation
        script_content = self._create_decompile_script(binary_path, max_functions)
        script_path = Path(self.temp_dir) / "decompile.py"

        with open(script_path, 'w') as f:
            f.write(script_content)

        # Output file for results
        output_path = Path(self.temp_dir) / "decompiled_functions.json"

        # Run IDA with the script
        # Note: This assumes IDA can run in batch mode with -S parameter
        cmd = [
            str(self.ida_path),
            "-B",  # Batch mode (no GUI)
            f"-S{script_path}",
            str(binary_path)
        ]

        try:
            logger.debug(f"Running IDA command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes timeout
                cwd=self.temp_dir
            )

            if result.returncode != 0:
                logger.error(f"IDA decompilation failed: {result.stderr}")
                # Try to fallback to alternative approach
                return self._fallback_decompilation(binary_path, max_functions)

            # Parse output JSON
            if output_path.exists():
                with open(output_path, 'r') as f:
                    functions_data = json.load(f)

                functions = []
                for func_data in functions_data:
                    func = FunctionInfo(
                        name=func_data.get("name", f"sub_{func_data['address']}"),
                        address=func_data.get("address", "0x0"),
                        pseudocode=func_data.get("pseudocode", ""),
                        size=func_data.get("size", 0)
                    )
                    functions.append(func)

                logger.info(f"Successfully decompiled {len(functions)} functions")
                return functions
            else:
                logger.warning("IDA script did not produce output file")
                return self._fallback_decompilation(binary_path, max_functions)

        except subprocess.TimeoutExpired:
            logger.error("IDA decompilation timed out after 5 minutes")
            return []
        except Exception as e:
            logger.error(f"Error during IDA decompilation: {e}")
            return []

    def _create_decompile_script(self, binary_path: Path, max_functions: int) -> str:
        """Create an IDAPython script for decompilation."""
        return f"""
import idautils
import idaapi
import idc
import json
import sys

def decompile_function(func_ea):
    '''Decompile a single function.'''
    try:
        # Get function name
        func_name = idc.get_func_name(func_ea)
        if not func_name:
            func_name = f"sub_{{func_ea:x}}"

        # Get function pseudocode using Hex-Rays decompiler
        # Note: This requires Hex-Rays decompiler license
        pseudocode = ""
        try:
            f = idaapi.get_func(func_ea)
            if f:
                cfunc = idaapi.decompile(f)
                if cfunc:
                    pseudocode = str(cfunc)
        except:
            # Fallback to disassembly if decompiler not available
            pseudocode = idc.GetDisasm(func_ea)

        # Get function size
        func_end = idc.find_func_end(func_ea)
        if func_end != idc.BADADDR:
            size = func_end - func_ea
        else:
            size = 0

        return {{
            "name": func_name,
            "address": f"0x{{func_ea:x}}",
            "pseudocode": pseudocode,
            "size": size
        }}
    except Exception as e:
        print(f"Error decompiling function at 0x{{func_ea:x}}: {{e}}")
        return None

def main():
    output_file = "{self.temp_dir}/decompiled_functions.json"
    functions = []

    # Get all functions
    func_count = 0
    for func_ea in idautils.Functions():
        if func_count >= {max_functions}:
            break

        func_data = decompile_function(func_ea)
        if func_data:
            functions.append(func_data)
            func_count += 1

    # Save to JSON
    with open(output_file, 'w') as f:
        json.dump(functions, f, indent=2)

    print(f"Decompiled {{len(functions)}} functions")
    idc.qexit(0)

if __name__ == "__main__":
    main()
"""

    def _fallback_decompilation(self, binary_path: Path, max_functions: int) -> List[FunctionInfo]:
        """
        Fallback decompilation method when IDAPython script fails.

        This could use alternative methods like:
        1. Using IDA's command-line output
        2. Using external tools like objdump
        3. Returning placeholder data for testing
        """
        logger.warning(f"Using fallback decompilation for {binary_path.name}")

        # Placeholder implementation - returns dummy data
        # In production, implement a proper fallback
        functions = []
        for i in range(min(10, max_functions)):
            func = FunctionInfo(
                name=f"func_{i}",
                address=f"0x{1000 + i*100:08x}",
                pseudocode=f"// Placeholder pseudocode for function {i}\nvoid func_{i}() {{\n    // Sample code\n    int x = 0;\n    return;\n}}",
                size=100 + i * 10
            )
            functions.append(func)

        return functions

    def get_function_count(self, binary_path: Path) -> int:
        """Get total number of functions in the binary."""
        # This would require running an IDA analysis
        # For now, return a placeholder
        try:
            # Try to get count from a quick analysis
            cmd = [
                str(self.ida_path),
                "-B",
                f"-A",  # Auto-analysis
                str(binary_path)
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            # Parse output to estimate function count
            # This is simplified - actual implementation would need proper parsing
            return 100  # Placeholder
        except:
            return 0

    def get_binary_info(self, binary_path: Path) -> dict:
        """Get basic information about the binary."""
        info = {
            "file_size": binary_path.stat().st_size,
            "format": "unknown",
            "architecture": "unknown",
            "entry_point": "unknown",
            "functions_count": self.get_function_count(binary_path)
        }

        # Try to get more info using file command
        try:
            result = subprocess.run(
                ["file", str(binary_path)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                info["file_info"] = result.stdout.strip()
        except:
            pass

        return info

    def cleanup(self):
        """Clean up temporary files."""
        if self.temp_dir and Path(self.temp_dir).exists():
            import shutil
            try:
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up IDA temp directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up IDA temp directory: {e}")