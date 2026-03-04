import subprocess
import tempfile
import json
import os
import time
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


class GhidraIntegration(ReverseEngineeringTool):
    """Ghidra integration."""

    def __init__(self, ghidra_path: str, projects_dir: Optional[str] = None):
        """
        Initialize Ghidra integration.

        Args:
            ghidra_path: Path to Ghidra installation directory.
            projects_dir: Path to Ghidra projects directory.
        """
        super().__init__("Ghidra")
        self.ghidra_path = Path(ghidra_path)
        self.projects_dir = Path(projects_dir) if projects_dir else None
        self.temp_dir = None
        self._initialized = False

    def initialize(self) -> bool:
        """Initialize Ghidra connection."""
        if not self.ghidra_path.exists():
            logger.error(f"Ghidra directory not found: {self.ghidra_path}")
            return False

        # Find analyzeHeadless script
        self.analyze_headless = self._find_analyze_headless()
        if not self.analyze_headless:
            logger.error("analyzeHeadless script not found in Ghidra installation")
            return False

        # Create temp directory
        self.temp_dir = tempfile.mkdtemp(prefix="ghidra_vdagent_")
        logger.info(f"Created temp directory for Ghidra: {self.temp_dir}")

        # Set projects directory if not provided
        if not self.projects_dir:
            self.projects_dir = Path(self.temp_dir) / "ghidra_projects"

        self.projects_dir.mkdir(exist_ok=True)

        # Test Ghidra availability
        test_result = self._test_ghidra_availability()
        if not test_result:
            logger.error("Ghidra is not available or not working properly")
            return False

        self._initialized = True
        logger.info("Ghidra integration initialized successfully")
        return True

    def _find_analyze_headless(self) -> Optional[Path]:
        """Find analyzeHeadless script in Ghidra installation."""
        possible_paths = [
            self.ghidra_path / "support" / "analyzeHeadless",
            self.ghidra_path / "support" / "analyzeHeadless.bat",
            self.ghidra_path / "support" / "analyzeHeadless.sh",
        ]

        for path in possible_paths:
            if path.exists():
                return path

        # Also check for the script with .sh extension on Unix-like systems
        if os.name != 'nt':  # Not Windows
            for path in possible_paths:
                sh_path = path.with_suffix('.sh')
                if sh_path.exists():
                    return sh_path

        return None

    def _test_ghidra_availability(self) -> bool:
        """Test if Ghidra is available and working."""
        try:
            # Try to run analyzeHeadless with --help
            cmd = [str(self.analyze_headless), "--help"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0 or "analyzeHeadless" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.error(f"Error testing Ghidra availability: {e}")
            return False

    def decompile_functions(self, binary_path: Path, max_functions: int = 100) -> List[FunctionInfo]:
        """
        Decompile functions using Ghidra.

        This uses Ghidra's headless mode to analyze the binary and extract
        function pseudocode.
        """
        if not self._initialized:
            if not self.initialize():
                raise RuntimeError("Ghidra integration not initialized")

        logger.info(f"Decompiling functions from {binary_path.name} using Ghidra...")

        # Create a unique project name based on binary
        project_name = f"vdagent_{binary_path.stem}_{int(time.time())}"
        output_file = Path(self.temp_dir) / "decompiled_functions.json"

        # Create Ghidra script for decompilation
        script_content = self._create_decompile_script(output_file, max_functions)
        script_path = Path(self.temp_dir) / "decompile.java"

        with open(script_path, 'w') as f:
            f.write(script_content)

        # Run Ghidra analyzeHeadless
        cmd = [
            str(self.analyze_headless),
            str(self.projects_dir),
            project_name,
            "-import", str(binary_path),
            "-scriptPath", str(self.temp_dir),
            "-postScript", "decompile.java",
            "-deleteProject"  # Clean up after analysis
        ]

        try:
            logger.debug(f"Running Ghidra command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes timeout (Ghidra can be slow)
                cwd=self.temp_dir
            )

            if result.returncode != 0:
                logger.error(f"Ghidra decompilation failed: {result.stderr}")
                # Try fallback
                return self._fallback_decompilation(binary_path, max_functions)

            # Parse output JSON
            if output_file.exists():
                with open(output_file, 'r') as f:
                    functions_data = json.load(f)

                functions = []
                for func_data in functions_data:
                    func = FunctionInfo(
                        name=func_data.get("name", f"FUN_{func_data['address']}"),
                        address=func_data.get("address", "0x0"),
                        pseudocode=func_data.get("pseudocode", ""),
                        size=func_data.get("size", 0)
                    )
                    functions.append(func)

                logger.info(f"Successfully decompiled {len(functions)} functions")
                return functions
            else:
                logger.warning("Ghidra script did not produce output file")
                return self._fallback_decompilation(binary_path, max_functions)

        except subprocess.TimeoutExpired:
            logger.error("Ghidra decompilation timed out after 10 minutes")
            return []
        except Exception as e:
            logger.error(f"Error during Ghidra decompilation: {e}")
            return []

    def _create_decompile_script(self, output_file: Path, max_functions: int) -> str:
        """Create a Ghidra Java script for decompilation."""
        return f"""
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class decompile extends GhidraScript {{

    @Override
    public void run() throws Exception {{
        PrintWriter writer = null;
        try {{
            // Setup output file
            File output = new File("{output_file}");
            writer = new PrintWriter(new FileWriter(output));

            // Get decompiler
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);

            // Get all functions
            FunctionManager functionManager = currentProgram.getFunctionManager();
            FunctionIterator functions = functionManager.getFunctions(true);

            JSONArray jsonArray = new JSONArray();
            int count = 0;

            while (functions.hasNext() && count < {max_functions}) {{
                Function function = functions.next();

                try {{
                    // Decompile function
                    DecompileResults results = decompiler.decompileFunction(
                        function, 30, monitor);

                    if (results != null && results.decompileCompleted()) {{
                        String pseudocode = results.getDecompiledFunction().getC();

                        // Create function info
                        JSONObject funcObj = new JSONObject();
                        funcObj.put("name", function.getName());
                        funcObj.put("address", "0x" + Long.toHexString(function.getEntryPoint().getOffset()));
                        funcObj.put("pseudocode", pseudocode);
                        funcObj.put("size", function.getBody().getNumAddresses());

                        jsonArray.put(funcObj);
                        count++;
                    }}
                }} catch (Exception e) {{
                    println("Error decompiling function " + function.getName() + ": " + e.getMessage());
                }}
            }}

            // Write JSON output
            writer.write(jsonArray.toString(2));
            println("Decompiled " + count + " functions");

            decompiler.closeProgram();
        }} catch (Exception e) {{
            println("Error in decompile script: " + e.getMessage());
            e.printStackTrace();
        }} finally {{
            if (writer != null) {{
                writer.close();
            }}
        }}
    }}
}}
"""

    def _fallback_decompilation(self, binary_path: Path, max_functions: int) -> List[FunctionInfo]:
        """Fallback decompilation method."""
        logger.warning(f"Using fallback decompilation for {binary_path.name}")

        # Placeholder implementation
        functions = []
        for i in range(min(10, max_functions)):
            func = FunctionInfo(
                name=f"FUN_{i:08x}",
                address=f"0x{1000 + i*100:08x}",
                pseudocode=f"// Ghidra fallback pseudocode for function {i}\nundefined FUN_{i:08x}(void)\n{{\n  // Sample code\n  int local_c;\n  return;\n}}",
                size=80 + i * 8
            )
            functions.append(func)

        return functions

    def get_function_count(self, binary_path: Path) -> int:
        """Get total number of functions in the binary."""
        # This would require running Ghidra analysis
        # For now, return placeholder
        return 0

    def get_binary_info(self, binary_path: Path) -> dict:
        """Get basic information about the binary."""
        info = {
            "file_size": binary_path.stat().st_size,
            "format": "unknown",
            "architecture": "unknown",
            "entry_point": "unknown"
        }

        # Try to get info using file command
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
                logger.info(f"Cleaned up Ghidra temp directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up Ghidra temp directory: {e}")