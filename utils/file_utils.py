import hashlib
import os
import magic
from pathlib import Path
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)


def get_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate hash of a file.

    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm (md5, sha1, sha256).

    Returns:
        Hexadecimal hash string.
    """
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def detect_file_type(file_path: Path) -> str:
    """
    Detect file type using magic numbers.

    Args:
        file_path: Path to the file.

    Returns:
        File type description.
    """
    try:
        # Try python-magic
        import magic as magic_lib
        return magic_lib.from_file(str(file_path))
    except ImportError:
        try:
            # Try file command as fallback
            import subprocess
            result = subprocess.run(
                ["file", "-b", str(file_path)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass

    # Fallback to extension
    return f"Unknown (extension: {file_path.suffix})"


def is_binary_file(file_path: Path) -> bool:
    """
    Check if a file is a binary executable.

    Args:
        file_path: Path to the file.

    Returns:
        True if file appears to be a binary executable.
    """
    # Check common binary extensions
    binary_extensions = {
        '.elf', '.so', '.o', '.a', '.exe', '.dll', '.sys', '.dylib',
        '.bin', '.out', '.ko', '.sys', '.drv', '.efi', '.app'
    }

    if file_path.suffix.lower() in binary_extensions:
        return True

    # Check file type using magic
    file_type = detect_file_type(file_path).lower()

    binary_indicators = [
        'elf', 'executable', 'shared object', 'pie executable',
        'mach-o', 'pe32', 'pe32+', 'dos executable', 'coff',
        'binary', 'executable and linkable format'
    ]

    return any(indicator in file_type for indicator in binary_indicators)


def get_binary_info(file_path: Path) -> Optional[dict]:
    """
    Get basic information about a binary file.

    Args:
        file_path: Path to the binary file.

    Returns:
        Dictionary with binary information or None.
    """
    if not file_path.exists():
        return None

    try:
        info = {
            "path": str(file_path),
            "size": file_path.stat().st_size,
            "hash_sha256": get_file_hash(file_path, "sha256"),
            "file_type": detect_file_type(file_path),
            "is_binary": is_binary_file(file_path)
        }

        # Try to get architecture info
        if info["is_binary"]:
            info.update(_get_binary_architecture(file_path))

        return info
    except Exception as e:
        logger.error(f"Error getting binary info for {file_path}: {e}")
        return None


def _get_binary_architecture(file_path: Path) -> dict:
    """Get architecture information from binary."""
    arch_info = {
        "architecture": "unknown",
        "bits": 0,
        "endian": "unknown"
    }

    try:
        with open(file_path, 'rb') as f:
            # Read ELF header
            header = f.read(20)
            if len(header) >= 20:
                # Check for ELF magic
                if header[:4] == b'\x7fELF':
                    arch_info["format"] = "ELF"
                    # Byte 4: 1 = 32-bit, 2 = 64-bit
                    if header[4] == 1:
                        arch_info["bits"] = 32
                    elif header[4] == 2:
                        arch_info["bits"] = 64
                    # Byte 5: 1 = little endian, 2 = big endian
                    if header[5] == 1:
                        arch_info["endian"] = "little"
                    elif header[5] == 2:
                        arch_info["endian"] = "big"

                # Check for PE (Windows) magic
                elif header[:2] == b'MZ':
                    arch_info["format"] = "PE"
                    # Read PE header offset
                    f.seek(0x3C)
                    pe_offset_bytes = f.read(4)
                    if len(pe_offset_bytes) == 4:
                        pe_offset = int.from_bytes(pe_offset_bytes, 'little')
                        f.seek(pe_offset)
                        pe_header = f.read(6)
                        if len(pe_header) >= 6 and pe_header[:2] == b'PE':
                            # Machine type is at offset 4
                            machine = int.from_bytes(pe_header[4:6], 'little')
                            if machine == 0x014C:
                                arch_info["bits"] = 32
                                arch_info["architecture"] = "x86"
                            elif machine == 0x8664:
                                arch_info["bits"] = 64
                                arch_info["architecture"] = "x86_64"
                            elif machine == 0x01C0:
                                arch_info["bits"] = 32
                                arch_info["architecture"] = "ARM"
                            elif machine == 0xAA64:
                                arch_info["bits"] = 64
                                arch_info["architecture"] = "ARM64"

    except Exception as e:
        logger.debug(f"Could not determine architecture: {e}")

    return arch_info


def create_output_directory(base_dir: Path, binary_name: str) -> Path:
    """
    Create a structured output directory for analysis results.

    Args:
        base_dir: Base output directory.
        binary_name: Name of the binary being analyzed.

    Returns:
        Path to the created directory.
    """
    import time
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() else "_" for c in binary_name)
    dir_name = f"{safe_name}_{timestamp}"

    output_dir = base_dir / dir_name
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create subdirectories
    (output_dir / "reports").mkdir(exist_ok=True)
    (output_dir / "logs").mkdir(exist_ok=True)
    (output_dir / "cache").mkdir(exist_ok=True)

    return output_dir


def validate_binary_file(file_path: Path) -> Tuple[bool, str]:
    """
    Validate that a file is a valid binary for analysis.

    Args:
        file_path: Path to the file.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not file_path.exists():
        return False, f"File does not exist: {file_path}"

    if not file_path.is_file():
        return False, f"Path is not a file: {file_path}"

    if file_path.stat().st_size == 0:
        return False, "File is empty"

    if file_path.stat().st_size > 100 * 1024 * 1024:  # 100MB
        return False, "File is too large (max 100MB)"

    if not is_binary_file(file_path):
        return False, "File does not appear to be a binary executable"

    return True, ""