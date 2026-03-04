# Vulnerability Detection Agent (VDAgent)

AI-powered automated vulnerability detection agent for binary analysis.

## Overview

VDAgent is an intelligent agent that automates vulnerability discovery in binary files (.elf, .exe, .dll, .so, etc.) by:

1. **Reverse Engineering Integration**: Automatically decompiles binary files using industry-standard tools (IDA Pro, Ghidra)
2. **AI-Powered Analysis**: Leverages DeepSeek V3 model to analyze decompiled pseudocode for security vulnerabilities
3. **Automated Reporting**: Generates detailed vulnerability reports with confidence scores and remediation advice

## Features

- **Multi-tool Support**: Integrates with IDA Pro and Ghidra for binary decompilation
- **DeepSeek V3 Integration**: State-of-the-art AI analysis for vulnerability detection
- **Smart Filtering**: Automatically filters trivial functions to focus analysis
- **Caching System**: Caches AI analysis results to reduce API costs
- **Comprehensive Reporting**: Generates markdown reports with vulnerability details
- **Configurable**: Easy configuration via environment variables or config files

## Installation

### Prerequisites

- Python 3.8 or higher
- IDA Pro or Ghidra (for binary decompilation)
- DeepSeek API key (for AI analysis)

### Install from source

```bash
git clone <repository-url>
cd vdagent
pip install -e .
```

### Install dependencies

```bash
pip install openai pydantic python-magic requests
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# DeepSeek API Configuration
DEEPSEEK_API_KEY=your_api_key_here
DEEPSEEK_API_BASE=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

# Reverse Engineering Tools
IDA_PATH=/path/to/ida64
GHIDRA_PATH=/path/to/ghidra_10.3.3_PUBLIC
GHIDRA_PROJECTS_DIR=/path/to/ghidra_projects

# Analysis Settings
MAX_FUNCTIONS_PER_ANALYSIS=100
MAX_PSEUDOCODE_LENGTH=10000

# Output Settings
OUTPUT_DIR=./output
LOG_LEVEL=INFO

# Cache Settings
USE_CACHE=true
CACHE_DIR=./cache
```

### Command Line Configuration

You can also override settings via command line arguments.

## Usage

### Basic Usage

```bash
# Analyze a binary file
python -m vdagent path/to/binary.elf

# Specify reverse engineering tool
python -m vdagent path/to/binary.exe --tool ida

# Limit number of functions analyzed
python -m vdagent path/to/binary.so --max-functions 50

# Specify output directory
python -m vdagent path/to/binary.dll --output ./reports

# Enable verbose logging
python -m vdagent path/to/binary.elf --verbose
```

### Python API

```python
from vdagent.core.agent import VDAgent

# Initialize agent
agent = VDAgent(tool_preference="auto")

# Analyze binary
findings = agent.analyze_binary("path/to/binary.elf")

# Process findings
for finding in findings:
    print(f"Vulnerability: {finding.vulnerability_type}")
    print(f"Function: {finding.function_name}")
    print(f"Confidence: {finding.confidence:.2f}")
    print(f"Description: {finding.description}")

# Cleanup
agent.cleanup()
```

## Supported Binary Formats

- **ELF**: Linux executables, shared libraries (.elf, .so)
- **PE**: Windows executables (.exe, .dll, .sys)
- **Mach-O**: macOS executables (.dylib, .bundle)
- **Other**: Any binary format supported by IDA Pro or Ghidra

## Vulnerability Detection Capabilities

The agent is trained to detect various vulnerability types:

- **Memory Corruption**: Buffer overflows, heap overflows, stack overflows
- **Use-After-Free**: Dangling pointer dereferences
- **Integer Issues**: Integer overflows, underflows, signedness errors
- **Format Strings**: Uncontrolled format string vulnerabilities
- **Race Conditions**: Time-of-check-time-of-use (TOCTOU) issues
- **Injection Vulnerabilities**: Command injection, path traversal
- **Cryptographic Issues**: Weak random number generation, hardcoded keys
- **Information Leaks**: Uninitialized memory disclosures

## Architecture

```
vdagent/
├── core/                    # Core agent logic
│   ├── agent.py            # Main agent class
│   └── models.py           # Data models
├── integrations/           # Reverse engineering tool integrations
│   ├── base.py             # Base tool interface
│   ├── ida.py              # IDA Pro integration
│   └── ghidra.py           # Ghidra integration
├── models/                 # AI model integrations
│   └── deepseek.py         # DeepSeek API integration
├── analyzers/             # Analysis engines
│   └── vulnerability.py    # Vulnerability analyzer
├── utils/                  # Utility functions
│   └── file_utils.py       # File handling utilities
├── config/                 # Configuration
│   └── settings.py         # Application settings
├── __main__.py            # CLI entry point
└── setup.py               # Package configuration
```

## Extending the Agent

### Adding New Reverse Engineering Tools

1. Create a new class in `integrations/` that inherits from `ReverseEngineeringTool`
2. Implement the required methods:
   - `initialize()`: Initialize tool connection
   - `decompile_functions()`: Decompile binary functions
   - `get_function_count()`: Get total functions
   - `get_binary_info()`: Get binary metadata
   - `cleanup()`: Clean up resources

### Adding New AI Models

1. Create a new class in `models/` following the pattern of `DeepSeekAnalyzer`
2. Implement the `analyze_vulnerabilities()` method
3. Update the agent to support the new model

## Limitations

- **API Costs**: Using DeepSeek API incurs costs based on usage
- **Decompilation Quality**: Analysis depends on decompilation accuracy
- **False Positives**: AI models may produce false positives
- **Tool Dependencies**: Requires IDA Pro or Ghidra installation
- **Performance**: Large binaries may take significant time to analyze

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- DeepSeek for providing the AI model
- Hex-Rays for IDA Pro
- NSA for Ghidra
- All open-source contributors

## Disclaimer

This tool is for authorized security testing and research purposes only. Use responsibly and only on systems you own or have explicit permission to test.