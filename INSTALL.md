# VDAgent Installation and Setup Guide

## Quick Start

1. **Clone and install dependencies:**
   ```bash
   git clone <repository-url>
   cd vdagent
   python3 -m venv venv
   source venv/bin/activate
   pip install -e .
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. **Configure reverse engineering tools:**
   - For IDA Pro: Set `IDA_PATH` in .env
   - For Ghidra: Set `GHIDRA_PATH` in .env

4. **Get DeepSeek API key:**
   - Register at https://platform.deepseek.com/
   - Add your API key to .env

5. **Analyze a binary:**
   ```bash
   python -m vdagent path/to/binary.elf
   ```

## Manual Setup (if pip install fails)

If you encounter import issues, you can run the agent directly:

1. **Install dependencies manually:**
   ```bash
   pip install openai pydantic-settings python-magic requests
   ```

2. **Run from source:**
   ```bash
   # Set Python path
   export PYTHONPATH=/path/to/vdagent:$PYTHONPATH

   # Run the agent
   python vdagent/__main__.py path/to/binary.elf
   ```

## Configuration Details

### Required Settings

1. **DeepSeek API Configuration:**
   - `DEEPSEEK_API_KEY`: Your API key (replace "GZQKEY")
   - `DEEPSEEK_API_BASE`: https://api.deepseek.com
   - `DEEPSEEK_MODEL`: deepseek-chat

2. **Reverse Engineering Tool (choose one):**
   - `IDA_PATH`: Path to IDA Pro executable
   - `GHIDRA_PATH`: Path to Ghidra installation
   - `GHIDRA_PROJECTS_DIR`: Ghidra projects directory

### Optional Settings

- `MAX_FUNCTIONS_PER_ANALYSIS`: Limit functions analyzed (default: 100)
- `OUTPUT_DIR`: Report output directory (default: ./output)
- `USE_CACHE`: Cache AI results (default: true)

## Testing the Installation

Create a test script `test_import.py`:

```python
import sys
sys.path.insert(0, '/path/to/vdagent')

try:
    from config.settings import settings
    print("✓ Settings imported")

    # Test creating data structures
    from core.agent import FunctionInfo, VulnerabilityFinding

    func = FunctionInfo(
        name="test_func",
        address="0x08048400",
        pseudocode="void test() {}",
        size=100
    )
    print(f"✓ FunctionInfo created: {func.name}")

    print("\nInstallation successful!")

except ImportError as e:
    print(f"✗ Import error: {e}")
    print("\nMake sure:")
    print("1. Dependencies are installed")
    print("2. Python path is correct")
    print("3. Package structure is intact")
```

## Troubleshooting

### Import Errors
- **"No module named 'vdagent'"**: Run `pip install -e .` from project root
- **"attempted relative import"**: Ensure proper package structure or use manual Python path setup
- **Pydantic errors**: Install pydantic-settings: `pip install pydantic-settings`

### Tool Integration Issues
- **IDA Pro not found**: Verify IDA_PATH points to the executable
- **Ghidra not found**: Verify GHIDRA_PATH points to installation directory
- **Decompilation fails**: Check tool licenses and permissions

### API Issues
- **DeepSeek API errors**: Verify API key and internet connection
- **Rate limiting**: Add delays between requests in the code

## File Structure

```
vdagent/
├── core/                    # Main agent logic
│   ├── agent.py            # VDAgent class
│   └── __init__.py
├── integrations/           # Reverse engineering tools
│   ├── base.py            # Base interface
│   ├── ida.py             # IDA Pro integration
│   ├── ghidra.py          # Ghidra integration
│   └── __init__.py
├── models/                 # AI model integrations
│   ├── deepseek.py        # DeepSeek API wrapper
│   └── __init__.py
├── analyzers/             # Analysis engines
│   ├── vulnerability.py   # Vulnerability analyzer
│   └── __init__.py
├── utils/                  # Utilities
│   ├── file_utils.py      # File handling
│   └── __init__.py
├── config/                 # Configuration
│   ├── settings.py        # App settings
│   └── __init__.py
├── __init__.py            # Package definition
├── __main__.py            # CLI entry point
├── setup.py               # Package installation
├── requirements.txt       # Dependencies
├── .env.example           # Example configuration
└── README.md              # Documentation
```

## Next Steps

1. Review and customize the vulnerability detection prompts in `models/deepseek.py`
2. Add support for additional reverse engineering tools
3. Implement parallel analysis for faster processing
4. Add more vulnerability detection heuristics
5. Create web interface or API server

## Support

For issues and questions:
1. Check the README.md for detailed documentation
2. Review the example configuration in .env.example
3. Examine the source code comments
4. Create an issue on the project repository