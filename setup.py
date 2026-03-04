from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / "README.md").read_text(encoding="utf-8") if (here / "README.md").exists() else ""

setup(
    name="vdagent",
    version="0.1.0",
    description="AI-powered Vulnerability Detection Agent for binary analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vdagent",
    author="Your Name",
    author_email="your.email@example.com",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Security Professionals",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="security, vulnerability, binary analysis, ai, reverse engineering",
    package_dir={"": "."},
    packages=["vdagent", "vdagent.core", "vdagent.integrations", "vdagent.models", "vdagent.analyzers", "vdagent.utils", "vdagent.config"],
    python_requires=">=3.8, <4",
    install_requires=[
        "openai>=1.0.0",
        "pydantic>=2.0.0",
        "python-magic>=0.4.27",
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
        "ida": [
            # IDAPython dependencies would be installed separately
        ],
        "ghidra": [
            # Ghidra dependencies would be installed separately
        ],
    },
    entry_points={
        "console_scripts": [
            "vdagent=vdagent.__main__:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/yourusername/vdagent/issues",
        "Source": "https://github.com/yourusername/vdagent",
    },
)