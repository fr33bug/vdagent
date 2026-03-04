import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="",  # No prefix
        case_sensitive=False
    )

    # DeepSeek API settings
    DEEPSEEK_API_KEY: str = Field(default="GZQKEY", description="DeepSeek API key")
    DEEPSEEK_API_BASE: str = Field(default="https://api.deepseek.com", description="DeepSeek API base URL")
    DEEPSEEK_MODEL: str = Field(default="deepseek-chat", description="DeepSeek model name")

    # Reverse engineering tools settings
    IDA_PATH: Optional[str] = Field(default=None, description="Path to IDA Pro executable")
    GHIDRA_PATH: Optional[str] = Field(default=None, description="Path to Ghidra installation")
    GHIDRA_PROJECTS_DIR: Optional[str] = Field(default=None, description="Path to Ghidra projects directory")

    # Analysis settings
    MAX_FUNCTIONS_PER_ANALYSIS: int = Field(default=100, description="Maximum number of functions to analyze")
    MAX_PSEUDOCODE_LENGTH: int = Field(default=10000, description="Maximum pseudocode length for AI analysis")

    # Output settings
    OUTPUT_DIR: str = Field(default="./output", description="Output directory for reports")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")

    # Cache settings
    USE_CACHE: bool = Field(default=True, description="Enable caching of AI analysis")
    CACHE_DIR: str = Field(default="./cache", description="Cache directory")


settings = Settings()