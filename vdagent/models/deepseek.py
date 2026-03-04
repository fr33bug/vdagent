import json
import logging
from typing import Dict, List, Optional, Any
import time
import hashlib
import os
from pathlib import Path

try:
    import openai
except ImportError:
    openai = None

try:
    # When installed as package
    from vdagent.config.settings import settings
except ImportError:
    # When running from source
    from ..config.settings import settings


logger = logging.getLogger(__name__)


class DeepSeekAnalyzer:
    """DeepSeek API integration for vulnerability analysis."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.deepseek.com",
        model: str = "deepseek-chat"
    ):
        """
        Initialize DeepSeek analyzer.

        Args:
            api_key: DeepSeek API key.
            base_url: Base URL for API.
            model: Model name to use.
        """
        if openai is None:
            raise ImportError(
                "OpenAI client is required for DeepSeek integration. "
                "Install with: pip install openai"
            )

        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.client = None
        self.cache_dir = None
        self.initialize_client()

    def initialize_client(self):
        """Initialize OpenAI client for DeepSeek API."""
        self.client = openai.OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )

        # Setup cache directory
        self.cache_dir = Path(settings.CACHE_DIR) / "deepseek"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"DeepSeek analyzer initialized with model: {self.model}")

    def analyze_vulnerabilities(self, pseudocode: str, function_name: str = "") -> Dict[str, Any]:
        """
        Analyze pseudocode for vulnerabilities using DeepSeek.

        Args:
            pseudocode: The pseudocode to analyze.
            function_name: Name of the function (optional).

        Returns:
            Dictionary with analysis results.
        """
        if not self.client:
            raise RuntimeError("DeepSeek client not initialized")

        # Check cache first
        cache_key = self._generate_cache_key(pseudocode, function_name)
        cached_result = self._get_cached_result(cache_key)
        if cached_result and settings.USE_CACHE:
            logger.debug(f"Using cached result for {function_name}")
            return cached_result

        # Prepare prompt
        prompt = self._create_vulnerability_analysis_prompt(pseudocode, function_name)

        try:
            logger.debug(f"Analyzing function {function_name} with DeepSeek...")

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,  # Low temperature for more deterministic results
                max_tokens=2000,
                timeout=30
            )

            analysis_text = response.choices[0].message.content

            # Parse the response
            result = self._parse_analysis_response(analysis_text)
            result["cache_key"] = cache_key

            # Cache the result
            self._cache_result(cache_key, result)

            logger.debug(f"Analysis complete for {function_name}")
            return result

        except Exception as e:
            logger.error(f"Error analyzing with DeepSeek: {e}")
            return {
                "vulnerabilities": [],
                "confidence": 0.0,
                "summary": f"Analysis failed: {str(e)}",
                "error": True
            }

    def _generate_cache_key(self, pseudocode: str, function_name: str) -> str:
        """Generate a cache key for the analysis."""
        content = f"{function_name}:{pseudocode}"
        return hashlib.md5(content.encode()).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis result."""
        if not settings.USE_CACHE:
            return None

        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                return None
        return None

    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result."""
        if not settings.USE_CACHE:
            return

        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to cache result: {e}")

    def _get_system_prompt(self) -> str:
        """Get system prompt for vulnerability analysis."""
        return """You are a senior binary security analyst specializing in vulnerability detection.
Your task is to analyze decompiled pseudocode and identify potential security vulnerabilities.

Focus on common vulnerability types:
1. Buffer overflows (stack-based, heap-based)
2. Integer overflows/underflows
3. Use-after-free
4. Double free
5. Format string vulnerabilities
6. Race conditions
7. Incorrect permission checks
8. Command injection
9. Path traversal
10. Memory corruption
11. Uninitialized variables
12. Type confusion

For each finding, provide:
- Vulnerability type
- Confidence level (0.0 to 1.0)
- Detailed description
- Affected code location
- Suggested remediation
- Relevant CWE ID if applicable

Be concise but thorough. If no vulnerabilities are found, state that clearly."""

    def _create_vulnerability_analysis_prompt(self, pseudocode: str, function_name: str) -> str:
        """Create prompt for vulnerability analysis."""
        return f"""Analyze the following decompiled pseudocode for security vulnerabilities.

Function: {function_name}
Pseudocode:
```
{pseudocode[:settings.MAX_PSEUDOCODE_LENGTH]}
```

Please analyze this code and identify any potential security vulnerabilities.
Provide your analysis in JSON format with the following structure:
{{
  "vulnerabilities": [
    {{
      "type": "vulnerability_type",
      "confidence": 0.95,
      "description": "Detailed description of the vulnerability",
      "location": "Specific location in the code (e.g., line numbers)",
      "remediation": "Suggested fix",
      "cwe_id": "CWE-XXX"
    }}
  ],
  "summary": "Brief summary of findings",
  "overall_confidence": 0.85
}}

If no vulnerabilities are found, return an empty vulnerabilities array.
Be objective and only report issues you are reasonably confident about."""

    def _parse_analysis_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse the analysis response from DeepSeek.

        The response should be in JSON format, but we need to handle
        cases where the model returns malformed JSON or additional text.
        """
        try:
            # Try to extract JSON from the response
            lines = response_text.strip().split('\n')
            json_start = -1
            json_end = -1

            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    json_start = i
                    break

            if json_start >= 0:
                # Find matching closing brace
                brace_count = 0
                for i in range(json_start, len(lines)):
                    line = lines[i]
                    brace_count += line.count('{')
                    brace_count -= line.count('}')

                    if brace_count == 0:
                        json_end = i + 1
                        break

                if json_end > json_start:
                    json_str = '\n'.join(lines[json_start:json_end])
                    result = json.loads(json_str)

                    # Ensure required fields
                    if "vulnerabilities" not in result:
                        result["vulnerabilities"] = []
                    if "summary" not in result:
                        result["summary"] = "Analysis completed"
                    if "overall_confidence" not in result:
                        result["overall_confidence"] = 0.0

                    return result

            # Fallback: create a basic result structure
            return {
                "vulnerabilities": [],
                "summary": "Could not parse analysis response",
                "overall_confidence": 0.0,
                "raw_response": response_text[:500]  # Include first 500 chars for debugging
            }

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            return {
                "vulnerabilities": [],
                "summary": f"JSON parsing error: {str(e)}",
                "overall_confidence": 0.0,
                "raw_response": response_text[:500]
            }
        except Exception as e:
            logger.error(f"Error parsing analysis response: {e}")
            return {
                "vulnerabilities": [],
                "summary": f"Error: {str(e)}",
                "overall_confidence": 0.0
            }

    def batch_analyze(self, functions_pseudocode: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple functions in batch.

        Args:
            functions_pseudocode: List of dicts with 'name' and 'pseudocode' keys.

        Returns:
            List of analysis results.
        """
        results = []
        for i, func_data in enumerate(functions_pseudocode):
            logger.info(f"Analyzing function {i+1}/{len(functions_pseudocode)}: {func_data.get('name', 'unknown')}")

            result = self.analyze_vulnerabilities(
                pseudocode=func_data['pseudocode'],
                function_name=func_data.get('name', '')
            )
            results.append(result)

            # Rate limiting: sleep between requests
            if i < len(functions_pseudocode) - 1:
                time.sleep(0.5)  # 500ms delay between requests

        return results