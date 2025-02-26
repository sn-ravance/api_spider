import asyncio
import json
import pytest
from .llm_analyzer import LLMAnalyzer

# Sample test data
TEST_URL = "http://api.example.com/users/1"
TEST_CONTEXT = {
    "responses": [
        {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "response": {"user_id": 1, "email": "test@example.com", "role": "admin"}
        }
    ],
    "patterns": [
        {
            "patterns": {"sensitive_data": ["email", "role"]},
            "normalized": "user_data_response"
        }
    ],
    "behavior": {
        "accepts_json": True,
        "requires_auth": False,
        "error_verbose": True
    }
}

TEST_SECURITY_PROMPT = """
Analyze this endpoint for security vulnerabilities:
URL: {url}
Response Pattern: {patterns}
Behavior: {behavior}

Provide security assessment and recommendations.
"""

@pytest.mark.asyncio
async def test_analyze_endpoint():
    """Test endpoint analysis with security-focused prompt"""
    analyzer = LLMAnalyzer(ollama_host="http://localhost:11434")
    analyzer.ollama_model = "llama2"
    
    # Test primary analysis
    result = await analyzer.analyze_endpoint(
        url=TEST_URL,
        context=TEST_CONTEXT,
        prompt=TEST_SECURITY_PROMPT
    )
    
    # Verify response structure
    assert isinstance(result, dict)
    assert 'confidence' in result
    assert isinstance(result.get('findings', []), list)
    assert isinstance(result.get('recommendations', []), list)
    
    # Verify security analysis content
    findings = result.get('findings', [])
    assert any('sensitive' in str(finding).lower() for finding in findings), \
        "Should detect sensitive data exposure"

@pytest.mark.asyncio
async def test_vulnerability_analysis():
    """Test specific vulnerability analysis"""
    analyzer = LLMAnalyzer(ollama_host="http://localhost:11434")
    analyzer.ollama_model = "llama2"
    
    finding = {
        "type": "information_disclosure",
        "severity": "medium",
        "description": "Endpoint exposes sensitive user information"
    }
    
    result = await analyzer.analyze_vulnerability(
        scanner_name="test_scanner",
        finding=finding,
        url=TEST_URL,
        method="GET"
    )
    
    # Verify vulnerability analysis
    assert isinstance(result, dict)
    assert result.get('confidence', 0) > 0.5, "Should have reasonable confidence"
    assert len(result.get('recommendations', [])) > 0, "Should provide recommendations"

@pytest.mark.asyncio
async def test_low_confidence_reanalysis():
    """Test secondary analysis trigger on low confidence"""
    analyzer = LLMAnalyzer(ollama_host="http://localhost:11434")
    analyzer.ollama_model = "llama2"
    
    # Modify context to trigger low confidence
    modified_context = TEST_CONTEXT.copy()
    modified_context['behavior']['error_verbose'] = False
    
    result = await analyzer.analyze_endpoint(
        url=TEST_URL,
        context=modified_context,
        prompt=TEST_SECURITY_PROMPT
    )
    
    # Verify secondary analysis was triggered
    assert result.get('confidence', 0) > 0, "Should have updated confidence"
    assert not result.get('error'), "Should not have errors"

if __name__ == "__main__":
    asyncio.run(test_analyze_endpoint())