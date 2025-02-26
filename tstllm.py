#!/usr/bin/env python3

from RAGScripts.llm_security_analyzer import LLMSecurityAnalyzer
import asyncio

async def main():
    # Initialize the security analyzer with default settings
    analyzer = LLMSecurityAnalyzer()
    
    # Sample API interaction to analyze
    test_path = "/api/users/1"
    test_method = "GET"
    test_request_headers = {"Authorization": "Bearer test_token"}
    test_request_body = {}
    test_response_headers = {"Content-Type": "application/json"}
    test_response_body = {"id": 1, "username": "test_user", "email": "test@example.com"}
    
    # Analyze for SQL injection vulnerabilities
    result = await analyzer.analyze_request_response(
        path=test_path,
        method=test_method,
        request_headers=test_request_headers,
        request_body=test_request_body,
        response_headers=test_response_headers,
        response_body=test_response_body,
        vulnerability_type="SQL injection"
    )
    
    # Print the analysis results
    print("Security Analysis Results:")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())